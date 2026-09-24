#!/usr/bin/env python3
"""
Isolamento automático do IP agressor.

Consulta periodicamente o Elasticsearch por eventos taggeados como
'port_scan_detected' ou 'syn_flood_detected' nos últimos N minutos e
bloqueia o IP de origem via iptables — evitando bloquear IPs repetidos
ou os que estão na allowlist (sua própria máquina, gateway etc).

Uso:
    sudo python3 isolate_ip.py \
        --es-host https://localhost:9200 \
        --es-user elastic --es-password <senha> \
        --ca-cert ./certs/ca/ca.crt \
        --allowlist 192.168.0.1,192.168.0.10 \
        --interval 15 --auto-unblock-minutes 30

IMPORTANTE:
- Rode isso apenas no seu ambiente de laboratório. Bloqueio automático
  em rede de produção sem allowlist bem definida pode causar auto-DoS.
- Requer privilégio para alterar iptables (root, ou capability NET_ADMIN
  se rodando em container).
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

STATE_FILE = Path("/var/lib/mini-siem/blocked_ips.json")


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def query_recent_attackers(es_host, es_user, es_password, ca_cert, minutes):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"terms": {"tags": ["port_scan_detected", "syn_flood_detected"]}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
        "aggs": {"attackers": {"terms": {"field": "source.ip", "size": 100}}},
    }
    resp = requests.post(
        f"{es_host}/siem-alerts-*/_search",
        auth=(es_user, es_password),
        verify=ca_cert,
        json=query,
        timeout=10,
    )
    resp.raise_for_status()
    buckets = resp.json().get("aggregations", {}).get("attackers", {}).get("buckets", [])
    return [b["key"] for b in buckets]


def block_ip(ip):
    subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    # -C só checa se já existe; se falhar (não existe), insere a regra
    check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    if check.returncode != 0:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[BLOQUEADO] {ip}")


def unblock_ip(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    print(f"[LIBERADO] {ip}")


def main():
    parser = argparse.ArgumentParser(description="Isolamento automático de IP agressor")
    parser.add_argument("--es-host", required=True)
    parser.add_argument("--es-user", default="elastic")
    parser.add_argument("--es-password", required=True)
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--allowlist", default="", help="IPs separados por vírgula, nunca bloqueados")
    parser.add_argument("--window-minutes", type=int, default=5, help="janela de busca de alertas")
    parser.add_argument("--interval", type=int, default=15, help="segundos entre checagens")
    parser.add_argument("--auto-unblock-minutes", type=int, default=30, help="0 = bloqueio permanente")
    args = parser.parse_args()

    allowlist = {ip.strip() for ip in args.allowlist.split(",") if ip.strip()}
    state = load_state()

    print("[+] Monitor de isolamento iniciado. Ctrl+C para parar.")
    try:
        while True:
            attackers = query_recent_attackers(
                args.es_host, args.es_user, args.es_password, args.ca_cert, args.window_minutes
            )
            now = datetime.now(timezone.utc)

            for ip in attackers:
                if ip in allowlist:
                    continue
                if ip not in state:
                    block_ip(ip)
                    state[ip] = now.isoformat()

            # libera IPs cujo tempo de bloqueio expirou
            if args.auto_unblock_minutes > 0:
                expired = [
                    ip for ip, blocked_at in state.items()
                    if now - datetime.fromisoformat(blocked_at) > timedelta(minutes=args.auto_unblock_minutes)
                ]
                for ip in expired:
                    unblock_ip(ip)
                    del state[ip]

            save_state(state)
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[+] Encerrado pelo usuário.")


if __name__ == "__main__":
    main()
