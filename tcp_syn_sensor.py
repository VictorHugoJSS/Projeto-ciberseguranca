#!/usr/bin/env python3
"""
Sensor de pacotes TCP SYN — captura tentativas de conexão na rede local
e envia como evento JSON (formato ECS-like) para o input custom_json
do Logstash (porta 5000/tcp).

Uso:
    sudo python3 tcp_syn_sensor.py --iface eth0 --logstash-host 127.0.0.1

Requisitos:
    pip install scapy
    Precisa rodar como root (ou com CAP_NET_RAW) para sniffar pacotes.
"""

import argparse
import json
import socket
import sys
from datetime import datetime, timezone

try:
    from scapy.all import sniff, TCP, IP
except ImportError:
    sys.exit("Instale a dependência primeiro: pip install scapy")


def build_event(pkt):
    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    flags = tcp_layer.flags

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["connection", "start"],
            "action": "connection_attempt",
        },
        "source": {"ip": ip_layer.src, "port": tcp_layer.sport},
        "destination": {"ip": ip_layer.dst, "port": tcp_layer.dport},
        "network": {"transport": "tcp"},
        "tcp": {
            "flags": {
                "syn": bool(flags & 0x02),
                "ack": bool(flags & 0x10),
            }
        },
    }


def send_event(sock, event):
    line = json.dumps(event) + "\n"
    sock.sendall(line.encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Sensor de SYN scan para o mini-SIEM")
    parser.add_argument("--iface", default=None, help="Interface de rede (ex: eth0)")
    parser.add_argument("--logstash-host", default="127.0.0.1")
    parser.add_argument("--logstash-port", type=int, default=5044)
    parser.add_argument(
        "--bpf",
        default="tcp[13] & 2 != 0",  # filtro BPF: só pacotes com flag SYN setada
        help="Filtro BPF aplicado na captura",
    )
    args = parser.parse_args()

    sock = socket.create_connection((args.logstash_host, args.logstash_port))
    print(f"[+] Conectado ao Logstash em {args.logstash_host}:{args.logstash_port}")
    print(f"[+] Capturando SYN packets na interface {args.iface or '(default)'}...")

    def handle(pkt):
        if IP in pkt and TCP in pkt:
            event = build_event(pkt)
            try:
                send_event(sock, event)
            except (BrokenPipeError, ConnectionResetError):
                print("[!] Conexão com Logstash perdida, encerrando.")
                sys.exit(1)

    try:
        sniff(iface=args.iface, filter=args.bpf, prn=handle, store=False)
    except KeyboardInterrupt:
        print("\n[+] Encerrado pelo usuário.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
