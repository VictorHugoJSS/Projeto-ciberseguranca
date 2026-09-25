#!/usr/bin/env python3
"""
Robôzinho brincalhão: finge ser um vilão tentando adivinhar
a senha SSH várias vezes, depois "acerta" — tudo enviado
como mensagens de syslog pro Logstash (porta 5514).

Uso:
    python3 simulate_bruteforce.py --attacker-ip 203.0.113.50 --attempts 8
"""
import argparse
import socket
import time
from datetime import datetime

def send_line(sock, host, port, message, use_udp=True):
    line = f"{datetime.now().strftime('%b %e %H:%M:%S')} victim-host sshd[1234]: {message}\n"
    if use_udp:
        sock.sendto(line.encode(), (host, port))
    else:
        sock.sendall(line.encode())
    print(f"[enviado] {message}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--attacker-ip", default="203.0.113.50")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--attempts", type=int, default=8, help="quantas vezes ele erra antes de acertar")
    parser.add_argument("--delay", type=float, default=0.5, help="segundos entre tentativas")
    parser.add_argument("--tcp", action="store_true", help="usa TCP em vez de UDP")
    args = parser.parse_args()

    use_udp = not args.tcp
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if use_udp else socket.SOCK_STREAM)
    if not use_udp:
        sock.connect((args.host, args.port))

    print(f"[+] Simulando ataque de força bruta de {args.attacker_ip} contra usuário '{args.user}'")
    port_num = 51400

    # As tentativas erradas (o vilão errando a senha várias vezes)
    for i in range(args.attempts):
        port_num += 1
        msg = f"Failed password for invalid user {args.user} from {args.attacker_ip} port {port_num} ssh2"
        send_line(sock, args.host, args.port, msg, use_udp)
        time.sleep(args.delay)

    # A tentativa certa (o vilão finalmente acerta)
    time.sleep(args.delay)
    port_num += 1
    msg = f"Accepted password for {args.user} from {args.attacker_ip} port {port_num} ssh2"
    send_line(sock, args.host, args.port, msg, use_udp)

    sock.close()
    print("[+] Pronto! Agora vai no Kibana ver se o robô espião percebeu 👀")

if __name__ == "__main__":
    main()