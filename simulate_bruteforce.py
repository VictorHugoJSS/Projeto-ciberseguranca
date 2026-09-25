#!/usr/bin/env python3
"""
Simulador de incidente de SSH com ruído de fundo realista.

Gera duas coisas ao mesmo tempo, misturadas em ordem cronológica:
  1) Tráfego "normal" de um servidor Linux comum (cron, systemd, logins
     legítimos de outros usuários/IPs, healthchecks, sudo, etc).
  2) O ataque de força bruta de verdade (Failed password x N -> Accepted
     password) vindo de um único IP "agressor".

Tudo é enviado como syslog (RFC3164-like) para a porta do Logstash
(mesma que já está configurada em 01_input.conf: 5514/tcp ou udp).

Uso básico:
    python3 simulate_bruteforce.py --attacker-ip 203.0.113.50 --attempts 8

    python3 simulate_bruteforce.py --attacker-ip 198.51.100.25 --attempts 12

Uso "cheio", com bastante ruído de fundo intercalado:
    python3 simulate_bruteforce.py \
        --attacker-ip 203.0.113.50 \
        --attempts 12 \
        --delay 0.4 \
        --noise-before 15 \
        --noise-during 10 \
        --noise-after 15 \
        --noise-delay-min 0.2 --noise-delay-max 2.5 \
        --seed 42
"""
import argparse
import random
import socket
import sys
import time
from datetime import datetime

HOSTNAME = "victim-host"

# ---------------------------------------------------------------------------
# Geradores de linhas de log "normais" (ruído de fundo).
# Cada função devolve uma string pronta pra virar o "message" do syslog,
# no formato: "<program>[<pid>]: <mensagem>"  (sem timestamp/host — isso é
# adicionado depois por send_line()).
# ---------------------------------------------------------------------------

NORMAL_USERS = ["deploy", "backup", "monitor", "carla", "joao"]
NORMAL_IPS = [
    "10.0.0.15", "10.0.0.22", "10.0.0.41",
    "192.168.1.50", "192.168.1.77",
]


def noise_cron():
    jobs = [
        "(root) CMD (/usr/bin/certbot renew --quiet)",
        "(root) CMD (/usr/local/bin/backup_db.sh)",
        "(www-data) CMD (/usr/bin/php /var/www/cron/cleanup.php)",
        "(root) CMD (run-parts /etc/cron.hourly)",
    ]
    return f"CRON[{random.randint(1000, 9999)}]: {random.choice(jobs)}"


def noise_systemd_session(action):
    user = random.choice(NORMAL_USERS)
    verb = "New session" if action == "open" else "Removed session"
    sid = random.randint(100, 999)
    suffix = f"of user {user}." if action == "open" else "."
    return f"systemd-logind[1]: {verb} {sid} {suffix}"


def noise_sshd_normal_login():
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    port = random.randint(40000, 60000)
    pid = random.randint(2000, 9000)
    return f"sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2"


def noise_sudo():
    user = random.choice(NORMAL_USERS)
    cmds = ["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/tail -f /var/log/syslog"]
    return f"sudo[{random.randint(2000, 9000)}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={random.choice(cmds)}"


def noise_kernel():
    msgs = [
        "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=10.0.0.5 PROTO=TCP",
        "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
        "kernel: TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.",
    ]
    return random.choice(msgs)


def noise_healthcheck():
    return f"healthcheck[{random.randint(1000, 5000)}]: GET /health HTTP/1.1 200 OK"


NOISE_GENERATORS = [
    noise_cron,
    lambda: noise_systemd_session("open"),
    lambda: noise_systemd_session("close"),
    noise_sshd_normal_login,
    noise_sudo,
    noise_kernel,
    noise_healthcheck,
]


def random_noise_line():
    return random.choice(NOISE_GENERATORS)()


# ---------------------------------------------------------------------------
# Envio via rede (UDP por padrão, TCP se --tcp)
# ---------------------------------------------------------------------------

def send_line(sock, host, port, raw_message, use_udp):
    line = f"{datetime.now().strftime('%b %e %H:%M:%S')} {HOSTNAME} {raw_message}\n"
    data = line.encode()
    if use_udp:
        sock.sendto(data, (host, port))
    else:
        sock.sendall(data)
    print(f"[enviado] {line.strip()}")


def burst_noise(sock, host, port, use_udp, count, delay_min, delay_max):
    for _ in range(count):
        send_line(sock, host, port, random_noise_line(), use_udp)
        time.sleep(random.uniform(delay_min, delay_max))


def main():
    parser = argparse.ArgumentParser(description="Simulador de incidente SSH com ruído de fundo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--tcp", action="store_true", help="usa TCP em vez de UDP")

    parser.add_argument("--attacker-ip", default="203.0.113.50")
    parser.add_argument("--user", default="admin", help="usuário-alvo do ataque")
    parser.add_argument("--attempts", type=int, default=8, help="quantas falhas antes do sucesso")
    parser.add_argument("--delay", type=float, default=0.3, help="segundos entre tentativas do atacante")

    parser.add_argument("--noise-before", type=int, default=10, help="linhas de ruído antes do ataque")
    parser.add_argument("--noise-during", type=int, default=6, help="linhas de ruído intercaladas DURANTE o ataque")
    parser.add_argument("--noise-after", type=int, default=10, help="linhas de ruído depois do ataque")
    parser.add_argument("--noise-delay-min", type=float, default=0.2)
    parser.add_argument("--noise-delay-max", type=float, default=1.5)

    parser.add_argument("--seed", type=int, default=None, help="fixa a aleatoriedade (reprodutível)")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    use_udp = not args.tcp
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if use_udp else socket.SOCK_STREAM)
    if not use_udp:
        sock.connect((args.host, args.port))

    print(f"[+] Alvo: {args.host}:{args.port} ({'UDP' if use_udp else 'TCP'})")
    print(f"[+] Fase 1/3: ruído de fundo ({args.noise_before} linhas)")
    burst_noise(sock, args.host, args.port, use_udp, args.noise_before,
                args.noise_delay_min, args.noise_delay_max)

    print(f"\n[+] Fase 2/3: ataque de força bruta de {args.attacker_ip} "
          f"contra '{args.user}' ({args.attempts} falhas), com ruído intercalado")

    port_num = 51400
    # Distribui as linhas de ruído "durante" entre as tentativas de ataque,
    # pra ficar tudo embaralhado em vez de vir em dois blocos separados.
    noise_slots = sorted(random.sample(range(args.attempts), min(args.noise_during, args.attempts)))
    noise_idx = 0

    for i in range(args.attempts):
        port_num += 1
        msg = f"sshd[1234]: Failed password for invalid user {args.user} from {args.attacker_ip} port {port_num} ssh2"
        send_line(sock, args.host, args.port, msg, use_udp)
        time.sleep(args.delay)

        # se essa posição sorteou uma linha de ruído, manda uma no meio
        while noise_idx < len(noise_slots) and noise_slots[noise_idx] == i:
            send_line(sock, args.host, args.port, random_noise_line(), use_udp)
            time.sleep(random.uniform(args.noise_delay_min, args.noise_delay_max))
            noise_idx += 1

    time.sleep(args.delay)
    port_num += 1
    msg = f"sshd[1234]: Accepted password for {args.user} from {args.attacker_ip} port {port_num} ssh2"
    send_line(sock, args.host, args.port, msg, use_udp)

    print(f"\n[+] Fase 3/3: ruído de fundo pós-ataque ({args.noise_after} linhas)")
    burst_noise(sock, args.host, args.port, use_udp, args.noise_after,
                args.noise_delay_min, args.noise_delay_max)

    sock.close()
    print("\n[+] Fim da simulação.")


if __name__ == "__main__":
    main()