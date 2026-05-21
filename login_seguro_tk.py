"""
Este ficheiro é o "MAIN", ele é o autenticador, orquestra tudo, e implementa a lógica do programa como uma plataforma de autenticação segura, em modo consola (terminal)

O main coordena, o io_utils lê/escreve, o parser converte logs, e o analytics usa esses logs convertidos para decidir e atualizar a blacklist

"""


from __future__ import annotations

import base64 #transforma bytes em texto e vice-versa
import hashlib #faz hash seguro de password - PBKDF2
import hmac #comparação segura para evitar ataques por timing
import os #para poder fazer salt, a gerar bytes aleatórios
from dataclasses import dataclass
from datetime import datetime, timezone #trabalhar com tempo em UTC
from getpass import getpass #pede password sem mostrar no ecrã
from typing import Dict, Optional, Tuple #indica que tipo de dados uma variável, parametro ou retorno de função deve ter (type hints)

from io_utils import read_json, atomic_write_json, append_csv_row #ler/escrever JSON e adicionar linhas a CSV
from analytics import (
    load_blacklist,
    save_blacklist,
    blacklist_is_blocked,
    analyse_and_update_blacklist,
) #gerir blacklist e analisar logs para bloquear IPs suspeitos

USERS_PATH = "users_secure.json" #bd utilizadores(JSON)
BLACKLIST_PATH = "blacklist.json" #blacklist
LOGS_PATH = "logs_exemplo.csv"     #logs (JSON)

LOG_HEADERS = ["timestamp", "utilizador", "ip", "sucesso"]

# Lockout / Backoff exponencial
MAX_FAILS_BEFORE_LOCK = 3
BASE_LOCK_SECONDS = 30          # 1º lock: 30s
MAX_LOCK_SECONDS = 60 * 60      # até 1h

#base 64 encode/decode
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)   #hora atual em UTC


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")  #Como JSON não guarda bem os bytes, eles guardam como string Base64.


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

#hash seguro
def pbkdf2_hash_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)

#le e guarda utilizadores, read_json lê o ficheiro; se não existir, cria estrutura default:
def load_users() -> Dict:
    return read_json(USERS_PATH, default={"users": {}}) 


def save_users(data: Dict) -> None:
    atomic_write_json(USERS_PATH, data) #atomic_write_json escreve de forma “atómica” (evita ficheiro corrompido se houver falha a meio)


def _get_user_record(users_db: Dict, username: str) -> Optional[Dict]:
    return (users_db.get("users") or {}).get(username)    #busca registo de um utilizador


"""
Criar utilizador

Fluxo:

Carrega BD

Verifica se já existe

Pede password 2x

Valida tamanho

Gera salt

Faz hash PBKDF2

Guarda no JSON

"""



def create_user(username: str) -> None:
    users_db = load_users()
    users = users_db.setdefault("users", {})

    if username in users:
        print("❌ Utilizador já existe.")
        return

    pw1 = getpass("Password: ")
    pw2 = getpass("Confirmar password: ")
    if pw1 != pw2:
        print("❌ As passwords não coincidem.")
        return
    if len(pw1) < 6:
        print("❌ Password demasiado curta (mínimo sugerido: 6).")
        return

    salt = os.urandom(16) #gera bytes aleatórios (salt)
    iterations = 200_000
    pwd_hash = pbkdf2_hash_password(pw1, salt, iterations)

    users[username] = {
        "salt": _b64e(salt),
        "hash": _b64e(pwd_hash),
        "iterations": iterations,
        "failed_attempts": 0, #contador de falhas
        "lock_until": 0,  # epoch seconds (UTC). 0 = não bloqueado
    }

    save_users(users_db)
    print("✅ Utilizador criado com sucesso.")


def _lockout_seconds(failed_attempts: int) -> int:
    """
    Backoff exponencial após MAX_FAILS_BEFORE_LOCK:
    lock = BASE_LOCK_SECONDS * 2^(n-1), com cap em MAX_LOCK_SECONDS
    """
    n = max(1, failed_attempts - MAX_FAILS_BEFORE_LOCK + 1)
    secs = BASE_LOCK_SECONDS * (2 ** (n - 1))
    return min(secs, MAX_LOCK_SECONDS)


#ver se a conta está bloqueada
def _is_account_locked(user_rec: Dict, now: datetime) -> Tuple[bool, int]:
    lock_until = int(user_rec.get("lock_until", 0) or 0) #ainda está no futuro = conta bloqueada
    now_epoch = int(now.timestamp())
    if lock_until > now_epoch:
        return True, lock_until - now_epoch
    return False, 0

#verificar login (password)

def verify_login(username: str, password: str) -> bool:
    users_db = load_users()
    user_rec = _get_user_record(users_db, username)
    if not user_rec:
        return False

    salt = _b64d(user_rec["salt"]) #recalcula hash com salt guardado
    stored = _b64d(user_rec["hash"])
    iterations = int(user_rec.get("iterations", 200_000))

    test = pbkdf2_hash_password(password, salt, iterations)

    return hmac.compare_digest(stored, test) #evita vazamento por timing

#guardar logs de tentativas (CSV)
def log_attempt(username: str, ip: str, success: bool) -> None:
    ts = _now_utc().isoformat().replace("+00:00", "Z")
    append_csv_row(
        LOGS_PATH,
        headers=LOG_HEADERS,
        row={
            "timestamp": ts, #UTC (formato ISO, termina em Z)
            "utilizador": username,
            "ip": ip,
            "sucesso": "true" if success else "false",
        },
    )

#fluxo completo de login

def login_flow(username: str, ip: str) -> None:
    now = _now_utc()

    # 1) Verificar blacklist antes de tudo
    blacklist = load_blacklist(BLACKLIST_PATH)
    blocked, reason = blacklist_is_blocked(blacklist, ip, now=now)
    if blocked:
        print(f"⛔ Acesso recusado. IP bloqueado ({reason}).")
        log_attempt(username, ip, False)
        return
    else:
        # Se blacklist foi limpa (expirados removidos), guardar
        save_blacklist(BLACKLIST_PATH, blacklist)

    users_db = load_users() #verificar se utilizador existe
    user_rec = _get_user_record(users_db, username)
    if not user_rec:
        print("❌ Utilizador não existe.")
        log_attempt(username, ip, False)
        return

    # 2) Verificar lockout da conta
    locked, remaining = _is_account_locked(user_rec, now)
    if locked:
        print(f"⏳ Conta temporariamente bloqueada. Tenta novamente em ~{remaining}s.")
        log_attempt(username, ip, False)
        return

    # 3) Pedir password
    password = getpass("Password: ")

    ok = verify_login(username, password)
    if ok:
        print("✅ Login com sucesso.")
        user_rec["failed_attempts"] = 0
        user_rec["lock_until"] = 0
        save_users(users_db)
        log_attempt(username, ip, True)

        #após login, pode correr análise para manter blacklist atualizada
        analyse_and_update_blacklist(LOGS_PATH, BLACKLIST_PATH)
        return

    #falhou
    user_rec["failed_attempts"] = int(user_rec.get("failed_attempts", 0) or 0) + 1
    fails = user_rec["failed_attempts"]

    #ativar lockout após N falhas
    if fails >= MAX_FAILS_BEFORE_LOCK:
        secs = _lockout_seconds(fails)
        user_rec["lock_until"] = int((now.timestamp() + secs))
        print(f"❌ Credenciais inválidas. Conta bloqueada por {secs}s (backoff).")
    else:
        print("❌ Credenciais inválidas.")

    save_users(users_db)
    log_attempt(username, ip, False)

    # Após falha, correr análise de logs para detetar ataques e atualizar blacklist
    report = analyse_and_update_blacklist(LOGS_PATH, BLACKLIST_PATH)
    if report.get("new_blocks_applied"):
        print("⚠️ Detetados comportamentos suspeitos. Blacklist atualizada:")
        for b in report["new_blocks_applied"]:
            print(f" - {b['ip']} | {b['reason']} | blocked_until={b['blocked_until']}")

"""
Loop infinito com opções:
criar utilizador
login (pede username + ip simulado)
analisar logs / atualizar blacklist
sair

"""

def main():
    while True:
        print("\n=== Plataforma de Autenticação Resiliente ===")
        print("1) Criar utilizador")
        print("2) Fazer login")
        print("3) Analisar logs / atualizar blacklist")
        print("0) Sair")

        op = input("Escolhe uma opção: ").strip()

        if op == "1":
            username = input("Novo utilizador: ").strip()
            if not username:
                print("❌ Nome inválido.")
                continue
            create_user(username)

        elif op == "2":
            username = input("Utilizador: ").strip()
            ip = input("IP de origem (simulado): ").strip()
            if not ip:
                print("❌ IP inválido.")
                continue
            login_flow(username, ip)

        elif op == "3":
            report = analyse_and_update_blacklist(LOGS_PATH, BLACKLIST_PATH)
            print("📊 Relatório:")
            print(report)

        elif op == "0":
            print("Até logo!")
            break
        else:
            print("❌ Opção inválida.")


if __name__ == "__main__":
    main()

#só executa o menu se correr o ficheiro diretamente