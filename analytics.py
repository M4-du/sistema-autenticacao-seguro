"""
O ANALYTICS serve para decidir QUANDO bloquear IPS e quais, este script é um detetor de ataques de força bruta a logins, o mais importante do programa

"""

from __future__ import annotations

from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional #type hint

from parser import LogEntry, try_read_logs_csv  #estrutura com dados de login, le o CSV e devolve uma lista 
from io_utils import read_json, atomic_write_json 
"""
regras do enunciado:
-  10+ falhas em 5 minutos = bloqueio temporário (1h)
-  30+ falhas em 24h = bloqueio permanente
-  5 utilizadores atacados pelo mesmo IP em 10 minutos = bloqueio temporário (1h)
"""

SHORT_WINDOW = timedelta(minutes=5)
LONG_WINDOW = timedelta(hours=24)
DISTR_WINDOW = timedelta(minutes=10)

SHORT_FAILS = 10
LONG_FAILS = 30
DIST_USERS = 5

TEMP_BLOCK = timedelta(hours=1) #duracao bloqueio temporario

#queando o script decide bloquear um IP, cria uma classe BlockDecision com
@dataclass
class BlockDecision:
    ip: str #IP a bloquear
    blocked_until_epoch: Optional[int]  # timestamp Unix opcional, ou se nao, none = permanente
    reason: str #texto curto (“bruteforce_24h”, “bruteforce_5m”)

#tempo atual em UTC
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

#le e guarda blacklist em blacklist.json
def load_blacklist(path: str) -> Dict:
    return read_json(path, default={"ips": {}})


def save_blacklist(path: str, data: Dict) -> None:
    atomic_write_json(path, data)

#verificar IP bloqueado
def blacklist_is_blocked(blacklist: Dict, ip: str, now: Optional[datetime] = None) -> Tuple[bool, str]:
    """
    Devolve (bloqueado?, motivo). Remove bloqueios temporários expirados.
    """
    now = now or _now_utc()
    ips = blacklist.get("ips", {})
    entry = ips.get(ip)
    if not entry:
        return False, ""

    blocked_until = entry.get("blocked_until")
    reason = entry.get("reason", "unknown")

    if blocked_until is None:
        return True, reason  # permanente

    try:
        blocked_until = int(blocked_until)
    except Exception:
        # entrada corrupta = remove
        ips.pop(ip, None)
        return False, ""

    if now.timestamp() < blocked_until:
        return True, reason

    # expirou = remove
    ips.pop(ip, None)
    return False, ""

#adiciona/atualiza um bloqueio, sem fazer downgrade no tempo, retorna true se alterou algo

def add_block(blacklist: Dict, decision: BlockDecision) -> bool:

    ips = blacklist.setdefault("ips", {})
    existing = ips.get(decision.ip)

    new_obj = {
        "blocked_until": decision.blocked_until_epoch,
        "reason": decision.reason,
    }

    if existing == new_obj:
        return False

    # Se já estava permanente, não faz downgrade para temporário
    if existing and existing.get("blocked_until") is None and decision.blocked_until_epoch is not None:
        return False

    ips[decision.ip] = new_obj
    return True

#estatísticas dos logs
def compute_stats(entries: List[LogEntry]) -> Dict:
    total = len(entries)
    fails = sum(1 for e in entries if not e.sucesso)
    success = total - fails

    fails_by_ip = Counter(e.ip for e in entries if not e.sucesso)
    fails_by_user = Counter(e.utilizador for e in entries if not e.sucesso)

    return {
        "total": total,
        "success": success,
        "fails": fails,
        "fails_by_ip_top10": fails_by_ip.most_common(10),
        "fails_by_user_top10": fails_by_user.most_common(10),
    }


def _window_filter(entries: List[LogEntry], start: datetime, end: datetime) -> List[LogEntry]:
    return [e for e in entries if start <= e.timestamp <= end]

## DETETAR IPS SUSPEITOS

def detect_suspicious_ips(entries: List[LogEntry], now: Optional[datetime] = None) -> List[BlockDecision]:
    """
    Avalia regras e devolve lista de decisões de bloqueio.
    """
    now = now or _now_utc()
    decisions: List[BlockDecision] = []

    # Pré-index por IP para performance
    by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for e in entries:
        by_ip[e.ip].append(e)

    for ip, ip_entries in by_ip.items():
        # Considera apenas falhas
        fails = [e for e in ip_entries if not e.sucesso]
        if not fails:
            continue

        # Regra longo prazo: >= 30 falhas em 24h
        long_start = now - LONG_WINDOW
        fails_24h = [e for e in fails if e.timestamp >= long_start]
        if len(fails_24h) >= LONG_FAILS:
            decisions.append(BlockDecision(ip=ip, blocked_until_epoch=None, reason="bruteforce_24h"))
            continue  # permanente ganha

        # Regra curto prazo: >= 10 falhas em 5m
        short_start = now - SHORT_WINDOW
        fails_5m = [e for e in fails if e.timestamp >= short_start]
        if len(fails_5m) >= SHORT_FAILS:
            until = int((now + TEMP_BLOCK).timestamp())
            decisions.append(BlockDecision(ip=ip, blocked_until_epoch=until, reason="bruteforce_5m"))
            continue

        # Regra distribuída: >= 5 utilizadores atacados em 10m (por falhas)
        dist_start = now - DISTR_WINDOW
        fails_10m = [e for e in fails if e.timestamp >= dist_start]
        users = {e.utilizador for e in fails_10m if e.utilizador}
        if len(users) >= DIST_USERS:
            until = int((now + TEMP_BLOCK).timestamp())
            decisions.append(BlockDecision(ip=ip, blocked_until_epoch=until, reason="distributed_attack_10m"))

    return decisions

# FUNÇÃO PRINCIPAL:

def analyse_and_update_blacklist(
    logs_path: str = "logs_exemplo.csv",
    blacklist_path: str = "blacklist.json",
    now: Optional[datetime] = None,
) -> Dict:
    """
    Lê logs, calcula estatísticas, deteta IPs suspeitos e atualiza blacklist.json.
    Retorna um relatório (dict).
    """
    now = now or _now_utc()
    entries = try_read_logs_csv(logs_path) or []

    blacklist = load_blacklist(blacklist_path) 

    # limpa ips expirados 
    ips = list((blacklist.get("ips") or {}).keys())
    for ip in ips:
        blacklist_is_blocked(blacklist, ip, now=now)

    #calcula stats e decisões
    stats = compute_stats(entries) 
    decisions = detect_suspicious_ips(entries, now=now)

    changed = False
    applied: List[Dict] = []

    #aplica decisões (e guarda se mudou)
    for d in decisions:
        if add_block(blacklist, d):
            changed = True #se changed for true, grava no JSON
            applied.append({
                "ip": d.ip,
                "blocked_until": d.blocked_until_epoch,
                "reason": d.reason
            })

    if changed:
        save_blacklist(blacklist_path, blacklist)

    #devolve relatorio
    return {
        "generated_at_utc": now.isoformat(),
        "stats": stats,
        "new_blocks_applied": applied,
        "blacklist_count": len(blacklist.get("ips", {})),
    }


#execução direta, atualiza blacklist, imprime relatório
if __name__ == "__main__":
    report = analyse_and_update_blacklist()
    print("Relatório de análise:")
    print(report)
