"""
O parser serve para ler o ficheiro CSV de logs e converter cada linha de texto num objeto estruturado - um dado, garantindo tipos corretos, datas em UTC e tolerância a erros (datas, IPs, sucesso/falha), permitindo que o ANALYTICS.PY posteriormente receba analise os dados de forma segura e consistente.

(LogEntry é uma classe de dados, dataclass)
Lê o ficheiro CSV de logs, converte cada linha num objeto LogEntry, valida e normaliza os dados .

logs_exemplo.csv → parser → List[LogEntry] → analytics → blacklist.json 


"""


import csv #le ficheiros CSV
from dataclasses import dataclass #facilita a criação de classes apenas para guardar dados
from datetime import datetime, timezone #trabalham com datas e horas (incluindo fuso horário)
from typing import List, Optional #type hints

#CLASSE LogEntry, define a estrutura de uma linha de log

@dataclass(frozen=True) #torna o objeto imutável (depois de criado, não pode ser alterado)
class LogEntry:
    timestamp: datetime
    utilizador: str
    ip: str
    sucesso: bool


#converte ISO 8601 (com ou sem 'Z') para um objeto datetime em UTC
def _parse_iso(ts: str) -> datetime:

    ts = ts.strip() #remove espaços extra
    if ts.endswith("Z"): #Z=UTC
        ts = ts[:-1] + "+00:00" #nao aceita Z por isso troca por +00:00
    dt = datetime.fromisoformat(ts) #converte str para datetime
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc) #se não tiver fuso horário, assume UTC
    return dt.astimezone(timezone.utc) #arante que a data final está sempre em UTC

#FUNCAO que le o ficheiro csv e devolve lista LogEntry
def read_logs_csv(path: str) -> List[LogEntry]:
    entries: List[LogEntry] = [] #criacao da lista
    with open(path, "r", newline="", encoding="utf-8") as f: #abre ficheiro (path) em modo leitura(r), sem mexer nos caracteres(newline)utf-8 evita problemas com acentos
        reader = csv.DictReader(f) #cada linha do CSV vira um dicionário
        for row in reader:
            if not row:
                continue
            try: #se tiver linhas malformadas, ignora (boa prática para logs reais)
                ts = _parse_iso(row["timestamp"]) #converte a data para datetime
                user = (row.get("utilizador") or "").strip() #get() evita erro se a coluna não existir, strip() remove espacos
                ip = (row.get("ip") or "").strip()
                sucesso_raw = (row.get("sucesso") or "").strip().lower() #normaliza o valor
                sucesso = sucesso_raw in ("true", "1", "yes", "y") #transforma texto em booleano
                entries.append(LogEntry(timestamp=ts, utilizador=user, ip=ip, sucesso=sucesso)) #cria o objeto LogEntry
            except Exception:
                
                continue
    return entries #devolve a lista com todos os logs válidos.


def try_read_logs_csv(path: str) -> Optional[List[LogEntry]]: #tenta ler o CSV sem crashar o programa.
    try:
        return read_logs_csv(path) #se o ficheiro existir = devolve os logs
    except FileNotFoundError:
        return None  #se não existir = devolve None


