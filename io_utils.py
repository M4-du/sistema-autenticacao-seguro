"""
Tudo o que envolve guardar dados no disco ou ler dados do disco passa pelo io_utils- Input / Output Utilities: trata de ler e escrever ficheiros sem decidir nenhuma logica (login, seguranca etc), só faz operacoes Input Output e garante que os ficheiros nao sejam corrompidos. Nenhum outro módulo escreve diretamente em ficheiros, ele é quem cria o adiciona linhas a todos os ficheiros do programa: "logs_exemplo.csv" "user_secure" e "blacklist"

"""

import csv
import json
import os  #operações com o sistema operativo (pastas, caminhos, ficheiros)
import tempfile  #criar ficheiros temporários de forma segura
from typing import Any, Dict, List #indica que tipo de dados uma variável, parametro ou retorno de função deve ter (type hints)

#garante que a pasta onde o ficheiro vai ser guardado existe, evita erros do tipo “no such file or directory”
def ensure_parent_dir(path: str) -> None: #pasta PAI
    parent = os.path.dirname(os.path.abspath(path)) #os.path.abspath = transforma o caminho num caminho absoluto, os.path.dirname = extrai a pasta “pai”
    if parent and not os.path.exists(parent):  #se a pasta PAI não existir cria-a, para evita erros do tipo “no such file or directory”
        os.makedirs(parent, exist_ok=True)  
        


def atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    """
   Escrever um ficheiro JSON de forma atómica, ou seja: ou o ficheiro é escrito por completo, ou não é alterado(nao guarda). isto evita ficheiros JSON corrompidos se o programa falhar a meio.
    """
    ensure_parent_dir(path) #garante que a pasta existe
    dir_name = os.path.dirname(os.path.abspath(path)) or "." #define a pasta onde o ficheiro temporario vai ser criado
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=dir_name) #cria ficheiro temporário oculto (.tmp_XXXX.json) com os dados:
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True) #permite acentos, le JSON e ordena chaves com seus respectivos valores
        os.replace(tmp_path, path) #substitui o ficheiro temporario em permanente num único passo seguro
    finally:        #garante limpeza se algo correr mal       
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


#lê um ficheiro JSON ou devolve default

def read_json(path: str, default: Dict[str, Any]) -> Dict[str, Any]: 
    if not os.path.exists(path): #se o ficheiro não existir= evita erro e devolve o default
        return default
    with open(path, "r", encoding="utf-8") as f: #le e devolve o conteudo JSON como dicionario
        return json.load(f)


#escrever CSV
def append_csv_row(path: str, headers: List[str], row: Dict[str, Any]) -> None: #acrescenta uma linha a um CSV criando se necessario

    ensure_parent_dir(path) #garante que a paste existe
    file_exists = os.path.exists(path) #verifica se existe
    needs_header = (not file_exists) or (os.path.getsize(path) == 0) #se a pasta estiver vazia, cria-se com o cabeçalho CSV(indicando as chaves e valores)

    with open(path, "a", newline="", encoding="utf-8") as f: #abre o ficheiro em modo append (permite adicionar conteúdo no fim do ficheiro, sem apagar o que já existe)
        writer = csv.DictWriter(f, fieldnames=headers) #permite escrever linhas usando dicionários
        if needs_header:  #cria-se com o cabeçalho CSV(indicando as chaves e valores)
            writer.writeheader()
        writer.writerow(row) #adiciona a nova linha ao CSV
