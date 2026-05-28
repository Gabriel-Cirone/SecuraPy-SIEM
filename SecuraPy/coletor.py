"""
Modulo 1 - Coletor de Logs
Responsavel por ler arquivos de log de diferentes fontes (auth, firewall, web),
parsear cada linha e normalizar os eventos em um formato padronizado de dicionario.
"""

import os


def _linha_valida(linha):
    return isinstance(linha, str) and linha.strip() != ""


def _extrair_kv(partes):
    dados = {}
    for parte in partes:
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            dados[chave.strip()] = valor.strip()
    return dados


def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log e retorna um dicionario normalizado.
    """
    if not _linha_valida(linha):
        return None

    partes = linha.strip().split()
    if len(partes) < 5:
        return None

    timestamp = f"{partes[0]} {partes[1]}"
    tipo = partes[2].upper()
    if tipo not in {"OK", "FAIL"}:
        return None

    dados = _extrair_kv(partes[3:])
    ip = dados.get("ip")
    usuario = dados.get("usuario")
    if not ip or not usuario:
        return None

    detalhes = f"usuario={usuario}"
    return {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log e retorna um dicionario normalizado.
    """
    if not _linha_valida(linha):
        return None

    partes = linha.strip().split()
    if len(partes) < 6:
        return None

    timestamp = f"{partes[0]} {partes[1]}"
    tipo = partes[2].upper()
    if tipo not in {"BLOCK", "ALLOW"}:
        return None

    dados = _extrair_kv(partes[3:])
    src = dados.get("src")
    dst = dados.get("dst")
    dport = dados.get("dport")
    proto = dados.get("proto")
    if not src or not dst or not dport or not proto:
        return None

    detalhes = f"proto={proto} dst={dst} dport={dport}"
    return {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": tipo,
        "ip": src,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log e retorna um dicionario normalizado.
    """
    if not _linha_valida(linha):
        return None

    partes = linha.strip().split()
    if len(partes) < 6:
        return None

    timestamp = f"{partes[0]} {partes[1]}"
    tipo = partes[2].upper()
    dados = _extrair_kv(partes[3:])
    ip = dados.get("ip")
    url = dados.get("url")
    status = dados.get("status")
    if not ip or not url or not status:
        return None

    detalhes = f"url={url} status={status}"
    return {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def carregar_log(caminho_arquivo, fonte):
    """
    Le um arquivo de log e retorna uma lista de eventos normalizados.
    """
    parsers = {
        "auth": parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web": parsear_linha_web,
    }

    parser = parsers.get(fonte)
    if parser is None:
        print(f"[ERRO] Fonte invalida: {fonte}")
        return []

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: {caminho_arquivo}")
        return []

    eventos = []
    for linha in linhas:
        if not linha.strip():
            continue
        evento = parser(linha)
        if evento is None:
            print(f"[AVISO] Linha ignorada em {caminho_arquivo}: {linha.strip()}")
            continue
        eventos.append(evento)

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """
    Le todos os arquivos de log da pasta e retorna uma lista unificada de eventos.
    """
    if not os.path.isdir(pasta_logs):
        print(f"[ERRO] Pasta de logs nao encontrada: {pasta_logs}")
        return []

    eventos = []
    for arquivo in sorted(os.listdir(pasta_logs)):
        if not arquivo.endswith(".log"):
            continue

        caminho = os.path.join(pasta_logs, arquivo)
        if "auth" in arquivo:
            fonte = "auth"
        elif "firewall" in arquivo:
            fonte = "firewall"
        elif "web" in arquivo:
            fonte = "web"
        else:
            continue

        eventos_arquivo = carregar_log(caminho, fonte)
        print(f"{arquivo}: {len(eventos_arquivo)} eventos carregados")
        eventos.extend(eventos_arquivo)

    return eventos
