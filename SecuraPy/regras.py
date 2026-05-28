"""
Modulo 2 - Motor de Regras
Responsavel por carregar regras de deteccao de um arquivo JSON,
avaliar cada evento contra as regras ativas e gerar alertas
quando uma regra eh violada.
"""

import json


def carregar_regras(caminho_config):
    """
    Le o arquivo regras.json e retorna a lista de regras.
    """
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras nao encontrado: {caminho_config}")
        return []
    except json.JSONDecodeError:
        print(f"[ERRO] JSON invalido em: {caminho_config}")
        return []

    if isinstance(dados, dict):
        regras = dados.get("regras", [])
    elif isinstance(dados, list):
        regras = dados
    else:
        return []

    return [r for r in regras if isinstance(r, dict) and r.get("ativa", False)]


def classificar_severidade(pontuacao):
    """
    Converte uma pontuacao numerica em nivel de severidade.
    """
    try:
        valor = float(pontuacao)
    except (TypeError, ValueError):
        valor = 0

    if valor >= 9:
        return "CRITICA"
    elif valor >= 7:
        return "ALTA"
    elif valor >= 5:
        return "MEDIA"
    elif valor >= 3:
        return "BAIXA"
    return "INFO"


def _extrair_usuario(detalhes):
    for parte in str(detalhes).split():
        if parte.startswith("usuario="):
            return parte.split("=", 1)[1]
    return None


def _extrair_dport(detalhes):
    for parte in str(detalhes).split():
        if parte.startswith("dport="):
            return parte.split("=", 1)[1]
    return None


def _extrair_url(detalhes):
    for parte in str(detalhes).split():
        if parte.startswith("url="):
            return parte.split("=", 1)[1]
    return ""


def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra especifica.
    """
    if not isinstance(regra, dict) or not isinstance(evento, dict):
        return None

    fonte_regra = regra.get("fonte")
    if fonte_regra and evento.get("fonte") != fonte_regra:
        return None

    condicao = regra.get("condicao")
    if not condicao:
        return None

    violou = False
    descricao = regra.get("descricao", "")
    ip = evento.get("ip", "")
    timestamp = evento.get("timestamp", "")
    nome = regra.get("nome") or regra.get("regra_nome") or regra.get("titulo") or regra.get("id") or regra.get("regra_id", "Regra")
    regra_id = regra.get("id") or regra.get("regra_id") or nome
    pontuacao = regra.get("severidade_base", 0)
    severidade = regra.get("severidade")
    if not severidade:
        severidade = classificar_severidade(pontuacao)

    if condicao == "usuario_privilegiado":
        usuario = _extrair_usuario(evento.get("detalhes", ""))
        usuarios_alvo = regra.get("usuarios_alvo", [])
        violou = usuario is not None and usuario in usuarios_alvo
        if violou and not descricao:
            descricao = f"Tentativa de login com usuario {usuario}"

    elif condicao == "porta_critica":
        dport = _extrair_dport(evento.get("detalhes", ""))
        portas = {str(p) for p in regra.get("portas_criticas", [])}
        violou = dport is not None and str(dport) in portas
        if violou and not descricao:
            descricao = f"Bloqueio em porta critica {dport}"

    elif condicao in {"path_traversal", "xss", "reconhecimento"}:
        url = _extrair_url(evento.get("detalhes", ""))
        padroes = regra.get("padroes", [])
        if condicao == "path_traversal" and not padroes:
            padroes = ["../", "..\\", "%2e%2e%2f", "%2e%2e\\"]
        elif condicao == "xss" and not padroes:
            padroes = ["<script", "javascript:", "onerror=", "onload="]
        elif condicao == "reconhecimento" and not padroes:
            padroes = ["/admin", "/login", "/wp-admin", "/phpmyadmin"]
        violou = any(padrao in url for padrao in padroes)
        if violou and not descricao:
            descricao = f"Padrao suspeito identificado na URL: {url}"

    else:
        return None

    if not violou:
        return None

    return {
        "timestamp": timestamp,
        "regra_id": regra_id,
        "regra_nome": nome,
        "severidade": severidade,
        "ip": ip,
        "descricao": descricao,
    }


def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras a todos os eventos e retorna os alertas gerados.
    """
    alertas = []
    for evento in eventos or []:
        for regra in regras or []:
            resultado = avaliar_regra(regra, evento)
            if resultado is not None:
                alertas.append(resultado)
    return alertas
