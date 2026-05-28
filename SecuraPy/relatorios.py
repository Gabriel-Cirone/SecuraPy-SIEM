"""
Modulo 6 - Dashboard CLI e Relatorios
Interface interativa do SIEM com menu de opcoes, filtros de eventos,
busca por IP, ranking de ameacas e exportacao de relatorios em JSON.
"""

import json
import os
from datetime import datetime

from enriquecimento import consultar_ip, exibir_enriquecimento


def exibir_menu():
    """
    Exibe o menu principal do SecuraPy e retorna a opcao escolhida.
    """
    print("\n" + "=" * 50)
    print("1. Carregar e processar logs")
    print("2. Resumo geral")
    print("3. Filtrar eventos")
    print("4. Buscar IP")
    print("5. Top 10 IPs suspeitos")
    print("6. Ver alertas por severidade")
    print("7. Enriquecer IPs suspeitos")
    print("8. Exportar relatorio JSON")
    print("9. Iniciar servidor de alertas")
    print("0. Sair")
    print("=" * 50)

    try:
        return int(input("Escolha uma opcao: "))
    except ValueError:
        return -1
    except EOFError:
        return 0


def resumo_geral(eventos, alertas):
    """
    Exibe um resumo com contadores gerais do processamento.
    """
    contagem_eventos = {"auth": 0, "firewall": 0, "web": 0}
    for evento in eventos or []:
        fonte = evento.get("fonte")
        if fonte in contagem_eventos:
            contagem_eventos[fonte] += 1
        else:
            contagem_eventos[fonte] = contagem_eventos.get(fonte, 0) + 1

    severidades = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAIXA": 0, "INFO": 0}
    for alerta in alertas or []:
        sev = alerta.get("severidade", "INFO")
        severidades[sev] = severidades.get(sev, 0) + 1

    print("\nResumo geral")
    print("-" * 50)
    print(f"Total de eventos: {len(eventos or [])}")
    for fonte in ["auth", "firewall", "web"]:
        print(f"{fonte:<10}: {contagem_eventos.get(fonte, 0)}")
    print(f"Total de alertas: {len(alertas or [])}")
    for sev in ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]:
        print(f"{sev:<10}: {severidades.get(sev, 0)}")


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """
    Filtra eventos pelos criterios fornecidos.
    """
    return [
        e for e in (eventos or [])
        if (fonte is None or e.get("fonte") == fonte)
        and (tipo is None or e.get("tipo") == tipo)
        and (ip is None or e.get("ip") == ip)
    ]


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """
    Exibe relatorio completo de um IP: eventos, alertas e geolocalizacao.
    """
    eventos_ip = filtrar_eventos(eventos, ip=ip)
    alertas_ip = [a for a in (alertas or []) if a.get("ip") == ip]
    dados_ip = consultar_ip(ip, cache_enriquecimento)

    print(f"\nRelatorio do IP {ip}")
    print("-" * 50)
    print(f"Eventos encontrados: {len(eventos_ip)}")
    for evento in eventos_ip:
        print(f"{evento.get('timestamp')} | {evento.get('fonte')} | {evento.get('tipo')} | {evento.get('detalhes')}")

    print(f"\nAlertas encontrados: {len(alertas_ip)}")
    for alerta in alertas_ip:
        print(f"{alerta.get('timestamp')} | {alerta.get('severidade')} | {alerta.get('regra_nome')} | {alerta.get('descricao')}")

    print("\nGeolocalizacao")
    exibir_enriquecimento(dados_ip)

    return {
        "eventos": eventos_ip,
        "alertas": alertas_ip,
        "geolocalizacao": dados_ip,
    }


def top_ips(eventos, n=10):
    """
    Retorna os N IPs com mais eventos registrados.
    """
    contagem = {}
    for evento in eventos or []:
        ip = evento.get("ip")
        if not ip:
            continue
        contagem[ip] = contagem.get(ip, 0) + 1

    resultado = sorted(contagem.items(), key=lambda x: x[1], reverse=True)
    return resultado[:n]


def _sanitizar_json(obj):
    if isinstance(obj, dict):
        return {k: _sanitizar_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitizar_json(v) for v in obj]
    if isinstance(obj, set):
        return sorted(_sanitizar_json(v) for v in obj)
    if isinstance(obj, tuple):
        return [_sanitizar_json(v) for v in obj]
    return obj


def exportar_relatorio_json(dados, caminho):
    """
    Salva um relatorio completo em formato JSON.
    """
    diretorio = os.path.dirname(caminho)
    if diretorio:
        os.makedirs(diretorio, exist_ok=True)

    dados = _sanitizar_json(dados)

    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)

    print(f"Relatorio salvo em: {caminho}")


def exibir_tabela(dados, colunas):
    """
    Exibe uma lista de dicionarios como tabela formatada no terminal.
    """
    if not dados:
        print("Nenhum dado encontrado")
        return

    colunas = list(colunas or [])
    if not colunas:
        print("Nenhum dado encontrado")
        return

    larguras = {}
    for coluna in colunas:
        max_dado = max(len(str(item.get(coluna, ""))) for item in dados)
        larguras[coluna] = max(max_dado, len(str(coluna)))

    cabecalho = " | ".join(f"{coluna:<{larguras[coluna]}}" for coluna in colunas)
    separador = "-+-".join("-" * larguras[coluna] for coluna in colunas)
    print(cabecalho)
    print(separador)
    for item in dados:
        linha = " | ".join(f"{str(item.get(coluna, '')):<{larguras[coluna]}}" for coluna in colunas)
        print(linha)
