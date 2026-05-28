"""
Modulo 5 - Enriquecimento de IPs
Adiciona contexto geografico e organizacional aos IPs suspeitos
consultando a API publica do ipinfo.io.

Classifica IPs em privados (rede interna) e publicos, e consulta
apenas os publicos para economizar requisicoes.

Formato do resultado de enriquecimento:
{
    "ip": "185.220.101.1",
    "privado": False,
    "cidade": "Frankfurt am Main",
    "regiao": "Hesse",
    "pais": "DE",
    "org": "AS208294 Fastethernet",
    "hostname": "tor-exit.r2"
}
"""

import requests
import json


def eh_ip_privado(ip):
    """
    Verifica se um endereco IP pertence a uma faixa de rede privada (RFC 1918).

    Parametros:
        ip (str): endereco IPv4 no formato "x.x.x.x"

    Retorna:
        bool: True se o IP for privado, False se for publico

    Faixas privadas:
        10.0.0.0    - 10.255.255.255   (10.x.x.x)
        172.16.0.0  - 172.31.255.255   (172.16-31.x.x)
        192.168.0.0 - 192.168.255.255  (192.168.x.x)
        127.0.0.0   - 127.255.255.255  (127.x.x.x - loopback)
    """
    try:
        octetos = [int(x) for x in ip.split(".")]

        if len(octetos) != 4:
            return False

        if not all(0 <= o <= 255 for o in octetos):
            return False

        primeiro  = octetos[0]
        segundo   = octetos[1]

        if primeiro == 10:
            return True

        if primeiro == 172 and 16 <= segundo <= 31:
            return True

        if primeiro == 192 and segundo == 168:
            return True

        if primeiro == 127:
            return True

        return False

    except (ValueError, AttributeError):
        # IP mal formatado (ex: "999.999.999.999" ou valor nao-string)
        return False


def consultar_ip(ip, cache):
    """
    Consulta a API do ipinfo.io para obter informacoes de geolocalizacao.

    Parametros:
        ip (str): endereco IP publico a ser consultado
        cache (dict): dicionario usado como cache de consultas anteriores

    Retorna:
        dict: informacoes do IP com chaves: ip, privado, cidade, regiao, pais, org, hostname
        Retorna dict com valores "Desconhecido" em caso de erro.
    """
    # 1. Retorna do cache se ja foi consultado
    if ip in cache:
        return cache[ip]

    # 2. IP privado: nao consulta a API, retorna dados fixos
    if eh_ip_privado(ip):
        resultado = {
            "ip":       ip,
            "privado":  True,
            "cidade":   "Rede Interna",
            "regiao":   "Rede Interna",
            "pais":     "Rede Interna",
            "org":      "Rede Interna",
            "hostname": "Rede Interna",
        }
        cache[ip] = resultado
        return resultado

    # Template de resultado padrao (usado em caso de erro)
    resultado_padrao = {
        "ip":       ip,
        "privado":  False,
        "cidade":   "Desconhecido",
        "regiao":   "Desconhecido",
        "pais":     "Desconhecido",
        "org":      "Desconhecido",
        "hostname": "Desconhecido",
    }

    try:
        url = f"https://ipinfo.io/{ip}/json"
        resposta = requests.get(url, timeout=5)

        # Verifica rate limit (429) e outros erros HTTP
        if resposta.status_code == 429:
            print(f"[AVISO] Limite de requisicoes atingido para IP {ip}. Tente mais tarde.")
            cache[ip] = resultado_padrao
            return resultado_padrao

        if resposta.status_code != 200:
            print(f"[AVISO] API retornou status {resposta.status_code} para IP {ip}.")
            cache[ip] = resultado_padrao
            return resultado_padrao

        dados = resposta.json()

        resultado = {
            "ip":       dados.get("ip",       ip),
            "privado":  False,
            "cidade":   dados.get("city",     "Desconhecido"),
            "regiao":   dados.get("region",   "Desconhecido"),
            "pais":     dados.get("country",  "Desconhecido"),
            "org":      dados.get("org",      "Desconhecido"),
            "hostname": dados.get("hostname", "Desconhecido"),
        }

        cache[ip] = resultado
        return resultado

    except requests.exceptions.ConnectionError:
        print(f"[ERRO] Sem conexao de rede ao consultar IP {ip}.")
    except requests.exceptions.Timeout:
        print(f"[ERRO] Timeout ao consultar IP {ip} (limite de 5s atingido).")
    except requests.exceptions.HTTPError as e:
        print(f"[ERRO] Erro HTTP ao consultar IP {ip}: {e}")
    except ValueError:
        # json.JSONDecodeError e subclasse de ValueError
        print(f"[ERRO] Resposta invalida (nao-JSON) ao consultar IP {ip}.")
    except Exception as e:
        print(f"[ERRO] Erro inesperado ao consultar IP {ip}: {e}")

    cache[ip] = resultado_padrao
    return resultado_padrao


def enriquecer_alertas(alertas, cache):
    """
    Adiciona informacoes de geolocalizacao a uma lista de alertas.

    Parametros:
        alertas (list[dict]): lista de alertas (cada um tem campo "ip")
        cache (dict): cache de consultas de IP

    Retorna:
        list[dict]: mesmos alertas com campo adicional "geolocalizacao"
    """
    if not alertas:
        return alertas

    # Coleta IPs unicos para minimizar chamadas a API
    ips_unicos = {alerta["ip"] for alerta in alertas if "ip" in alerta}

    # Consulta cada IP unico uma unica vez (o cache cuida de nao repetir)
    for ip in ips_unicos:
        consultar_ip(ip, cache)

    # Distribui os dados de geolocalizacao para cada alerta
    alertas_enriquecidos = []
    for alerta in alertas:
        alerta_copia = dict(alerta)  # nao modifica o original
        ip = alerta_copia.get("ip", "")
        if ip and ip in cache:
            alerta_copia["geolocalizacao"] = cache[ip]
        else:
            alerta_copia["geolocalizacao"] = {
                "ip":       ip,
                "privado":  False,
                "cidade":   "Desconhecido",
                "regiao":   "Desconhecido",
                "pais":     "Desconhecido",
                "org":      "Desconhecido",
                "hostname": "Desconhecido",
            }
        alertas_enriquecidos.append(alerta_copia)

    return alertas_enriquecidos


def exibir_enriquecimento(dados_ip):
    """
    Exibe as informacoes de um IP de forma formatada no terminal.

    Parametros:
        dados_ip (dict): dicionario retornado por consultar_ip()
    """
    tipo = "PRIVADO (Rede Interna)" if dados_ip.get("privado") else "PUBLICO"

    print("-" * 45)
    print(f"{'IP:':<15} {dados_ip.get('ip', 'N/A')}")
    print(f"{'Tipo:':<15} {tipo}")
    print(f"{'Cidade:':<15} {dados_ip.get('cidade', 'Desconhecido')}")
    print(f"{'Regiao:':<15} {dados_ip.get('regiao', 'Desconhecido')}")
    print(f"{'Pais:':<15} {dados_ip.get('pais', 'Desconhecido')}")
    print(f"{'Organizacao:':<15} {dados_ip.get('org', 'Desconhecido')}")
    print(f"{'Hostname:':<15} {dados_ip.get('hostname', 'Desconhecido')}")
    print("-" * 45)


# ---------------------------------------------------------------------------
# Testes rapidos — executar com: python enriquecimento.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cache_teste = {}

    print("=== Teste 1: IP publico (8.8.8.8 — Google DNS) ===")
    dados = consultar_ip("8.8.8.8", cache_teste)
    exibir_enriquecimento(dados)

    print("\n=== Teste 2: IP privado (192.168.1.10) ===")
    dados = consultar_ip("192.168.1.10", cache_teste)
    exibir_enriquecimento(dados)

    print("\n=== Teste 3: Mesmo IP publico novamente (deve usar cache) ===")
    dados = consultar_ip("8.8.8.8", cache_teste)
    print(f"Retornado do cache: {dados['cidade']}, {dados['pais']}")

    print("\n=== Teste 4: IP invalido (999.999.999.999) ===")
    dados = consultar_ip("999.999.999.999", cache_teste)
    exibir_enriquecimento(dados)

    print("\n=== Teste 5: Enriquecimento de alertas ===")
    alertas_exemplo = [
        {"timestamp": "2025-02-20 08:15:01", "regra": "R001", "severidade": "ALTA",
         "ip": "185.220.101.1", "descricao": "Brute force detectado"},
        {"timestamp": "2025-02-20 08:15:03", "regra": "R001", "severidade": "INFO",
         "ip": "192.168.1.10", "descricao": "Login OK"},
        {"timestamp": "2025-02-20 08:15:05", "regra": "R002", "severidade": "ALTA",
         "ip": "185.220.101.1", "descricao": "Port scan"},  # IP repetido -> cache
    ]
    alertas_enriquecidos = enriquecer_alertas(alertas_exemplo, cache_teste)
    for a in alertas_enriquecidos:
        geo = a["geolocalizacao"]
        print(f"  IP {a['ip']:20} -> {geo['pais']} / {geo['cidade']} / {geo['org']}")

    print(f"\nIPs no cache ao final: {list(cache_teste.keys())}")
