"""
Modulo 3 - Detector de Anomalias
Analisa o conjunto de eventos para identificar padroes de ataque
que so ficam visiveis quando multiplos eventos sao correlacionados.
"""

def _classificar_por_quantidade(valor):
    if valor > 20:
        return "CRITICA"
    elif valor > 10:
        return "ALTA"
    elif valor > 5:
        return "MEDIA"
    return "BAIXA"


def detectar_brute_force(eventos, threshold=5):
    """
    Identifica IPs com muitas tentativas de login falhas.
    """
    contagem = {}
    usuarios = {}

    for evento in eventos or []:
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL":
            continue

        ip = evento.get("ip")
        if not ip:
            continue

        contagem[ip] = contagem.get(ip, 0) + 1
        usuarios.setdefault(ip, set())

        for parte in str(evento.get("detalhes", "")).split():
            if parte.startswith("usuario="):
                usuarios[ip].add(parte.split("=", 1)[1])

    resultado = {}
    for ip, tentativas in contagem.items():
        if tentativas >= threshold:
            resultado[ip] = {
                "tentativas": tentativas,
                "usuarios": sorted(usuarios.get(ip, set())),
                "severidade": _classificar_por_quantidade(tentativas),
            }

    return resultado


def detectar_port_scan(eventos, threshold=3):
    """
    Identifica IPs que tentaram acessar muitas portas distintas.
    """
    portas_por_ip = {}

    for evento in eventos or []:
        if evento.get("fonte") != "firewall" or evento.get("tipo") != "BLOCK":
            continue

        ip = evento.get("ip")
        if not ip:
            continue

        dport = None
        for parte in str(evento.get("detalhes", "")).split():
            if parte.startswith("dport="):
                dport = parte.split("=", 1)[1]
                break
        if not dport:
            continue

        portas_por_ip.setdefault(ip, set()).add(str(dport))

    resultado = {}
    for ip, portas in portas_por_ip.items():
        quantidade = len(portas)
        if quantidade >= threshold:
            resultado[ip] = {
                "portas": portas,
                "quantidade": quantidade,
                "severidade": "CRITICA" if quantidade > 10 else "ALTA" if quantidade > 5 else "MEDIA",
            }

    return resultado


def verificar_blacklist(eventos, blacklist):
    """
    Cruza os IPs encontrados nos eventos com uma blacklist conhecida.
    """
    ips_eventos = {evento.get("ip") for evento in (eventos or []) if evento.get("ip")}
    blacklist = set(blacklist or [])
    ips_encontrados = ips_eventos & blacklist

    contagem_por_ip = {ip: 0 for ip in ips_encontrados}
    for evento in eventos or []:
        ip = evento.get("ip")
        if ip in ips_encontrados:
            contagem_por_ip[ip] += 1

    return ips_encontrados, contagem_por_ip


def _classificar_pontuacao(pontuacao):
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    return "INFO"


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """
    Consolida todas as deteccoes em um resumo unificado de ameacas.
    """
    blacklist_ips, blacklist_contagem = blacklist_resultado if blacklist_resultado else (set(), {})
    brute_force = brute_force or {}
    port_scan = port_scan or {}

    todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | set(blacklist_ips)
    resumo = []

    for ip in todos_ips:
        deteccoes = []
        pontuacao = 0
        detalhes = {}

        if ip in brute_force:
            deteccoes.append("brute_force")
            pontuacao += brute_force[ip]["tentativas"]

        if ip in port_scan:
            deteccoes.append("port_scan")
            pontuacao += port_scan[ip]["quantidade"]

        if ip in blacklist_ips:
            deteccoes.append("blacklist")
            pontuacao += blacklist_contagem.get(ip, 0)

        resumo.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": _classificar_pontuacao(pontuacao),
            "detalhes": detalhes,
        })

    resumo.sort(key=lambda item: (item["pontuacao"], item["ip"]), reverse=True)
    return resumo
