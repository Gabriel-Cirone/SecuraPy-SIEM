"""
Modulo 4a - Servidor de Alertas em Tempo Real
Servidor TCP que aceita conexoes de multiplos clientes.
"""

import socket
import threading
from datetime import datetime

HOST = "0.0.0.0"
PORTA = 9999
MAX_CLIENTES = 10

clientes = {}
lock = threading.Lock()
historico_alertas = []


def formatar_alerta(alerta_dict):
    """
    Converte um dicionario de alerta em string formatada para exibicao.
    """
    if isinstance(alerta_dict, str):
        return alerta_dict

    timestamp = str(alerta_dict.get("timestamp", "")).strip()
    hora = timestamp.split()[-1] if timestamp else datetime.now().strftime("%H:%M:%S")
    severidade = alerta_dict.get("severidade", "INFO")
    regra_nome = alerta_dict.get("regra_nome", "Alerta")
    ip = alerta_dict.get("ip", "Desconhecido")
    descricao = alerta_dict.get("descricao", "")
    return f"[{hora}] [{severidade}] {regra_nome} - {ip} - {descricao}"


def broadcast_alerta(alerta):
    """
    Envia um alerta para todos os clientes conectados.
    """
    mensagem = formatar_alerta(alerta)
    if isinstance(alerta, dict):
        historico_alertas.append(mensagem)
    else:
        historico_alertas.append(str(mensagem))

    with lock:
        lista_clientes = list(clientes.keys())

    desconectados = []
    for conexao in lista_clientes:
        try:
            conexao.send((mensagem + "\n").encode())
        except OSError:
            desconectados.append(conexao)

    for conexao in desconectados:
        remover_cliente(conexao)


def remover_cliente(conexao):
    """
    Remove um cliente da lista de conectados.
    """
    with lock:
        endereco = clientes.pop(conexao, None)
    try:
        conexao.close()
    except OSError:
        pass
    if endereco:
        print(f"Cliente removido: {endereco[0]}:{endereco[1]}")


def tratar_cliente(conexao, endereco):
    """
    Gerencia a comunicacao com um cliente individual.
    """
    with lock:
        if len(clientes) >= MAX_CLIENTES:
            try:
                conexao.send("Servidor cheio. Tente novamente mais tarde.\n".encode())
            except OSError:
                pass
            remover_cliente(conexao)
            return
        clientes[conexao] = endereco

    try:
        conexao.send("Bem-vindo ao SecuraPy Alertas!\n".encode())

        while True:
            dados = conexao.recv(1024).decode(errors="ignore")
            if not dados:
                break

            comando = dados.strip()

            if comando == "/status":
                with lock:
                    qtd_clientes = len(clientes)
                resposta = (
                    f"Clientes conectados: {qtd_clientes}\n"
                    f"Alertas na sessao: {len(historico_alertas)}\n"
                )
                conexao.send(resposta.encode())

            elif comando == "/historico":
                ultimos = historico_alertas[-10:]
                if not ultimos:
                    conexao.send("Sem alertas no historico.\n".encode())
                else:
                    conexao.send(("\n".join(ultimos) + "\n").encode())

            elif comando == "/sair":
                try:
                    conexao.send("Desconectando...\n".encode())
                except OSError:
                    pass
                break

            else:
                conexao.send("Comando invalido. Use /status, /historico ou /sair.\n".encode())

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        remover_cliente(conexao)


def iniciar_servidor(host=HOST, porta=PORTA):
    """
    Inicia o servidor TCP de alertas.
    """
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen(MAX_CLIENTES)

    print(f"Servidor de alertas iniciado em {host}:{porta}")

    try:
        while True:
            conexao, endereco = servidor.accept()
            thread = threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\nEncerrando servidor de alertas...")
    finally:
        try:
            servidor.close()
        except OSError:
            pass


if __name__ == "__main__":
    iniciar_servidor()
