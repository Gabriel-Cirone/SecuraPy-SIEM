"""
Modulo 4b - Cliente de Alertas
Conecta ao servidor de alertas e recebe notificacoes em tempo real.
Permite enviar comandos: /status, /historico, /sair
"""

import socket
import threading

# ── recepção de alertas ───────────────────────────────────────

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    """
    Thread que fica ouvindo mensagens do servidor e exibindo no terminal.
    """
    try:
        while True:
            try:
                dados = cliente.recv(4096).decode(errors="ignore")
                if not dados:
                    print("Servidor desconectado.")
                    break
                print(dados, end="" if dados.endswith("\n") else "\n")
            except (ConnectionResetError, OSError):
                print("Conexao com o servidor foi encerrada.")
                break
    finally:
        try:
            cliente.close()
        except OSError:
            pass


def conectar_servidor(host=HOST, porta=PORTA):
    """
    Conecta ao servidor de alertas e inicia a interacao.
    """
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, porta))
    except ConnectionRefusedError:
        print(f"Servidor indisponivel em {host}:{porta}")
        try:
            cliente.close()
        except OSError:
            pass
        return
    except OSError as e:
        print(f"Erro ao conectar: {e}")
        try:
            cliente.close()
        except OSError:
            pass
        return

    thread = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
    thread.start()

    try:
        while True:
            try:
                comando = input().strip()
            except EOFError:
                comando = "/sair"

            if not comando:
                continue

            try:
                cliente.send((comando + "\n").encode())
            except OSError:
                break

            if comando == "/sair":
                break
    except KeyboardInterrupt:
        try:
            cliente.send(("/sair\n").encode())
        except OSError:
            pass
    finally:
        try:
            cliente.close()
        except OSError:
            pass


if __name__ == "__main__":
    conectar_servidor()
