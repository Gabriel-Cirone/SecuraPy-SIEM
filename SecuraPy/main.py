"""
SecuraPy SIEM - Ponto de Entrada Principal
Integra todos os modulos: coletor, regras, detector, enriquecimento,
servidor de alertas e relatorios em um menu interativo.
"""

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas
from relatorios import exibir_menu, resumo_geral, filtrar_eventos, buscar_ip, top_ips, exportar_relatorio_json
from enriquecimento import enriquecer_alertas
from servidor_alertas import iniciar_servidor

PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def main():
    eventos = []
    alertas = []
    resumo = []
    cache_enriquecimento = {}

    print("=" * 50)
    print("       SecuraPy SIEM - Coding for Security")
    print("=" * 50)

    while True:
        opcao = exibir_menu()

        if opcao == 1:
            eventos = carregar_todos_os_logs(PASTA_LOGS)
            regras = carregar_regras(ARQUIVO_REGRAS)
            alertas = aplicar_regras(eventos, regras)
            brute = detectar_brute_force(eventos)
            scan = detectar_port_scan(eventos)
            bl = verificar_blacklist(eventos, BLACKLIST)
            resumo = gerar_resumo_ameacas(brute, scan, bl)
            print("Processamento concluido.")

        elif opcao == 2:
            if not eventos:
                print("Carregue os logs primeiro (opcao 1)")
            else:
                resumo_geral(eventos, alertas)

        elif opcao == 3:
            if not eventos:
                print("Carregue os logs primeiro (opcao 1)")
            else:
                fonte = input("Fonte (auth/firewall/web ou vazio): ").strip() or None
                tipo = input("Tipo ou vazio: ").strip() or None
                ip = input("IP ou vazio: ").strip() or None
                resultado = filtrar_eventos(eventos, fonte=fonte, tipo=tipo, ip=ip)
                print(f"Eventos encontrados: {len(resultado)}")

        elif opcao == 4:
            if not eventos:
                print("Carregue os logs primeiro (opcao 1)")
            else:
                ip = input("Digite o IP: ").strip()
                buscar_ip(ip, eventos, alertas, cache_enriquecimento)

        elif opcao == 5:
            if not eventos:
                print("Carregue os logs primeiro (opcao 1)")
            else:
                print(top_ips(eventos))

        elif opcao == 6:
            if not eventos:
                print("Carregue os logs primeiro (opcao 1)")
            else:
                severidade = input("Severidade (CRITICA/ALTA/MEDIA/BAIXA/INFO): ").strip().upper()
                filtrados = [a for a in alertas if a.get("severidade") == severidade]
                print(f"Alertas encontrados: {len(filtrados)}")

        elif opcao == 7:
            if not alertas:
                print("Carregue os logs primeiro (opcao 1)")
            else:
                alertas = enriquecer_alertas(alertas, cache_enriquecimento)
                print("Alertas enriquecidos.")

        elif opcao == 8:
            if not eventos:
                print("Carregue os logs primeiro (opcao 1)")
            else:
                dados = {
                    "eventos": eventos,
                    "alertas": alertas,
                    "resumo": resumo,
                }
                exportar_relatorio_json(dados, "saida/relatorio.json")

        elif opcao == 9:
            iniciar_servidor()

        elif opcao == 0:
            print("Encerrando SecuraPy.")
            break

        else:
            print("Opcao invalida. Tente novamente.")


if __name__ == "__main__":
    main()
