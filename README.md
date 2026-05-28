# SecuraPy SIEM — Trabalho Final

## Como usar este projeto

Este projeto contém a **casca** (esqueleto) do sistema SecuraPy SIEM. Todos os
arquivos `.py` dos módulos já existem com as funções definidas, mas o corpo de
cada função contém apenas `pass` — ou seja, **nada funciona ainda**.

Seu trabalho é **implementar o código** dentro de cada função, seguindo as
docstrings e dicas que já estão escritas nos arquivos.

### Verificando seu progresso com os testes

O projeto inclui **testes automatizados** que validam se sua implementação está
correta. Quando você começar, **todos os testes vão falhar**. Conforme você
implementa as funções, os testes vão passando.

#### Instalando as dependências

```bash
# Na pasta securaPy/
pip install pytest requests
```

#### Rodando todos os testes

```bash
# Na pasta securaPy/
python -m pytest testes/ -v
```

#### Rodando testes de um módulo específico

```bash
# Testar apenas o coletor
python -m pytest testes/test_coletor.py -v

# Testar apenas as regras
python -m pytest testes/test_regras.py -v

# Testar apenas o detector
python -m pytest testes/test_detector.py -v

# Testar apenas o enriquecimento
python -m pytest testes/test_enriquecimento.py -v

# Testar apenas o servidor de alertas
python -m pytest testes/test_servidor.py -v

# Testar apenas os relatórios
python -m pytest testes/test_relatorios.py -v

# Testar apenas a integração (ponta a ponta)
python -m pytest testes/test_integracao.py -v
```

#### Rodando um teste específico

```bash
# Rodar apenas um teste por nome
python -m pytest testes/test_coletor.py::TestParsearLinhaAuth::test_linha_fail_retorna_dict -v
```

#### Vendo quantos testes passam vs falham

```bash
python -m pytest testes/ --tb=no -q
```

Saída esperada no início (tudo falhando):
```
182 failed, 15 passed
```
(os 15 que passam de cara são testes de entrada inválida/vazia — como as funções
ainda não fazem nada, retornar `None` coincide com o comportamento esperado para
entradas inválidas)

Saída esperada quando tudo estiver implementado:
```
197 passed, 0 failed
```

### Ordem recomendada de implementação

Comece pelo módulo que os outros dependem e vá subindo:

1. **`coletor.py`** — base de tudo (rode `test_coletor.py`)
2. **`regras.py`** — precisa do coletor (rode `test_regras.py`)
3. **`detector.py`** — precisa do coletor (rode `test_detector.py`)
4. **`enriquecimento.py`** — independente (rode `test_enriquecimento.py`)
5. **`relatorios.py`** — precisa de todos (rode `test_relatorios.py`)
6. **`servidor_alertas.py` + `cliente_alertas.py`** — independente (rode `test_servidor.py`)
7. **`main.py`** — integra tudo (rode `test_integracao.py`)

### Estrutura do projeto

```
securaPy/
├── main.py                  # Ponto de entrada — menu principal
├── coletor.py               # Módulo 1 — Leitura e parsing de logs
├── regras.py                # Módulo 2 — Motor de regras de detecção
├── detector.py              # Módulo 3 — Detecção de anomalias
├── servidor_alertas.py      # Módulo 4a — Servidor TCP de alertas
├── cliente_alertas.py       # Módulo 4b — Cliente TCP de alertas
├── enriquecimento.py        # Módulo 5 — Consulta API de geolocalização
├── relatorios.py            # Módulo 6 — Dashboard CLI e relatórios
├── logs/                    # Arquivos de log para teste
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── config/
│   └── regras.json          # Configuração das regras de detecção
├── saida/                   # Relatórios gerados (pasta de saída)
├── testes/                  # Testes automatizados
│   ├── conftest.py          # Fixtures compartilhadas
│   ├── test_coletor.py      # Testes do módulo 1
│   ├── test_regras.py       # Testes do módulo 2
│   ├── test_detector.py     # Testes do módulo 3
│   ├── test_servidor.py     # Testes do módulo 4
│   ├── test_enriquecimento.py  # Testes do módulo 5
│   ├── test_relatorios.py   # Testes do módulo 6
│   └── test_integracao.py   # Testes ponta a ponta
└── README.md                # Este arquivo
```

### Mapa de testes por módulo

| Módulo | Arquivo de teste | Testes | O que valida |
|--------|-----------------|--------|-------------|
| coletor.py | test_coletor.py | 47 | Parsing dos 3 formatos de log, normalização, erros de arquivo |
| regras.py | test_regras.py | 37 | Carregamento JSON, classificação severidade, avaliação de cada regra |
| detector.py | test_detector.py | 38 | Brute force, port scan, blacklist, resumo consolidado |
| enriquecimento.py | test_enriquecimento.py | 26 | IP privado/público, cache, mock de API, tratamento de erros |
| servidor_alertas.py | test_servidor.py | 7 | Formatação de alertas, conexão TCP, broadcast |
| relatorios.py | test_relatorios.py | 30 | Filtros, top IPs, exportação JSON, menu |
| integração | test_integracao.py | 12 | Fluxo completo ponta a ponta |
| | | **197** | **Total** |

---

# SecuraPy SIEM — Room 4

## Integrantes

| Nome | RM | Responsabilidade |
|------|-----|-----------------|
| Matheus Silva Souza | RM:572335 | Módulos 1 e 6 |
| Enzo Parada Seixas | RM:572294 | Módulo 2 |
| João Pedro Silva Ribeiro | RM:570090 | Módulos 3 e 6 |
| Guilherme Benjamim dos Reis | RM:573724 | Módulo 4 |
| Gabriel Cirone Galter | RM:568717 | Módulo 5 |

## Descrição

O SecuraPy é um SIEM simplificado, desenvolvido para coletar, analisar e correlacionar eventos de segurança de múltiplas fontes em tempo real. O sistema resolve um problema comum em ambientes corporativos: a análise manual de logs, que é lenta, propensa a erros e incapaz de detectar ataques em andamento. Com o SecuraPy, esse processo passa a ser automatizado, permitindo que a equipe de segurança identifique ameaças de forma rápida e estruturada.

O sistema é composto por seis módulos integrados. O Módulo 1 lê e normaliza os arquivos de log de diferentes fontes — autenticação, firewall e acesso web. O Módulo 2 aplica regras de detecção configuráveis sobre esses eventos, gerando alertas quando algo suspeito é identificado. O Módulo 3 vai além e analisa padrões no conjunto de eventos, detectando comportamentos como tentativas de brute force e varredura de portas. O Módulo 4 transmite esses alertas em tempo real via rede para os analistas conectados. O Módulo 5 enriquece os IPs suspeitos com informações geográficas e organizacionais consultando uma API externa. E o Módulo 6 reúne tudo em um dashboard interativo no terminal, permitindo filtros, buscas e exportação de relatórios.

A integração entre os módulos segue um fluxo linear e bem definido: os eventos coletados pelo Módulo 1 alimentam os módulos de detecção, que geram alertas enriquecidos pelo Módulo 5 e exibidos pelo Módulo 6. Cada módulo tem uma responsabilidade única e se comunica com os demais através de estruturas de dados padronizadas, o que torna o sistema modular, fácil de manter e preparado para evoluir.

## Como executar

```bash
# 1. Instalar dependências
pip install requests

# 2. Rodar o sistema
cd securaPy
python main.py

# 3. Rodar os testes
python -m pytest testes/ -v
```

## Resultado dos testes

<img width="1920" height="1048" alt="Screenshot From 2026-05-28 18-07-05" src="https://github.com/user-attachments/assets/e1c368b8-bce6-444f-9718-866d56706c2e" />

## Divisão de tarefas

### Nome — Pessoa A
- **Módulos:** lista
- **O que fez:** descreva em 2-3 frases
- **Dificuldades:** o que foi mais difícil e como resolveu

### Nome — Enzo Parada Seixas
- **Módulos:** Módulo: 2 e edição do vídeo
- **O que fez:** Desenvolvi o módulo de detecção de ameaças e regras configuráveis em JSON.
- **Dificuldades:** Estruturar a lógica de detecção das regras de forma flexível, permitindo que o sistema analisasse diferentes tipos de eventos sem precisar alterar o código principal.

### Nome — Pessoa C
- **Módulos:** lista
- **O que fez:** descreva em 2-3 frases
- **Dificuldades:** o que foi mais difícil e como resolveu

### Nome — Pessoa D
- **Módulos:** lista
- **O que fez:** descreva em 2-3 frases
- **Dificuldades:** o que foi mais difícil e como resolveu

### Nome — Gabriel Cirone Galter
- **Módulos:** Módulo 5 e execução de arquivos
- **O que fez:** Desenvolvi o módulo que adiciona contexto geográfico e organizacional aos IPs suspeitos, consultando a API do ipinfo.io. Implementou cache para evitar consultas repetidas e tratamento de erros de rede.
- **Dificuldades:** O Linux bloqueou a instalação das dependências com o pip por ser um ambiente gerenciado externamente. A solução foi criar um ambiente virtual com python3 -m venv.



## Observações

Para executar cada comando no meu sistema Ubuntu, eu precisei criar um ambiente virtual no VS Code para rodar os arquivos no terminal, com os seguintes comandos:

## Criar um ambiente virtual. No terminal do VS Code:

```bash
python3 -m venv venv
```

## Ativar o ambiente:

```bash
source venv/bin/activate
```

Toda vez que abrir um novo terminal, precisará ativar o venv de novo com source venv/bin/activate. Você verá (venv) no início da linha quando estiver ativo.

## Demonstração em vídeo

[Link do vídeo enviado pelo Teams]
