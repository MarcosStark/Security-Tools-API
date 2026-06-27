# ==============================================================================
# IMPORTE DE BIBLIOTECAS (Pilha de Tecnologia)
# ==============================================================================
from fastapi import FastAPI      # Framework web para gerenciar rotas e requisições HTTP
from pydantic import BaseModel   # Ferramenta para validação de dados e tipagem estrita
import socket                    # Biblioteca nativa para conexões de rede (Sockets de Baixo Nível)
import threading                 # Biblioteca nativa para travas de memória (Thread Safety)
import concurrent.futures        # Biblioteca nativa para gerenciamento de pooling de threads
from fastapi.middleware.cors import CORSMiddleware

# Inicializa a aplicação FastAPI e define o título que aparecerá na documentação automática
app = FastAPI(
    title="API de Ferramentas de Segurança | Por: Marcos Augusto",
    description=(
        "**Desenvolvido por:** Marcos Augusto Rodrigues de Menezes<br>"
        "**Versão:** 2.0.0 (Upgrade de Alta Performance com Thread Pool)<br><br>"
        "Interface de alta performance para auditoria de infraestrutura e análise de vulnerabilidades em redes."
    ),
    version="2.0.0",
    contact={
        "name": "Marcos Augusto Rodrigues de Menezes",
        "url": "https://github.com/MarcosStark",
    },
    license_info={
        "name": "Licença MIT",
        "url": "https://opensource.org/licenses/MIT",
    }
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],            # Permite pedidos de qualquer origem (ficheiros locais)
    allow_credentials=True,
    allow_methods=["*"],            # Permite todos os métodos, incluindo OPTIONS e POST
    allow_headers=["*"],            # Permite todos os cabeçalhos das requisições
)

# ==============================================================================
# MODELO DE ENTRADA DE DADOS (CONTRATO DA API VIA PYDANTIC)
# ==============================================================================
class Target(BaseModel):
    alvo: str  # IP ou Domínio (ex: "192.168.0.1" ou "scanme.nmap.org")
    p0: int    # Porta Inicial do intervalo de escaneamento (ex: 20)
    p1: int    # Porta Final do intervalo de escaneamento (ex: 100)

# ==============================================================================
# CONFIGURAÇÃO DE CONCORRÊNCIA E CONTROLE DE MEMÓRIA
# ==============================================================================
# O Lock funciona como um "cadeado" para que as threads não corrompam a lista ao salvar dados juntas
lista_lock = threading.Lock()

# ==============================================================================
# FUNÇÃO TRABALHADORA (WORKER) - EXECUTA O SCAN EM UMA PORTA ESPECÍFICA
# ==============================================================================
def scan_porta(alvo: str, porta: int, lista_resultados: list):
    """
    Função executada por cada Thread individual. 
    Testa se uma porta específica está aberta e captura o banner do serviço.
    """
    # Cria um socket IPv4 (AF_INET) utilizando o protocolo TCP (SOCK_STREAM)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define 1.0 segundo como tempo limite de espera. Se a porta não responder, desiste.
    s.settimeout(1.0)

    # Tenta a conexão. O connect_ex não quebra o código se falhar; retorna 0 apenas se der certo.
    resultado = s.connect_ex((alvo, porta))

    # Se o resultado for igual a 0, significa que a porta está aberta e respondendo!
    if resultado == 0:
        try:
            # Envia uma saudação genérica em formato de bytes para forçar o serviço a responder
            s.sendall(b"Hello\r\n")

            # Captura até 1024 bytes da resposta do servidor (Banner Grabbing)
            # decode(errors="ignore") evita que o script quebre caso venham caracteres estranhos
            # strip() remove espaços vazios ou quebras de linha inúteis do início e fim do texto
            banner = s.recv(1024).decode(errors="ignore").strip()
        except:
            # Se a porta estiver aberta mas o serviço se recusar a responder, define como Desconhecido
            banner = "Desconhecido"

        # Estrutura os dados encontrados desta porta específica em um dicionário organizado
        dados_porta = {
            "porta": porta,
            "status": "Aberta",
            "servico": banner if banner else "Sem banner disponível"
        }

        # Tranca o cadeado (Lock) para garantir acesso exclusivo à lista global
        with lista_lock:
            # Adiciona o resultado com segurança dentro da lista de portas encontradas
            lista_resultados.append(dados_porta)

    # Fecha a conexão do socket para liberar o descritor e a memória do sistema operacional
    s.close()

# ==============================================================================
# ENDPOINT DA API (A ROTA QUE O CLIENTE CHAMA VIA HTTP POST)
# ==============================================================================
@app.post("/scan/ports", tags=["Auditoria de Infraestrutura"])
def executar_port_scan(dados: Target):
    """
    Rota principal da API v2.0. Recebe o JSON de entrada, distribui a carga de portas
    em uma esteira de execução fixa de 50 threads e retorna o relatório final.
    """
    portas_abertas = []  # Lista que será preenchida com segurança pelas threads da esteira

    # Cria uma lista simples com os números de todas as portas que precisam ser testadas (A Fila de Clientes)
    intervalo_portas = range(dados.p0, dados.p1 + 1)

    # Inicializa o pool com um limite fixo de 50 threads simultâneas.
    # O bloco 'with' gerencia o ciclo de vida e garante que a rota aguarde a conclusão de todas as tarefas.
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # O método 'submit' envia cada tarefa (porta) individualmente para a esteira rápida.
        [executor.submit(scan_porta, dados.alvo, porta, portas_abertas) for porta in intervalo_portas]

    # Quando o bloco 'with' termina, significa que TODAS as portas da fila foram processadas!
    # Ordenamos os resultados pelo número da porta para entregar um relatório limpo
    portas_ordenadas = sorted(portas_abertas, key=lambda x: x["porta"])

    # Retorna o dicionário final para o usuário convertido em JSON automaticamente
    return {
        "copyright": "© 2026 Marcos Augusto Rodrigues de Menezes. Todos os direitos reservados.",
        "licenca": "MIT - Permitido uso acadêmico/profissional mantendo atribuição (créditos)",
        "alvo": dados.alvo,
        "total_portas_abertas": len(portas_ordenadas),
        "portas_encontradas": portas_ordenadas
    }