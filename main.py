# ==============================================================================
# IMPORTE DE BIBLIOTECAS (Pilha de Tecnologia)
# ==============================================================================
from fastapi import FastAPI      # Framework web para gerenciar rotas e requisições HTTP
from pydantic import BaseModel   # Ferramenta para validação de dados e tipagem estrita
import socket                    # Biblioteca nativa para conexões de rede (Sockets de Baixo Nível)
import threading                 # Biblioteca nativa para criação e controle de Threads (Paralelismo)

# Inicializa a aplicação FastAPI e define o título que aparecerá na documentação automática
app = FastAPI(title="API de Ferramentas de Segurança")

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
# O Semáforo garante que no máximo 50 threads rodem simultaneamente, evitando travar o PC
semaphore = threading.Semaphore(50)

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
    # Reserva uma vaga das 50 disponíveis no semáforo. Se estiver cheio, aguarda.
    with semaphore:
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
@app.post("/scan/ports")
def executar_port_scan(dados: Target):
    """
    Rota principal da API. Recebe o JSON de entrada configurado no modelo 'Target',
    gerencia a criação de múltiplas threads e entrega o relatório final formatado.
    """
    portas_abertas = []  # Lista vazia que será compartilhada e preenchida pelas threads
    threads = []         # Lista auxiliar para podermos gerenciar e monitorar todas as threads
    
    # Laço de repetição que vai da porta inicial (dados.p0) até a porta final (dados.p1)
    # O '+ 1' garante que a última porta escolhida também entre no loop
    for porta in range(dados.p0, dados.p1 + 1):
        # Configura uma thread apontando para a nossa função trabalhadora
        # Passa o alvo enviado pelo usuário, a porta atual do loop e a lista de armazenamento
        t = threading.Thread(
            target=scan_porta, 
            args=(dados.alvo, porta, portas_abertas)
        )
        threads.append(t)  # Guarda a thread na lista de controle
        t.start()          # Dispara a thread imediatamente em segundo plano
        
    # Força a API a travar temporariamente nesta linha até que a última thread finalize
    # Isso garante que a resposta HTTP só seja enviada quando todo o scan acabar
    for t in threads:
        t.join()
        
    # Retorna o dicionário final para o usuário. 
    # O FastAPI pega automaticamente esse dicionário e o converte para o formato padrão JSON.
    return {
        "alvo": dados.alvo,
        "total_portas_abertas": len(portas_abertas),
        "portas_encontradas": portas_abertas
    }