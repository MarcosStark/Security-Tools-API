/* ==========================================================================
   LÓGICA DE INTEGRAÇÃO FULL-STACK (FRONT-END -> API REST COOPERATIVA)
   PROJETO: SECURITY TOOLS PORT SCANNER
   ========================================================================== */

// Configuração do endpoint alvo para consumo da API REST via Uvicorn
const API_URL = "http://127.0.0.1:8000/scan/ports";

// Mapeamento e cacheamento estático de elementos do DOM para manipulação de estado
const scanForm = document.getElementById("scanForm");
const btnScan = document.getElementById("btnScan");
const resultsSection = document.getElementById("resultsSection");
const statusLoading = document.getElementById("statusLoading");
const resultsTableBody = document.getElementById("resultsTableBody");

// Registro do manipulador de eventos (Event Listener) para submissão do formulário
scanForm.addEventListener("submit", async (event) => {
    // Interceptação do comportamento padrão do agente de usuário para evitar recarregamento
    event.preventDefault();

    // Captura e sanitização elementar dos dados de entrada fornecidos pela interface
    const target = document.getElementById("target").value.trim();
    const portaInicio = parseInt(document.getElementById("porta_inicio").value);
    const portaFim = parseInt(document.getElementById("porta_fim").value);

    // Redefinição de estado do fluxo de UI para inicialização do ciclo de varredura
    resultsTableBody.innerHTML = ""; 
    resultsSection.classList.remove("hidden");
    statusLoading.classList.remove("hidden");
    
    // Bloqueio preventivo do gatilho para evitar condições de corrida em chamadas concorrentes
    btnScan.disabled = true;
    btnScan.innerText = "Escaneando...";

    // Estruturação do objeto de carga (Payload) conforme o contrato estrito do modelo Pydantic
    const payload = {
        alvo: target,
        p0: portaInicio,
        p1: portaFim
    };

    try {
        // Inicialização do canal assíncrono de comunicação via Fetch API com cabeçalho de tipo de conteúdo
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        // Verificação do código de status HTTP da resposta
        if (!response.ok) {
            throw new Error(`Erro na API: Código HTTP ${response.status}`);
        }

        // Desserialização do payload de resposta JSON para objeto nativo JavaScript
        const data = await response.json();

        // Ocultação do indicador visual de processamento em segundo plano
        statusLoading.classList.add("hidden");

        // Avaliação de correspondência e renderização condicional do conjunto de dados
        if (data.portas_encontradas && data.portas_encontradas.length > 0) {
            
            // Iteração estrutural sobre a coleção de portas abertas retornadas pelo backend
            data.portas_encontradas.forEach(item => {
                const row = document.createElement("tr");
                
                // Injeção dinâmica de nós de dados contendo o status e os metadados do serviço (banners)
                row.innerHTML = `
                    <td>${item.porta}</td>
                    <td><span style="color: #2ea44f; font-weight: bold;">${item.status}</span></td>
                    <td>${item.servico || "Sem banner disponível"}</td>
                `;
                
                resultsTableBody.appendChild(row);
            });
        } else {
            // Tratamento visual para o cenário de vetor de resultados nulo ou vazio
            resultsTableBody.innerHTML = `
                <tr>
                    <td colspan="3" style="text-align: center; color: #8b949e; font-style: italic;">
                        Nenhuma porta aberta encontrada no intervalo selecionado.
                    </td>
                </tr>
            `;
        }

    } catch (error) {
        // Log de exceções em console e tratamento de falhas críticas de infraestrutura ou rede
        console.error("Falha na varredura:", error);
        statusLoading.classList.add("hidden");
        resultsTableBody.innerHTML = `
            <tr>
                <td colspan="3" style="text-align: center; color: #f85149; font-weight: bold;">
                    ⚠️ Falha de comunicação com a API. Certifique-se de que o backend FastAPI está rodando.
                </td>
            </tr>
        `;
    } finally {
        // Restauração das propriedades e interatividades originais dos elementos de controle da UI
        btnScan.disabled = false;
        btnScan.innerText = "Iniciar Varredura";
    }
});