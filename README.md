# Api Security Tools 🔍🛡️

Uma API REST assíncrona de alta performance desenvolvida em Python com FastAPI, projetada para automação de tarefas de infraestrutura, auditoria de redes e varredura de segurança (*Port Scanning*).

Este projeto demonstra a aplicação prática de conceitos avançados de engenharia de software, redes e programação concorrente utilizando o ecossistema moderno do Python.

---

### 🚀 Recursos e Funcionalidades

- **Varredura Assíncrona de Portas (Port Scanner):** Auditoria rápida de portas abertas em hosts alvos utilizando conexões via sockets TCP de forma concorrente.
- **Gerenciamento Avançado de Concorrência:** Controle preciso do fluxo de threads utilizando `threading.Semaphore` para evitar sobrecarga de rede e `threading.Lock` para garantir a integridade da memória ao manipular os estados globais da varredura.
- **Validação de Dados Estrita:** Uso do Pydantic para tipagem, higienização e validação dos dados de entrada (como faixas de IPs e intervalos de portas).
- **Documentação Automatizada:** Interface interativa pronta para testes via Swagger UI (/docs).

---

### 🛠️ Tecnologias Utilizadas

- **Core:** Python 3
- **Framework Web:** FastAPI / Uvicorn
- **Validação:** Pydantic
- **Módulos Nativos:** `socket`, `threading`, `asyncio`

---

### 🔧 Instalação e Execução

1. Clone o repositório:
```bash
git clone [https://github.com/MarcosStark/api-security-tools.git](https://github.com/MarcosStark/api-security-tools.git)
