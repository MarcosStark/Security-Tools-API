# Security Tools API 🔍🛡️

Uma API REST multithreading de alta performance desenvolvida em Python com FastAPI, projetada para automação de tarefas de infraestrutura, auditoria de redes e varredura de segurança (Port Scanning).

Este projeto demonstra a aplicação prática de conceitos avançados de engenharia de software, redes e programação concorrente utilizando o ecossistema moderno do Python.

---

### 🚀 Recursos e Funcionalidades

- **Varredura Concorrente de Portas (Port Scanner):** Auditoria rápida de portas abertas em hosts alvos utilizando conexões via sockets TCP de forma paralela.
- **Gerenciamento Avançado de Concorrência (Thread Pool):** Controle preciso do fluxo de execução utilizando `concurrent.futures.ThreadPoolExecutor` para criar uma esteira fixa de alta performance, minimizando a alocação de recursos em memória, e `threading.Lock` para garantir a integridade da escrita na seção crítica (Thread Safety).
- **Validação de Dados Estrita:** Uso do Pydantic para tipagem, higienização e validação dos dados de entrada (como faixas de IPs e intervalos de portas).
- **Documentação Automatizada:** Interface interativa pronta para testes e consumo via Swagger UI (/docs).

---

### 🛠️ Tecnologias Utilizadas

- **Core:** Python 3
- **Framework Web:** FastAPI / Uvicorn
- **Validação:** Pydantic
- **Módulos Nativos:** `socket`, `threading`, `concurrent.futures`

---

### 🔧 Instalação e Execução

1. Clone o repositório:
```bash
git clone [https://github.com/MarcosStark/api-security-tools.git](https://github.com/MarcosStark/api-security-tools.git)
```
2. Instale as dependências necessárias:
```bash
pip install fastapi uvicorn pydantic
```
3. Inicie o servidor de desenvolvimento:
```bash
uvicorn main:app --reload
```

Acesse a documentação interativa do Swagger no seu navegador para testar as requisições: http://127.0.0.1:8000/docs


📄 Licença
Este projeto está licenciado sob a Licença MIT - consulte o arquivo LICENSE para obter mais detalhes.

⚠️ Aviso de Isenção de Responsabilidade (Disclaimer)
Este projeto foi desenvolvido exclusivamente para fins educacionais, acadêmicos e de demonstração de competências em engenharia de software, concorrência e redes.

O uso desta ferramenta para realizar varreduras (scanning) ou testes em sistemas, redes ou IPs sem a autorização prévia, expressa e por escrito do proprietário é de total responsabilidade do usuário final. O desenvolvedor não incentiva, não apoia e não se responsabiliza por quaisquer danos, infrações legais ou uso indevido deste código por terceiros.