# 🛡️ WebSecOps Dashboard - Plataforma de Inteligência de Segurança

![Project Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow?style=flat-square)
![Stack](https://img.shields.io/badge/Stack-Next.js%20%7C%20FastAPI%20%7C%20Docker-blue?style=flat-square)

O **WebSecOps** é uma plataforma centralizada para auxiliar times de QA e Segurança no monitoramento contínuo de aplicações web. O sistema atua como um "Radar Passivo", identificando tecnologias, correlacionando vulnerabilidades (CVEs) e trazendo inteligência de ameaças em tempo real.

## 🚀 Funcionalidades Principais

*   **📊 Dashboard Executivo**: Visão unificada com indicadores de risco (Score de Vulnerabilidade, Alertas Críticos).
*   **🎯 Gestão de Alvos (Targets)**: Gerenciamento centralizado das URLs monitoradas (Aplicações, APIs).
*   **🕵️‍♂️ Detecção de Tech Stack**: Identificação automática de tecnologias (Servidores, Frameworks, CMS) sem necessidade de acesso privilegiado.
*   **🚨 Monitoramento de CVEs**: Cruzamento automático das tecnologias detectadas com o banco de dados oficial de vulnerabilidades (NVD/NIST).
*   **📰 Inteligência de Ameaças**: Feed integrado de notícias de cibersegurança e alertas globais.
*   **⚡ ZAP Integration (Em Breve)**: Orquestração de scans DAST utilizando OWASP ZAP containerizado.

---

## 🏗️ Arquitetura do Projeto

O projeto utiliza uma arquitetura baseada em **Microserviços Containerizados**:

| Componente | Tecnologia | Função |
| :--- | :--- | :--- |
| **Frontend** | **Next.js 14** (React) | Interface do utilizador (Dashboard, Gráficos), renderização Server/Client. |
| **Backend** | **Python (FastAPI)** | API REST, Orquestração de Scanners, Integração com NVD. |
| **Database** | **PostgreSQL** | Armazenamento de CVEs, Resultados de Scans e Metadados. |
| **Cache/Queue** | **Redis** | Filas de processamento para scanners assíncronos. |
| **Scanner** | **OWASP ZAP** | Engine de varredura ativa de vulnerabilidades web (DAST). |

---

## 🛠️ Como Executar (Ambiente de Desenvolvimento)

### Pré-requisitos
*   **Docker Desktop** (Com suporte a Linux Containers no Windows)
*   **Node.js 20+** (Para rodar o Frontend localmente e poupar recursos)

### Passo 1: Iniciar a Infraestrutura (Backend)
O Backend e os serviços de apoio rodam em containers para garantir isolamento.

```bash
# Na raiz do projeto:
docker compose up -d db backend redis
```

### Passo 2: Iniciar o Frontend (Local)
Para melhor performance de desenvolvimento (Hot-Reload), rodamos o frontend nativamente.

```bash
cd frontend
npm install  # (Apenas na primeira vez)
npm run dev
```

> O painel estará acessível em: **[http://localhost:3000](http://localhost:3000)**

---

## 🚀 Deploy Simples na DigitalOcean

Este projeto pode subir em um único Droplet com Docker. O fluxo mais barato é:

1. Clonar o repositório no droplet.
2. Copiar `.env.example` para `.env` e ajustar a senha do Postgres.
3. Subir com `docker compose -f docker-compose.prod.yml up -d --build`.

Exemplo de variáveis:

```bash
cp .env.example .env
```

Se quiser usar outro endereço público para a API, ajuste `NEXT_PUBLIC_API_URL` antes de fazer o build do frontend.

---

## 📂 Estrutura de Pastas

```
innovation/
├── backend/            # API Python (FastAPI)
│   ├── app/
│   │   ├── api/        # Endpoints (Routes)
│   │   ├── core/       # Configs e DB Connection
│   │   └── models/     # Modelos SQL (SQLAlchemy)
│   └── main.py         # Entrypoint da Aplicação
│
├── frontend/           # Aplicação Next.js
│   ├── app/
│   │   ├── (routes)/   # Páginas (Dashboard, Targets, Vulns)
│   │   └── components/ # Componentes Reutilizáveis (Sidebar, Cards)
│   └── lib/            # Integração com API (Axios)
│
└── docker-compose.yml  # Orquestração dos Containers
```

## 🤝 Contribuição (QA Security)

Este projeto serve como ferramenta de apoio para a definição de **Casos de Teste de Segurança**. 
O fluxo de trabalho sugerido é:
1.  Cadastrar aplicação alvo no Dashboard.
2.  Identificar tecnologias vulneráveis alertas pelo sistema.
3.  Criar testes automatizados específicos no repositório de QA oficial para validar a correção (Patch/Update).

---

**Desenvolvido com foco em Cyber + Privacy 🔒**
