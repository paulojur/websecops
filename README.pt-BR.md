# 🛡️ WebSecOps – Plataforma de Inteligência de Segurança para Aplicações Web

🌐 [English](README.md) | **Português (BR)**

![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow?style=flat-square)
![Stack](https://img.shields.io/badge/Stack-Next.js%20%7C%20FastAPI%20%7C%20Docker-blue?style=flat-square)

O **WebSecOps** é uma plataforma self-hosted de monitoramento contínuo de segurança de aplicações web (AppSec) e testes DAST (*Dynamic Application Security Testing*). Ajuda times de QA e Segurança a entender o que suas aplicações rodam, quais vulnerabilidades conhecidas se aplicam e o que corrigir primeiro.

Também foi construído como um **showcase interativo de portfólio**: visitantes públicos acessam um **Demo Mode** isolado, enquanto os motores de scan reais ficam protegidos no **Live Mode**, que exige autenticação.

---

## 🚀 Funcionalidades

| Funcionalidade | Descrição |
| :--- | :--- |
| 📊 **Dashboard Executivo** | Visão unificada de risco: score, alertas críticos e tendências. |
| 🎯 **Gestão de Alvos** | Cadastro e acompanhamento das URLs monitoradas. |
| 🕵️ **Detecção Passiva de Tech Stack** | Identifica servidores, frameworks e CMSs via headers HTTP, cookies e HTML, sem enviar exploits. |
| 🚨 **Correlação de CVEs** | Cruza as tecnologias detectadas com a base NVD/NIST. |
| 🧠 **Remediation Engine** | Prioriza os 5 riscos mais relevantes, com nível de confiança, evidências e passos de mitigação. |
| ⚡ **DAST Ativo** | OWASP ZAP (spider + active scan) e templates Nuclei. |
| 📰 **Feed de Inteligência** | Notícias e alertas agregados (NVD, CISA, OWASP, HackerNews, Google Security). |
| 📄 **Exportação de Relatórios** | Resultados exportáveis em PDF. |
| 🌍 **i18n** | Interface completa em Português e Inglês. |

### Demo Mode vs. Live Mode

| | Demo Mode (padrão) | Live Mode |
| :--- | :--- | :--- |
| Acesso | Qualquer visitante | Exige a Master API Key (header `X-API-Key`) |
| Alvos | Apenas uma whitelist de sites de teste propositalmente vulneráveis | Qualquer alvo |
| Dados | Local storage do navegador | PostgreSQL |

> [!WARNING]
> ZAP e Nuclei fazem scans **ativos** (fuzzing, injeção de payloads). Use apenas contra sistemas que você possui ou tem autorização explícita para testar.

---

## 🏗️ Arquitetura

| Componente | Tecnologia | Função |
| :--- | :--- | :--- |
| **Frontend** | Next.js 16, React 19, TailwindCSS 4 | Dashboard, gráficos, logs em tempo real. Faz proxy das chamadas à API. |
| **Backend** | Python, FastAPI | API REST, orquestração de scanners, correlação de CVEs, autenticação. |
| **Banco** | PostgreSQL 16 | Alvos, CVEs, histórico de scans. |
| **Cache/Fila** | Redis | Cache e resultados assíncronos. |
| **Scanners** | OWASP ZAP, Nuclei | Motores DAST ativos. |
| **Proxy** | Nginx + Let's Encrypt | Proxy reverso, TLS, hardening. |

---

## 🛠️ Como Executar Localmente

```bash
cp .env.example .env          # defina POSTGRES_PASSWORD e ADMIN_API_KEY
docker compose up -d db redis backend

cd frontend
npm install
npm run dev                   # http://localhost:3000
```

ZAP opcional: `docker compose up -d zap`
Testes: `cd backend && pytest`

## 🚢 Produção

```bash
cp .env.example .env          # POSTGRES_PASSWORD é obrigatório em produção
docker compose -f docker-compose.prod.yml up -d --build db redis backend frontend nginx
```

Para HTTPS, rode `init-letsencrypt.sh` depois de apontar o domínio para o servidor.

---

## 📂 Estrutura

Veja a seção *Project Structure* no [README em inglês](README.md#-project-structure).

---

**Desenvolvido com foco em Cyber + Privacy 🔒**
