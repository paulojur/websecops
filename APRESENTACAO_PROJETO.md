# 🛡️ WebSecOps Dashboard: Documentação Executiva
## Visão Geral e Arquitetura do Sistema

### 1. O Que É o Projeto? (Conceito)
O **WebSecOps** é uma plataforma centralizada de **Monitoramento e Inteligência em Cibersegurança**. 

O objetivo do sistema é automatizar a vigilância da segurança de aplicações web protegidas. Em vez de depender de verificações manuais esporádicas, a plataforma oferece um painel em tempo real que:
1.  **Identifica** as tecnologias usadas pelos seus sites.
2.  **Cruza** essas informações com bancos de dados globais de falhas de segurança.
3.  **Monitora** notícias recentes sobre ameaças cibernéticas.
4.  **Alerta** visualmente sobre riscos críticos antes que sejam explorados.

---

### 2. Fluxo de Funcionamento (Como ele opera)

O sistema opera em um ciclo contínuo de três etapas:

#### A. Coleta (Input)
O usuário fornece apenas a URL (endereço) do site que deseja monitorar. O sistema não exige acesso privilegiado (senhas) ao servidor, pois simula a visão de um atacante externo.

#### B. Processamento (Análise)
Assim que uma URL é inserida, o "motor" do sistema entra em ação:
*   **Identificação de Tech Stack:** O sistema analisa as respostas do servidor para descobrir o que está rodando por trás (Ex: "Este site usa PHP 7.4 e Servidor Apache").
*   **Correlação de Vulnerabilidades (CVEs):** Ele consulta sua base de dados interna (sincronizada com o governo americano/NVD) para verificar: *"A versão 7.4 do PHP tem falhas conhecidas?"*.
*   **Análise de Inteligência:** Paralelamente, robôs (scrapers) varrem feeds de notícias de segurança para trazer os últimos alertas do mercado.

#### C. Visualização (Output)
O resultado é apresentado em um Dashboard executivo:
*   **Score de Risco:** Indicadores visuais (Verde/Amarelo/Vermelho) baseados na gravidade das falhas encontradas.
*   **Lista de Vulnerabilidades:** Detalhamento técnico de cada falha (ex: "Risco de Injeção de SQL").
*   **Feed de Notícias:** Atualizações em tempo real sobre o cenário de segurança global.

---

### 3. Arquitetura Técnica (Para o Arquiteto explicar)

O projeto é construído sobre uma arquitetura moderna de **Microserviços em Containers**, garantindo modularidade e facilidade de manutenção.

#### 🖥️ Frontend (Interface do Usuário)
*   **Tecnologia:** Next.js (React).
*   **Papel:** É a camada de apresentação. Responsável por traduzir dados técnicos complexos (JSONs de APIs) em gráficos e tabelas compreensíveis.
*   **Destaque:** Foco em UX (Experiência do Usuário) com design responsivo e atualizações em tempo real sem recarregar a página.

#### ⚙️ Backend (API e Regras de Negócio)
*   **Tecnologia:** Python com FastAPI.
*   **Papel:** É o núcleo de processamento. Recebe as requisições, orquestra os scanners, processa os dados brutos e decide o que é relevante salvar.
*   **Destaque:** Alta performance assíncrona, permitindo escanear múltiplos sites e consultar milhares de registros de vulnerabilidades simultaneamente sem travar.

#### 🗄️ Camada de Dados (Persistência)
*   **Tecnologia:** PostgreSQL.
*   **Papel:** Armazenamento relacional robusto. Guarda o histórico de scans, a base completa de CVEs (vulnerabilidades globais) e os perfis dos sites monitorados.

#### 🤖 Módulos de Scan e Inteligência
*   **Tech Detector:** Módulo próprio em Python que analisa cabeçalhos HTTP e padrões de HTML para "assinar" as tecnologias do site.
*   **Integração NVD:** Um serviço agendado que baixa diariamente o "National Vulnerability Database", garantindo que o sistema conheça falhas descobertas até o dia anterior.

---

### 4. Diferenciais Estratégicos (Por que usar?)

1.  **Vigilância Ativa vs. Passiva:**
    *   *Antigo:* Você espera um pentest anual para saber se está seguro.
    *   *Novo:* O sistema monitora continuamente se a sua tecnologia ficou obsoleta ou perigosa da noite para o dia.

2.  **Contexto, não apenas Dados:**
    *   Muitas ferramentas apenas listam 10.000 problemas. Nosso sistema foca em **vulnerabilidades correlacionadas**: ele só avisa sobre falhas do Apache se o seu site *realmente* usar Apache. Isso reduz drasticamente o ruído e o falso-positivo.

3.  **Independência:**
    *   Todo o sistema roda em infraestrutura própria (On-Premise ou Nuvem Privada), via Docker. Os dados dos seus sites não passam por terceiros, garantindo total privacidade e controle.

---

### 5. Perguntas Frequentes (FAQ para Apresentação)

*   **"Ele invade o site?"**
    *   Não. O modo padrão apenas lê informações públicas que o site já expõe (Scan Passivo). Ele não realiza ataques nem derruba serviços.
    
*   **"De onde vêm os dados de falhas?"**
    *   São fontes oficiais e públicas, principalmente o banco de dados do NIST (Instituto Nacional de Padrões e Tecnologia dos EUA).

*   **"Preciso instalar algo no meu servidor?"**
    *   Não. O sistema é externo (Black Box). Ele avalia o site como um visitante comum veria.
