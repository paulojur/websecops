# 🛡️ WebSecOps Dashboard: Documentação Executiva e Funcional

## Visão Geral e Arquitetura do Sistema

### 1. O Que É o Projeto? (Conceito)
O **WebSecOps** é uma plataforma centralizada de **Monitoramento e Inteligência em Cibersegurança** (AppSec) e testes DAST (*Dynamic Application Security Testing*). 

O objetivo do sistema é automatizar a vigilância da segurança de aplicações web protegidas. Mais do que uma ferramenta funcional, o WebSecOps foi construído como um **Showcase Interativo (Portfólio)** para demonstrar habilidades avançadas de engenharia de software e segurança. 

Visitantes acessam o site automaticamente em **Demo Mode (Sandbox)**, uma vitrine segura que permite simular a correlação de vulnerabilidades em tempo real sem comprometer o servidor real ou disparar ataques acidentais.

Para analistas de segurança operando em ambiente real, a plataforma oferece um painel que:
1.  **Identifica** as tecnologias (Tech-Stack) usadas pelos seus sites.
2.  **Cruza** essas informações com bancos de dados globais (NVD) para identificar vulnerabilidades conhecidas (CVEs).
3.  **Realiza** simulações ativas de ataques (DAST) usando motores como OWASP ZAP e Nuclei.
4.  **Sintetiza** os riscos de forma inteligente através de uma Engine de Remediação interna.
5.  **Monitora** feeds de notícias recentes sobre ameaças cibernéticas globais.

---

### 2. Fluxo de Funcionamento (Como ele opera)

O sistema opera em diferentes níveis de profundidade (Passivo e Ativo):

#### A. Coleta Passiva (Tech Stack & Recon)
O usuário fornece a URL do site. O sistema simula a visão de um atacante externo e analisa silenciosamente os cabeçalhos HTTP (Headers), Cookies e o DOM (HTML) para descobrir tecnologias rodando por trás (ex: React, Nginx, PHP).

#### B. Processamento e Priorização (Remediation Engine)
- **Correlação Direta:** O sistema consulta a base de dados interna de CVEs e verifica se as tecnologias detectadas possuem vulnerabilidades críticas.
- **Redução de Ruído (Anti-Spam):** Para evitar pânico com milhares de falsos positivos, o backend filtra e prioriza apenas os **Top 5 riscos mais relevantes** para analistas.
- **Padronização:** A Engine de Remediação traduz jargões técnicos complexos em planos de ação claros, com evidências técnicas, razões de correlação (Alta/Baixa Confiança) e passos imediatos de mitigação, entregues no padrão global de cibersegurança (Inglês).

#### C. DAST Activo (Live Mode)
Para usuários autenticados via **Master API Key**, o sistema libera os motores de ataque dinâmicos:
- **OWASP ZAP (Spider & Active Scan):** Varre rotas invisíveis e injeta *payloads* em campos de formulário para detectar XSS, SQLi, entre outros.
- **Nuclei:** Executa milhares de templates rápidos (YAML) baseados em vulnerabilidades recentes (*Zero-Days*) para testar se a infraestrutura está exposta.

---

### 3. Arquitetura Técnica (Para o Arquiteto explicar)

O projeto é construído sobre uma arquitetura moderna de **Microserviços em Containers (Docker)**, garantindo modularidade, portabilidade e segurança isolada.

#### 🖥️ Frontend (Interface do Usuário)
*   **Tecnologias:** Next.js, React, TailwindCSS.
*   **Papel:** Dashboard executivo e interativo. Traduz dados técnicos (JSONs) em componentes visuais, gráficos (Vulnerability Trends) e logs de terminal em tempo real.
*   **Destaque:** Totalmente Internacionalizado (i18n), permitindo transição fluida entre Português (PT-BR) e Inglês (EN). Implementa um sistema dual: *Demo Mode* (seguro, sem acesso a banco) e *Live Mode* (acesso total via API Key).

#### ⚙️ Backend (API e Regras de Negócio)
*   **Tecnologia:** Python com FastAPI.
*   **Papel:** Núcleo de orquestração. Gerencia segurança (Validação Criptográfica de Chaves), despacha tarefas assíncronas de scan (ZAP/Nuclei) e executa as lógicas pesadas de correlação.
*   **Segurança Embutida (Secure-by-Default):** Proteções ativas contra escalonamento. Caso a Master API Key não seja fornecida no servidor, o sistema gera criptograficamente uma chave temporária bloqueando acessos indevidos.

#### 🗄️ Camada de Dados e Cache
*   **Tecnologias:** PostgreSQL e Redis.
*   **Papel:** Armazenamento relacional para histórico de alvos e varreduras (Postgres). Gerenciamento rápido de cache e filas assíncronas para os resultados dos scanners (Redis).

#### 🛡️ Infraestrutura e Proxy
*   **Tecnologia:** Nginx.
*   **Papel:** Proxy reverso que roteia as chamadas do frontend para os serviços de backend.
*   **Destaque (Hardening):** Configurado com diretivas como `server_tokens off;` e roteamento restrito, dificultando o *Fingerprinting* do próprio WebSecOps por robôs maliciosos.

---

### 4. Diferenciais Estratégicos (Por que usar?)

1.  **Vigilância Ativa vs. Passiva:**
    Em vez de esperar um relatório de *pentest* anual para saber se está seguro, a empresa audita ativamente e descobre imediatamente quando uma tecnologia fica obsoleta.

2.  **Contexto e Inteligência (Menos Ruído):**
    Muitas ferramentas apenas jogam logs na tela. O *Remediation Engine* do WebSecOps prioriza riscos e cria hipóteses (Baixa vs Alta confiança) baseado em evidências, economizando horas da equipe de SOC (Security Operations Center).

3.  **Independência e Privacidade (On-Premise):**
    Todo o sistema roda em infraestrutura própria via Docker Compose. Os dados das varreduras não passam por servidores de terceiros, garantindo total privacidade e controle, protegidos por uma autenticação ponta-a-ponta nativa.

4.  **Showcase e Portfólio Interativo (Demo Mode):**
    Projetado para impressionar técnica e visualmente. A arquitetura de frontend isolado garante que recrutadores, desenvolvedores ou equipes de venda explorem um "Sandbox" (Demo Mode) seguro e restrito à memória do navegador (Local Storage). Os motores destrutivos ficam trancados na infraestrutura real (Live Mode), acessíveis apenas através de uma Master Key rigorosamente validada no backend.

---

### 5. Perguntas Frequentes (FAQ para Apresentação)

*   **"O modo de Correlação (Tech Stack) derruba meu site?"**
    Não. A primeira varredura é 100% passiva. O sistema não envia *exploits*, apenas mapeia o que é público. O risco de impacto é nulo.
    
*   **"E o ZAP e o Nuclei? Eles causam impacto?"**
    Sim. Eles realizam fuzzing e injeções (Scans Ativos). Por isso, no sistema WebSecOps, esses módulos são trancados atrás do painel administrativo e só podem ser executados no modo "LIVE", devendo ser usados estritamente contra aplicações que você tem permissão para auditar.

*   **"Como o sistema protege a si mesmo?"**
    Toda a interface entre cliente e backend depende da validação de uma Master Key via Headers HTTP, mitigando ataques de quebra de autenticação. Além disso, a comunicação exposta ao exterior é filtrada pelo Nginx (Hardening).

*   **"Como a inteligência é alimentada?"**
    Robôs internos mantêm uma sincronia contínua de ameaças raspando dados do NVD, HackerNews, OWASP, CISA e Google Security.
