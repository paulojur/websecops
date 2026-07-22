export type Language = 'pt' | 'en';

export const translations = {
  pt: {
    // Sidebar
    dashboard: 'Dashboard',
    myTargets: 'Meus Alvos',
    scanCenter: 'Centro de Scan',
    vulnerabilities: 'Vulnerabilidades',
    intelligence: 'Inteligência',
    settings: 'Configurações',
    qaEngineer: 'Engenheiro de QA',
    securityDept: 'Departamento de Segurança',
    language: 'Idioma',

    // Dashboard / Home
    criticalVulnerabilities: 'Vulnerabilidades Críticas',
    trackedAssets: 'Ativos Rastreados',
    recentVulnerabilities: 'Vulnerabilidades Recentes',
    threatIntelligence: 'Inteligência de Ameaças',
    targetCorrelations: 'Correlações de Alvos',
    allTargets: 'Todos os Alvos',
    riskScore: 'Pontuação de Risco',
    severity: 'Severidade',
    critical: 'Crítica',
    high: 'Alta',
    medium: 'Média',
    low: 'Baixa',
    addTarget: 'Adicionar Alvo',
    enterTargetUrl: 'Insira a URL do alvo',
    addButton: 'Adicionar',
    noTargets: 'Nenhum alvo encontrado',
    deleteTarget: 'Deletar Alvo',
    syncVulnerabilities: 'Sincronizar Vulnerabilidades',
    loadingData: 'Carregando dados...',
    errorLoading: 'Erro ao carregar dados',
    filterByRisk: 'Filtrar por Risco',
    noCVEFound: 'Nenhum CVE encontrado',
    viewDetails: 'Ver Detalhes',
    close: 'Fechar',
    delete: 'Deletar',
    confirm: 'Confirmar',
    cancel: 'Cancelar',
    areYouSure: 'Tem certeza de que deseja deletar este alvo?',

    // Targets page
    myTargetsTitle: 'Meus Alvos',
    myTargetsDescription: 'Gerencie seus alvos de segurança',
    addNewTarget: 'Adicionar Novo Alvo',
    targetUrl: 'URL do Alvo',
    status: 'Status',
    active: 'Ativo',
    inactive: 'Inativo',
    lastScanned: 'Último Scan',
    actions: 'Ações',
    scan: 'Scan',
    remove: 'Remover',

    // Scans page & Origin Filters
    scanCenter: 'Centro de Scan Avançado',
    scanCenterSubtitle: 'Análise profunda de vulnerabilidades (DAST & Recon)',
    runScan: 'Executar Scan',
    scanHistory: 'Histórico de Scans Salvos',
    startTime: 'Hora de Início',
    endTime: 'Hora de Término',
    duration: 'Duração',
    results: 'Resultados',
    issuesFound: 'Problemas Encontrados',
    scanning: 'ESCANEANDO...',
    scanCompleted: 'Scan Concluído!',
    allOrigins: 'Todas',
    nucleiReconFilter: 'Nuclei Recon',
    zapDastFilter: 'ZAP DAST',
    staticCveFilter: 'Estática (CVE)',
    reconNuclei: '⚡ Recon (Nuclei)',
    spiderPassive: '🕷️ Spider (Passivo)',
    activeIntrusive: '🔥 Active (Intrusivo)',
    footprintAndCves: 'Footprint & CVEs',
    mappingAndStructure: 'Mapeamento & Estrutura',
    simulatedAttacks: 'Ataques Simulados',
    startScan: 'INICIAR SCAN',
    executionLogs: 'Logs de Execução',
    waitingCommand: 'Aguardando comando...',
    progress: 'Progresso',
    coverageReport: 'Relatório de Cobertura',
    alerts: 'Alertas',
    coverage: 'Cobertura',
    noAlertsFound: 'Nenhum alerta vulnerável encontrado.',
    configureScanPrompt: 'Configure um scan para ver os resultados aqui.',
    copyTicket: 'Copiar Ticket (Jira/Markdown)',
    occurrences: 'ocorrência',
    occurrencesPlural: 'ocorrências',

    // Master Key Modal & Tooltips
    masterKeyRequiredTitle: 'Master API Key Necessária',
    masterKeyRequiredDesc: 'Para executar varreduras ativas no servidor de produção, informe a Master Key abaixo. No modo DEMO, você pode usar a simulação interativa.',
    masterKeyTooltip: 'Execução Ativa no Servidor: Requer Master Key. Passe para DEMO para testar simulação.',
    enterMasterKey: 'Insira a Master API Key',
    saveMasterKey: 'Salvar Chave',
    clearMasterKey: 'Remover Chave',

    // Targets page
    myTargetsTitle: 'Gerenciamento de Alvos',
    myTargetsDescription: 'Monitore suas aplicações web e APIs',
    liveModeDesc: 'Os alvos são salvos no backend Postgres e consultados pela API.',
    demoModeDesc: 'Os alvos são analisados em tempo real e salvos localmente no seu navegador.',
    activeTargets: 'ALVOS ATIVOS',
    enterTargetUrl: 'https://exemplo.com.br',
    addTargetButton: 'ADICIONAR',
    targetAddedSuccess: 'Alvo escaneado e adicionado com sucesso!',
    targetAddError: 'Falha ao adicionar alvo. Verifique se a Master Key está salva para o modo LIVE.',

    // Vulnerabilities page
    vulnerabilitiesTitle: 'Vulnerabilidades',
    vulnerabilitiesDescription: 'Todas as vulnerabilidades detectadas e correlacionadas',
    cveId: 'ID do CVE',
    description: 'Descrição',
    affectedSystems: 'Sistemas Afetados',
    published: 'Publicado',
    remediation: 'Remediação',
    export: 'Exportar',
    exportPDF: 'Exportar para PDF',

    // Intelligence page
    intelligenceTitle: 'Inteligência de Ameaças',
    intelligenceDescription: 'Atualizações de segurança cibernética e boletins CISA/NVD',
    source: 'Fonte',
    date: 'Data',
    readMore: 'Leia Mais',
  },
  en: {
    // Sidebar
    dashboard: 'Dashboard',
    myTargets: 'My Targets',
    scanCenter: 'Scan Center',
    vulnerabilities: 'Vulnerabilities',
    intelligence: 'Intelligence',
    settings: 'Settings',
    qaEngineer: 'QA Engineer',
    securityDept: 'Security Dept.',
    language: 'Language',

    // Dashboard / Home
    criticalVulnerabilities: 'Critical Vulnerabilities',
    trackedAssets: 'Tracked Assets',
    recentVulnerabilities: 'Recent Vulnerabilities',
    threatIntelligence: 'Threat Intelligence',
    targetCorrelations: 'Target Correlations',
    allTargets: 'All Targets',
    riskScore: 'Risk Score',
    severity: 'Severity',
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    addTarget: 'Add Target',
    enterTargetUrl: 'Enter target URL',
    addButton: 'Add',
    noTargets: 'No targets found',
    deleteTarget: 'Delete Target',
    syncVulnerabilities: 'Sync Vulnerabilities',
    loadingData: 'Loading data...',
    errorLoading: 'Error loading data',
    filterByRisk: 'Filter by Risk',
    noCVEFound: 'No CVE found',
    viewDetails: 'View Details',
    close: 'Close',
    delete: 'Delete',
    confirm: 'Confirm',
    cancel: 'Cancel',
    areYouSure: 'Are you sure you want to delete this target?',

    // Scans page & Origin Filters
    scanCenterTitle: 'Advanced Scan Center',
    scanCenterSubtitle: 'Deep vulnerability analysis (DAST & Recon)',
    runScan: 'Run Scan',
    scanHistory: 'Saved Scan History',
    startTime: 'Start Time',
    endTime: 'End Time',
    duration: 'Duration',
    results: 'Results',
    issuesFound: 'Issues Found',
    scanning: 'SCANNING...',
    scanCompleted: 'Scan Completed!',
    allOrigins: 'All',
    nucleiReconFilter: 'Nuclei Recon',
    zapDastFilter: 'ZAP DAST',
    staticCveFilter: 'Static (CVE)',
    reconNuclei: '⚡ Recon (Nuclei)',
    spiderPassive: '🕷️ Spider (Passive)',
    activeIntrusive: '🔥 Active (Intrusive)',
    footprintAndCves: 'Footprint & CVEs',
    mappingAndStructure: 'Mapping & Structure',
    simulatedAttacks: 'Simulated Attacks',
    startScan: 'START SCAN',
    executionLogs: 'Execution Logs',
    waitingCommand: 'Waiting for command...',
    progress: 'Progress',
    coverageReport: 'Coverage Report',
    alerts: 'Alerts',
    coverage: 'Coverage',
    noAlertsFound: 'No vulnerable alerts found.',
    configureScanPrompt: 'Configure a scan to see results here.',
    copyTicket: 'Copy Ticket (Jira/Markdown)',
    occurrences: 'occurrence',
    occurrencesPlural: 'occurrences',

    // Master Key Modal & Tooltips
    masterKeyRequiredTitle: 'Master API Key Required',
    masterKeyRequiredDesc: 'To execute active scans on the production server, enter your Master Key below. In DEMO mode, you can use interactive simulation.',
    masterKeyTooltip: 'Active Execution: Master Key required. Switch to DEMO to test interactive simulation.',
    enterMasterKey: 'Enter Master API Key',
    saveMasterKey: 'Save Key',
    clearMasterKey: 'Clear Key',

    // Targets page
    myTargetsTitle: 'Target Management',
    myTargetsDescription: 'Monitor your web applications and APIs',
    liveModeDesc: 'Targets are stored in Postgres backend and queried via API.',
    demoModeDesc: 'Targets are analyzed in real-time and saved locally in your browser.',
    activeTargets: 'ACTIVE TARGETS',
    enterTargetUrl: 'https://example.com',
    addTargetButton: 'ADD TARGET',
    targetAddedSuccess: 'Target scanned and added successfully!',
    targetAddError: 'Failed to add target. Ensure Master Key is set for LIVE mode.',

    // Vulnerabilities page
    vulnerabilitiesTitle: 'Vulnerabilities',
    vulnerabilitiesDescription: 'All detected and correlated vulnerabilities',
    cveId: 'CVE ID',
    description: 'Description',
    affectedSystems: 'Affected Systems',
    published: 'Published',
    remediation: 'Remediation',
    export: 'Export',
    exportPDF: 'Export to PDF',

    // Intelligence page
    intelligenceTitle: 'Threat Intelligence',
    intelligenceDescription: 'Cybersecurity updates and CISA/NVD bulletins',
    source: 'Source',
    date: 'Date',
    readMore: 'Read More',
  },
};

export const detectLanguage = (): Language => {
  if (typeof window === 'undefined') return 'pt';
  
  // Verifica se há idioma salvo no localStorage
  const savedLang = localStorage.getItem('language') as Language | null;
  if (savedLang && (savedLang === 'pt' || savedLang === 'en')) {
    return savedLang;
  }

  // Detecta o idioma do navegador
  const browserLang = navigator.language.split('-')[0].toLowerCase();
  return browserLang === 'pt' ? 'pt' : 'en';
};

export const getTranslation = (lang: Language, key: keyof typeof translations.pt): string => {
  return translations[lang][key] || translations.pt[key] || key;
};
