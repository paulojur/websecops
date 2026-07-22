'use client';

import { Zap, Play, Activity, ShieldCheck, FileDown, Copy, Check, Key, History, HelpCircle, X, Layers } from 'lucide-react';
import { useState, useEffect } from 'react';
import { startSpiderScan, startActiveScan, checkScanStatus, getScanResults, saveScanHistory, startNucleiScan, checkNucleiStatus, getNucleiResults } from '@/lib/api';
import { exportScanResultsCSV, exportScanResultsPDF } from '@/lib/export';
import { useLanguage } from '@/lib/useLanguage';
import { AppMode, getAppMode, getDemoScanHistory, saveDemoScanHistory } from '@/lib/demo-targets';

type ScanStatus = {
    status: 'starting' | 'scanning' | 'completed';
    progress: number;
    id?: string;
    type?: string;
};

type AlertRemediation = {
    title: string;
    category: string;
    confidence: string;
    confidence_reason?: string;
    root_cause?: string;
    evidence: string;
    recommendation: string;
    next_step?: string;
    report_text: string;
    report_sections?: {
        risk: string;
        evidence: string;
        impact: string;
        recommendation: string;
        next_step: string;
    };
    snippets?: {
        nginx?: string;
        apache?: string;
    };
};

type ScanAlert = {
    alert: string;
    risk: string;
    confidence?: string;
    description?: string;
    method?: string;
    url?: string;
    sourceid?: string;
    remediations?: AlertRemediation[];
};

type CoverageItem = {
    name: string;
    status: 'pass' | 'fail';
    cwe?: string;
};

type TriageGroup = {
    root_cause: string;
    count: number;
    highest_severity: string;
    next_step: string;
};

type ScanTriage = {
    total_alerts: number;
    analyst_note?: string;
    risk_groups?: TriageGroup[];
};

export default function ScansPage() {
    const { t } = useLanguage();
    const [targetUrl, setTargetUrl] = useState('');
    const [scanType, setScanType] = useState('spider');
    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const [results, setResults] = useState<ScanAlert[] | null>(null);
    const [coverage, setCoverage] = useState<CoverageItem[] | null>(null);
    const [triage, setTriage] = useState<ScanTriage | null>(null);
    const [riskFilter, setRiskFilter] = useState('ALL');
    const [viewMode, setViewMode] = useState<'alerts' | 'coverage'>('alerts');
    const [sourceFilter, setSourceFilter] = useState<'ALL' | 'NUCLEI' | 'ZAP' | 'STATIC'>('ALL');
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const [isAdmin, setIsAdmin] = useState(false);
    const [appMode, setAppModeState] = useState<AppMode>('demo');
    const [showKeyModal, setShowKeyModal] = useState(false);
    const [masterKeyInput, setMasterKeyInput] = useState('');
    const [savedHistory, setSavedHistory] = useState<any[]>([]);
    const [showHistoryDrawer, setShowHistoryDrawer] = useState(false);

    useEffect(() => {
        const mode = getAppMode();
        setAppModeState(mode);
        const savedKey = localStorage.getItem('admin_api_key');
        setIsAdmin(!!savedKey);
        loadHistory(mode);
    }, []);

    const loadHistory = (mode: AppMode) => {
        if (mode === 'demo') {
            setSavedHistory(getDemoScanHistory());
        }
    };

    const addLog = (msg: string) => setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);

    const handleSaveKey = (e: React.FormEvent) => {
        e.preventDefault();
        if (masterKeyInput.trim()) {
            localStorage.setItem('admin_api_key', masterKeyInput.trim());
            setIsAdmin(true);
            setShowKeyModal(false);
            alert('Master API Key salva com sucesso!');
        }
    };

    const handleClearKey = () => {
        localStorage.removeItem('admin_api_key');
        setIsAdmin(false);
        setMasterKeyInput('');
        setShowKeyModal(false);
    };

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!targetUrl) return;

        // If in LIVE mode and requiring admin key for active or nuclei scan without key
        if (appMode === 'live' && !isAdmin && (scanType === 'active' || scanType === 'nuclei')) {
            setShowKeyModal(true);
            return;
        }

        setScanStatus({ status: 'starting', progress: 0 });
        setLogs([]);
        setResults(null);
        setCoverage(null);
        setTriage(null);

        if (appMode === 'demo') {
            runDemoSimulationScan();
            return;
        }

        addLog(`Iniciando Scan Live (${scanType}) em: ${targetUrl}`);

        try {
            let data;
            if (scanType === 'spider') {
                data = await startSpiderScan(targetUrl);
            } else if (scanType === 'nuclei') {
                data = await startNucleiScan(targetUrl);
            } else {
                if (!confirm('ATENÇÃO: O Scan Ativo envia payloads de teste que podem ser interpretados como ataque. Você tem autorização para escanear este alvo?')) {
                    setScanStatus(null);
                    return;
                }
                data = await startActiveScan(targetUrl);
            }

            if (data.status === 'started') {
                addLog(`Scan iniciado com ID: ${data.scan_id}`);
                setScanStatus({ status: 'scanning', progress: 0, id: data.scan_id, type: scanType });
                pollStatus(scanType, data.scan_id);
            } else {
                addLog(`Erro ao iniciar: ${data.message}`);
                setScanStatus(null);
            }
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : 'erro desconhecido';
            addLog(`Erro de conexão: ${message}`);
            setScanStatus(null);
        }
    };

    // Interactive Demo Scan Simulation for visitors
    const runDemoSimulationScan = () => {
        setScanStatus({ status: 'scanning', progress: 5 });
        addLog(`[DEMO SIMULATION] Iniciando varredura interativa (${scanType.toUpperCase()}) em ${targetUrl}...`);

        const steps = [
            { pct: 20, log: 'Mapeando estrutura do alvo, portas ativas e rotas HTTPS...' },
            { pct: 45, log: scanType === 'nuclei' ? 'Executando templates Nuclei (CVEs, Footprints & Misconfigurations)...' : 'Executando Spider DAST e analisando headers de resposta...' },
            { pct: 70, log: 'Verificando assinaturas de vulnerabilidades e cabeçalhos de segurança...' },
            { pct: 90, log: 'Correlacionando alertas com o banco de inteligência NVD...' },
            { pct: 100, log: 'Varredura concluída com sucesso!' },
        ];

        let stepIndex = 0;
        const interval = setInterval(() => {
            if (stepIndex < steps.length) {
                const step = steps[stepIndex];
                setScanStatus({ status: step.pct === 100 ? 'completed' : 'scanning', progress: step.pct });
                addLog(`[DEMO SIMULATION] ${step.log}`);
                stepIndex++;
            } else {
                clearInterval(interval);
                generateDemoResults();
            }
        }, 1200);
    };

    const generateDemoResults = () => {
        const mockAlerts: ScanAlert[] = [
            {
                alert: 'HTTP Missing Security Headers',
                risk: 'Medium',
                confidence: 'High',
                description: 'A aplicação web não retornou os cabeçalhos de segurança recomendados (X-Frame-Options, Content-Security-Policy, Strict-Transport-Security).',
                method: 'GET',
                url: targetUrl,
                sourceid: scanType === 'nuclei' ? 'nuclei' : 'zap',
                remediations: [{
                    title: 'Adicionar Cabeçalhos de Segurança HTTP',
                    category: 'Header Configuration',
                    confidence: 'High',
                    evidence: 'GET ' + targetUrl,
                    recommendation: 'Configure os cabeçalhos X-Frame-Options: DENY, X-Content-Type-Options: nosniff e Content-Security-Policy no seu proxy/servidor web (Nginx/Apache).',
                    report_text: 'Impacto: Permite ataques de Clickjacking e MIME Sniffing devido à ausência de diretivas HTTP rígidas.'
                }]
            },
            {
                alert: 'TLS Version - Deprecated Protocol Check',
                risk: 'Low',
                confidence: 'Medium',
                description: 'Verificação da versão do protocolo TLS e ciphers suportados pelo servidor.',
                method: 'GET',
                url: targetUrl,
                sourceid: 'nuclei',
                remediations: [{
                    title: 'Desativar TLS 1.0 e 1.1',
                    category: 'TLS Hardening',
                    confidence: 'High',
                    evidence: 'TLS 1.2 / TLS 1.3 Active',
                    recommendation: 'Assegure que apenas TLS 1.2 e TLS 1.3 estejam habilitados no Nginx/Apache.',
                    report_text: 'Recomendado desativar ciphers legados para conformidade com PCI-DSS.'
                }]
            },
            {
                alert: 'Cross-Site Scripting (Reflected Candidate)',
                risk: scanType === 'active' ? 'High' : 'Medium',
                confidence: 'Medium',
                description: 'Potencial vetor de injeção de scripts detectado em parâmetros de URL sem higienização adequada.',
                method: 'GET',
                url: `${targetUrl}/?q=%3Cscript%3Ealert(1)%3C/script%3E`,
                sourceid: 'zap',
                remediations: [{
                    title: 'Higienização de Entrada e Encoding de Saída',
                    category: 'Input Validation',
                    confidence: 'High',
                    evidence: 'Param: q',
                    recommendation: 'Aplique encoding HTML para dados dinâmicos exibidos no DOM e implemente uma política CSP (Content Security Policy) restritiva.',
                    report_text: 'Ataques XSS permitem a execução de scripts maliciosos no navegador de usuários legítimos.'
                }]
            }
        ];

        const mockCoverage: CoverageItem[] = [
            { name: 'Certificado SSL/TLS Válido', status: 'pass', cwe: 'CWE-295' },
            { name: 'Proteção contra Clickjacking (X-Frame-Options)', status: 'fail', cwe: 'CWE-1021' },
            { name: 'Sanitização de Parâmetros (XSS)', status: 'fail', cwe: 'CWE-79' },
            { name: 'Strict-Transport-Security (HSTS)', status: 'pass', cwe: 'CWE-523' },
        ];

        const mockTriage: ScanTriage = {
            total_alerts: mockAlerts.length,
            analyst_note: 'Varredura demonstrativa concluída. Foram identificados 3 alertas de severidade Média/Alta que requerem atenção de hardening.',
            risk_groups: [
                { root_cause: 'Configuração de Cabeçalhos HTTP', count: 2, highest_severity: 'Medium', next_step: 'Adicionar Nginx security headers' },
                { root_cause: 'Validação de Parâmetros Web', count: 1, highest_severity: 'High', next_step: 'Implementar Sanitização XSS' }
            ]
        };

        setResults(mockAlerts);
        setCoverage(mockCoverage);
        setTriage(mockTriage);

        // Save to demo history
        const historyItem = {
            target_url: targetUrl,
            scan_type: scanType,
            total_alerts: mockAlerts.length,
            alerts: mockAlerts
        };
        saveDemoScanHistory(historyItem);
        loadHistory('demo');
    };

    const pollStatus = async (type: string, id: string) => {
        const interval = setInterval(async () => {
            try {
                let data;
                if (type === 'nuclei') {
                    data = await checkNucleiStatus(id);
                } else {
                    data = await checkScanStatus(type, id);
                }
                setScanStatus((prev) => prev ? { ...prev, progress: data.progress } : prev);

                if (data.details && !logs.includes(`[${new Date().toLocaleTimeString()}] ${data.details}`)) {
                    setLogs(prev => {
                        const lastLog = prev[0] || '';
                        if (!lastLog.includes(data.details)) {
                            return [`[${new Date().toLocaleTimeString()}] ${data.details}`, ...prev];
                        }
                        return prev;
                    });
                }

                if (data.status === 'completed' || data.progress >= 100) {
                    clearInterval(interval);
                    addLog('Scan concluído!');
                    setScanStatus((prev) => prev ? { ...prev, status: 'completed', progress: 100 } : prev);
                    const resultsData = await loadResults(type, id);
                    try {
                        addLog('Salvando histórico de vulnerabilidades...');
                        if (type === 'nuclei' && resultsData?.alerts) {
                            await saveScanHistory(targetUrl, type, resultsData.alerts);
                        } else {
                            await saveScanHistory(targetUrl, type);
                        }
                        addLog('Histórico salvo com sucesso!');
                    } catch (err) {
                        addLog('Falha ao salvar o histórico no backend.');
                    }
                }
            } catch (e) {
                console.error(e);
                clearInterval(interval);
            }
        }, 5000);
    };

    const loadResults = async (type?: string, id?: string) => {
        try {
            addLog('Buscando resultados...');
            let data;
            
            const currentType = type || scanStatus?.type;
            const currentId = id || scanStatus?.id;
            
            if (currentType === 'nuclei' && currentId) {
                const raw = await getNucleiResults(currentId);
                const transformedAlerts = (raw.alerts || []).map((alert: any) => ({
                    alert: alert.info?.name || 'Nuclei Finding',
                    risk: alert.info?.severity || 'Low',
                    confidence: 'Medium',
                    description: alert.info?.description || 'No description provided by Nuclei template.',
                    method: 'GET',
                    url: alert.matched_at || targetUrl,
                    sourceid: 'nuclei',
                    evidence: alert.extracted_results ? alert.extracted_results.join(', ') : '',
                    remediations: [{
                        title: alert.info?.name || 'Finding',
                        category: alert.type || 'vuln',
                        confidence: 'Medium',
                        evidence: alert.matched_at || '',
                        recommendation: alert.info?.remediation || 'Investigate the matched signature.',
                        report_text: alert.info?.description || 'Nuclei template match.'
                    }]
                }));

                const nucleiTriage: ScanTriage = {
                    total_alerts: transformedAlerts.length,
                    analyst_note: `Nuclei Recon concluído para ${targetUrl}. ${transformedAlerts.length} assinaturas encontradas.`,
                    risk_groups: [
                        {
                            root_cause: 'Nuclei Template Detections',
                            count: transformedAlerts.length,
                            highest_severity: transformedAlerts[0]?.risk || 'Info',
                            next_step: 'Analisar evidencias e validar footprint.'
                        }
                    ]
                };

                setResults(transformedAlerts);
                setTriage(nucleiTriage);
                return { alerts: transformedAlerts };
            } else {
                data = await getScanResults(targetUrl);
                setResults(data.alerts);
                setCoverage(data.coverage);
                setTriage(data.triage);
                return data;
            }
        } catch (e) {
            addLog('Erro ao carregar resultados.');
            console.error(e);
        }
    };

    const loadHistoricalScan = (historyItem: any) => {
        setTargetUrl(historyItem.target_url);
        setScanType(historyItem.scan_type || 'spider');
        setResults(historyItem.alerts || []);
        setShowHistoryDrawer(false);
        addLog(`[HISTÓRICO] Carregado scan anterior para ${historyItem.target_url}`);
    };

    const handleCopyJira = (alertItem: ScanAlert) => {
        const text = `*VULNERABILIDADE DETECTADA: ${alertItem.alert}*\n` +
            `*Risco:* ${alertItem.risk}\n` +
            `*URL:* ${alertItem.url || targetUrl}\n` +
            `*Origem:* ${alertItem.sourceid || 'DAST'}\n\n` +
            `*Descrição:*\n${alertItem.description || 'N/A'}\n\n` +
            `*Recomendação:*\n${alertItem.remediations?.[0]?.recommendation || 'Verificar hardening.'}`;

        navigator.clipboard.writeText(text).then(() => {
            setCopiedId(alertItem.alert);
            setTimeout(() => setCopiedId(null), 2000);
        });
    };

    const filteredResults = results?.filter((alert) => {
        const riskMatch = riskFilter === 'ALL' || alert.risk.toUpperCase() === riskFilter;
        let sourceMatch = true;
        if (sourceFilter === 'NUCLEI') {
            sourceMatch = alert.sourceid === 'nuclei';
        } else if (sourceFilter === 'ZAP') {
            sourceMatch = alert.sourceid !== 'nuclei' && alert.sourceid !== 'static_analysis';
        } else if (sourceFilter === 'STATIC') {
            sourceMatch = alert.sourceid === 'static_analysis';
        }
        return riskMatch && sourceMatch;
    });

    const groupedResultsMap = new Map<string, any>();
    if (filteredResults) {
        for (const r of filteredResults) {
            if (groupedResultsMap.has(r.alert)) {
                const existing = groupedResultsMap.get(r.alert);
                existing.occurrences = (existing.occurrences || 1) + 1;
            } else {
                groupedResultsMap.set(r.alert, { ...r, occurrences: 1 });
            }
        }
    }
    const groupedResults = Array.from(groupedResultsMap.values());

    return (
        <div className="p-8 space-y-8 h-full flex flex-col relative">
            <header className="flex justify-between items-end border-b border-white/10 pb-6 shrink-0">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
                        <Zap className="w-8 h-8 text-yellow-400" />
                        {t('scanCenter')}
                    </h1>
                    <p className="text-gray-400 mt-2">{t('scanCenterSubtitle')}</p>
                </div>
                <div className="flex items-center gap-3">
                    <button
                        onClick={() => setShowHistoryDrawer(!showHistoryDrawer)}
                        className="flex items-center gap-2 px-3 py-2 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 text-gray-300 text-xs font-bold transition-colors"
                    >
                        <History className="w-4 h-4 text-cyber-secondary" />
                        {t('scanHistory')}
                    </button>
                    <button
                        onClick={() => setShowKeyModal(true)}
                        className={`flex items-center gap-2 px-3 py-2 border rounded-lg text-xs font-bold transition-colors ${isAdmin ? 'bg-cyber-primary/20 border-cyber-primary text-cyber-primary' : 'bg-white/5 border-white/10 text-gray-400 hover:text-white'}`}
                    >
                        <Key className="w-4 h-4" />
                        {isAdmin ? 'Master Key Salva' : 'Informar Master Key'}
                    </button>
                </div>
            </header>

            {/* Main Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 flex-1 min-h-0">
                {/* Left Panel: Configuration & Logs */}
                <div className="space-y-6">
                    <div className="glass-panel p-6 rounded-lg">
                        <h2 className="text-xl font-bold mb-4 flex items-center gap-2 text-white">
                            <Play className="w-5 h-5 text-cyber-primary" /> {t('runScan')}
                        </h2>
                        <form onSubmit={handleScan} className="space-y-4">
                            <div>
                                <label className="block text-xs font-bold text-gray-400 mb-1 uppercase">{t('targetUrl')}</label>
                                <input
                                    type="url"
                                    required
                                    placeholder="https://exemplo.com.br"
                                    className="w-full bg-black/30 border border-white/10 rounded p-3 text-white focus:border-cyber-primary outline-none"
                                    value={targetUrl}
                                    onChange={e => setTargetUrl(e.target.value)}
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-bold text-gray-400 mb-1 uppercase">Modo de Scan</label>
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                                    <button
                                        type="button"
                                        onClick={() => setScanType('nuclei')}
                                        className={`p-3 rounded border text-sm font-bold transition-colors text-left ${scanType === 'nuclei'
                                            ? 'bg-blue-500/20 border-blue-500 text-blue-400'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:bg-white/10'
                                            }`}
                                    >
                                        {t('reconNuclei')}
                                        <span className="block text-[10px] font-normal opacity-70 mt-1">{t('footprintAndCves')}</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setScanType('spider')}
                                        className={`p-3 rounded border text-sm font-bold transition-colors text-left ${scanType === 'spider'
                                            ? 'bg-cyber-primary/20 border-cyber-primary text-cyber-primary'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:bg-white/10'
                                            }`}
                                    >
                                        {t('spiderPassive')}
                                        <span className="block text-[10px] font-normal opacity-70 mt-1">{t('mappingAndStructure')}</span>
                                    </button>
                                    <button
                                        type="button"
                                        title={!isAdmin && appMode === 'live' ? t('masterKeyTooltip') : ''}
                                        onClick={() => {
                                            if (appMode === 'live' && !isAdmin) {
                                                setShowKeyModal(true);
                                            } else {
                                                setScanType('active');
                                            }
                                        }}
                                        className={`p-3 rounded border text-sm font-bold transition-colors text-left relative ${scanType === 'active'
                                            ? 'bg-red-500/20 border-red-500 text-red-500'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:bg-white/10'
                                            }`}
                                    >
                                        {t('activeIntrusive')}
                                        <span className="block text-[10px] font-normal opacity-70 mt-1">
                                            {appMode === 'live' && !isAdmin ? 'Requer Master Key' : t('simulatedAttacks')}
                                        </span>
                                    </button>
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={(scanStatus && scanStatus.status !== 'completed') || !targetUrl}
                                className="w-full bg-cyber-primary text-black font-bold py-3 rounded hover:bg-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed uppercase"
                            >
                                {scanStatus && scanStatus.status === 'scanning' ? t('scanning') : t('startScan')}
                            </button>
                        </form>
                    </div>

                    <div className="glass-panel p-6 rounded-lg flex flex-col h-[300px]">
                        <h2 className="text-sm font-bold mb-4 flex items-center gap-2 text-gray-400 uppercase tracking-wider">
                            <Activity className="w-4 h-4" /> {t('executionLogs')}
                        </h2>
                        <div className="bg-black/50 rounded flex-1 p-4 font-mono text-xs text-green-400 overflow-y-auto space-y-1 border border-white/5">
                            {logs.length === 0 && <span className="text-gray-600 italic">{t('waitingCommand')}</span>}
                            {logs.map((log, i) => (
                                <div key={i}>{log}</div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Right Panel: Results & Vulnerabilities */}
                <div className="lg:col-span-2 glass-panel p-6 rounded-lg flex flex-col min-h-0">
                    <div className="flex flex-col mb-6 gap-4">
                        <div className="flex justify-between items-center">
                            <div className="flex items-center gap-4">
                                <h2 className="text-xl font-bold flex items-center gap-2 text-white">
                                    <ShieldCheck className="w-5 h-5 text-cyber-secondary" />
                                    {viewMode === 'alerts' ? t('vulnerabilitiesTitle') : t('coverageReport')}
                                </h2>
                                {results && (
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <div className="flex bg-white/5 rounded p-1">
                                            <button
                                                onClick={() => setViewMode('alerts')}
                                                className={`px-3 py-1 text-xs font-bold rounded transition-colors ${viewMode === 'alerts' ? 'bg-cyber-primary text-black' : 'text-gray-400 hover:text-white'}`}
                                            >{t('alerts')}</button>
                                            <button
                                                onClick={() => setViewMode('coverage')}
                                                className={`px-3 py-1 text-xs font-bold rounded transition-colors ${viewMode === 'coverage' ? 'bg-cyber-primary text-black' : 'text-gray-400 hover:text-white'}`}
                                            >{t('coverage')} {(coverage?.length ?? 0) > 0 && `(${coverage?.length ?? 0})`}</button>
                                        </div>
                                        <button
                                            onClick={() => exportScanResultsCSV(results, triage as ScanTriage)}
                                            className="flex items-center gap-1 px-3 py-1 text-xs font-bold text-gray-300 bg-white/5 border border-white/10 rounded hover:bg-white/10 transition-colors"
                                        >
                                            <FileDown className="w-3 h-3" /> CSV
                                        </button>
                                        <button
                                            onClick={() => exportScanResultsPDF(results, triage as ScanTriage, coverage as CoverageItem[])}
                                            className="flex items-center gap-1 px-3 py-1 text-xs font-bold text-gray-300 bg-white/5 border border-white/10 rounded hover:bg-white/10 transition-colors"
                                        >
                                            <FileDown className="w-3 h-3" /> PDF
                                        </button>
                                    </div>
                                )}
                            </div>

                            {scanStatus && (
                                <div className="flex items-center gap-3">
                                    <div className="text-right">
                                        <p className="text-xs text-gray-400 uppercase">{t('progress')}</p>
                                        <p className="text-xl font-bold text-cyber-primary">{scanStatus.progress}%</p>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Filters */}
                        {results && (
                            <div className="flex flex-wrap items-center gap-4 bg-white/5 p-3 rounded-lg border border-white/5">
                                <div className="flex items-center gap-2">
                                    <span className="text-[10px] uppercase font-bold text-gray-500">{t('severity')}:</span>
                                    <div className="flex gap-1">
                                        {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((level) => (
                                            <button
                                                key={level}
                                                onClick={() => setRiskFilter(level)}
                                                className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors border ${riskFilter === level
                                                    ? 'bg-cyber-primary text-black border-cyber-primary'
                                                    : 'bg-transparent text-gray-500 border-white/10 hover:border-white/30'
                                                    }`}
                                            >
                                                {level}
                                            </button>
                                        ))}
                                    </div>
                                </div>

                                <div className="w-px h-4 bg-white/10 mx-2"></div>

                                <div className="flex items-center gap-2">
                                    <span className="text-[10px] uppercase font-bold text-gray-500">Origem:</span>
                                    <div className="flex gap-1">
                                        <button
                                            onClick={() => setSourceFilter('ALL')}
                                            className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors border ${sourceFilter === 'ALL'
                                                ? 'bg-cyber-secondary text-black border-cyber-secondary'
                                                : 'bg-transparent text-gray-500 border-white/10 hover:border-white/30'
                                                }`}
                                        >
                                            {t('allOrigins')}
                                        </button>
                                        <button
                                            onClick={() => setSourceFilter('NUCLEI')}
                                            className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors border ${sourceFilter === 'NUCLEI'
                                                ? 'bg-yellow-400 text-black border-yellow-400'
                                                : 'bg-transparent text-gray-500 border-white/10 hover:border-white/30'
                                                }`}
                                        >
                                            {t('nucleiReconFilter')}
                                        </button>
                                        <button
                                            onClick={() => setSourceFilter('ZAP')}
                                            className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors border ${sourceFilter === 'ZAP'
                                                ? 'bg-purple-400 text-black border-purple-400'
                                                : 'bg-transparent text-gray-500 border-white/10 hover:border-white/30'
                                                }`}
                                        >
                                            {t('zapDastFilter')}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        )}

                        {triage && (
                            <div className="bg-cyber-primary/10 border border-cyber-primary/20 rounded-lg p-4">
                                {triage.analyst_note && <p className="text-sm text-gray-200">{triage.analyst_note}</p>}
                            </div>
                        )}
                    </div>

                    <div className="flex-1 overflow-y-auto pr-2 space-y-3">
                        {!results && !scanStatus && (
                            <div className="h-full flex flex-col items-center justify-center text-gray-500 opacity-50">
                                <Zap className="w-16 h-16 mb-4" />
                                <p>{t('configureScanPrompt')}</p>
                            </div>
                        )}

                        {viewMode === 'alerts' && results && results.length === 0 && (
                            <div className="h-full flex items-center justify-center text-green-500">
                                <ShieldCheck className="w-12 h-12 mr-2" /> {t('noAlertsFound')}
                            </div>
                        )}

                        {viewMode === 'alerts' && groupedResults && groupedResults.map((alert: any, i: number) => (
                            <div key={i} className={`bg-white/5 border-l-4 p-4 rounded-r ${alert.risk === 'High' ? 'border-red-500' :
                                alert.risk === 'Medium' ? 'border-orange-500' :
                                    alert.risk === 'Low' ? 'border-yellow-500' : 'border-blue-500'
                                }`}>
                                <div className="flex justify-between items-start">
                                    <div className="flex flex-col gap-1">
                                        <h3 className={`font-bold ${alert.risk === 'High' ? 'text-red-400' :
                                            alert.risk === 'Medium' ? 'text-orange-400' : 'text-gray-200'
                                            }`}>
                                            {alert.alert}
                                            <span className="text-gray-400 font-normal ml-2 text-sm">
                                                ({alert.occurrences} {alert.occurrences === 1 ? t('occurrences') : t('occurrencesPlural')})
                                            </span>
                                        </h3>

                                        <div className="flex gap-2 mt-1">
                                            {alert.sourceid === 'nuclei' ? (
                                                <span className="text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold bg-yellow-500/20 text-yellow-400 border-yellow-500/30 w-fit">
                                                    Nuclei Recon
                                                </span>
                                            ) : (
                                                <span className="text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold bg-purple-500/20 text-purple-400 border-purple-500/30 w-fit">
                                                    ZAP Scanner
                                                </span>
                                            )}
                                        </div>
                                    </div>

                                    <div className="flex gap-2 items-center">
                                        <button
                                            onClick={() => handleCopyJira(alert)}
                                            className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-white/5 border border-white/10 hover:bg-white/10 transition-colors text-gray-300"
                                            title="Copiar Ticket (Jira/Markdown)"
                                        >
                                            {copiedId === alert.alert ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                                            {copiedId === alert.alert ? 'Copiado!' : t('copyTicket')}
                                        </button>
                                    </div>
                                </div>

                                <p className="text-xs text-gray-400 mt-2">{alert.description}</p>
                                {alert.remediations?.[0] && (
                                    <div className="mt-3 bg-black/40 p-3 rounded border border-white/5 text-xs">
                                        <p className="text-cyber-secondary font-bold mb-1">Recomendação:</p>
                                        <p className="text-gray-300">{alert.remediations[0].recommendation}</p>
                                    </div>
                                )}
                            </div>
                        ))}

                        {viewMode === 'coverage' && coverage && (
                            <div className="space-y-2">
                                {coverage.map((item, idx) => (
                                    <div key={idx} className="flex justify-between items-center p-3 bg-white/5 rounded border border-white/5">
                                        <span className="text-sm text-gray-300">{item.name}</span>
                                        <span className={`text-xs px-2 py-1 rounded font-bold ${item.status === 'pass' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
                                            {item.status.toUpperCase()}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Master Key Modal */}
            {showKeyModal && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-cyber-panel border border-white/10 rounded-lg p-6 max-w-md w-full space-y-4">
                        <div className="flex justify-between items-center border-b border-white/10 pb-3">
                            <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                <Key className="w-5 h-5 text-cyber-primary" />
                                {t('masterKeyRequiredTitle')}
                            </h3>
                            <button onClick={() => setShowKeyModal(false)} className="text-gray-400 hover:text-white">
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <p className="text-xs text-gray-300 leading-relaxed">
                            {t('masterKeyRequiredDesc')}
                        </p>

                        <form onSubmit={handleSaveKey} className="space-y-4">
                            <div>
                                <label className="block text-xs font-bold text-gray-400 mb-1">{t('enterMasterKey')}</label>
                                <input
                                    type="password"
                                    placeholder="••••••••••••••••"
                                    className="w-full bg-black/40 border border-white/10 rounded p-3 text-white text-sm focus:border-cyber-primary outline-none"
                                    value={masterKeyInput}
                                    onChange={e => setMasterKeyInput(e.target.value)}
                                    required
                                />
                            </div>

                            <div className="flex gap-2">
                                <button type="submit" className="flex-1 bg-cyber-primary text-black font-bold py-2 rounded hover:bg-white text-xs transition-colors">
                                    {t('saveMasterKey')}
                                </button>
                                {isAdmin && (
                                    <button type="button" onClick={handleClearKey} className="px-3 py-2 bg-red-500/20 text-red-400 rounded text-xs hover:bg-red-500/30">
                                        {t('clearMasterKey')}
                                    </button>
                                )}
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Scan History Drawer */}
            {showHistoryDrawer && (
                <div className="fixed inset-y-0 right-0 w-80 bg-cyber-panel border-l border-white/10 z-50 p-6 flex flex-col space-y-4 shadow-2xl">
                    <div className="flex justify-between items-center border-b border-white/10 pb-3">
                        <h3 className="font-bold text-white flex items-center gap-2">
                            <History className="w-5 h-5 text-cyber-secondary" />
                            {t('scanHistory')}
                        </h3>
                        <button onClick={() => setShowHistoryDrawer(false)} className="text-gray-400 hover:text-white">
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    <div className="flex-1 overflow-y-auto space-y-3">
                        {savedHistory.length === 0 && (
                            <p className="text-xs text-gray-500 italic">Nenhum scan salvo no histórico local.</p>
                        )}

                        {savedHistory.map((item, idx) => (
                            <div
                                key={idx}
                                onClick={() => loadHistoricalScan(item)}
                                className="p-3 bg-white/5 border border-white/5 rounded hover:border-cyber-primary cursor-pointer transition-colors"
                            >
                                <p className="text-xs font-bold text-white truncate">{item.target_url}</p>
                                <div className="flex justify-between items-center mt-2 text-[10px] text-gray-400">
                                    <span className="uppercase font-mono text-cyber-secondary">{item.scan_type}</span>
                                    <span>{item.total_alerts || item.alerts?.length || 0} alertas</span>
                                </div>
                                <p className="text-[9px] text-gray-500 mt-1">{new Date(item.created_at || Date.now()).toLocaleString()}</p>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
