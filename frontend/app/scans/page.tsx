'use client';

import { Zap, Play, Activity, ShieldCheck, FileDown, Copy, Check } from 'lucide-react';
import { useState, useEffect } from 'react';
import { startSpiderScan, startActiveScan, checkScanStatus, getScanResults, saveScanHistory, startNucleiScan, checkNucleiStatus, getNucleiResults } from '@/lib/api';
import { exportScanResultsCSV, exportScanResultsPDF } from '@/lib/export';

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
    const [targetUrl, setTargetUrl] = useState('');
    const [scanType, setScanType] = useState('spider');
    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const [results, setResults] = useState<ScanAlert[] | null>(null);
    const [coverage, setCoverage] = useState<CoverageItem[] | null>(null);
    const [triage, setTriage] = useState<ScanTriage | null>(null);
    const [riskFilter, setRiskFilter] = useState('ALL');
    const [viewMode, setViewMode] = useState<'alerts' | 'coverage'>('alerts');
    const [sourceFilter, setSourceFilter] = useState<'ALL' | 'STATIC' | 'DYNAMIC'>('ALL');
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const [isAdmin, setIsAdmin] = useState(false);

    useEffect(() => {
        setIsAdmin(!!localStorage.getItem('admin_api_key'));
    }, []);

    const addLog = (msg: string) => setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!targetUrl) return;

        setScanStatus({ status: 'starting', progress: 0 });
        setLogs([]);
        setResults(null);
        setCoverage(null);
        setTriage(null);
        addLog(`Iniciando Scan (${scanType === 'spider' ? 'Passivo/Spider' : 'Ativo'}) em: ${targetUrl}`);

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

                // Show real-time activity in logs
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
                    // Save history
                    try {
                        addLog('Salvando histórico de vulnerabilidades...');
                        if (type === 'nuclei' && resultsData?.alerts) {
                            await saveScanHistory(targetUrl, type, resultsData.alerts);
                        } else {
                            await saveScanHistory(targetUrl, type);
                        }
                        addLog('Histórico salvo com sucesso!');
                    } catch (err) {
                        addLog('Falha ao salvar o histórico. O alvo está cadastrado no sistema?');
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
                // Transform Nuclei format into ZAP format for UI compatibility
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
                        report_text: alert.info?.description || ''
                    }]
                }));
                data = { alerts: transformedAlerts, coverage: [], triage: null };
            } else {
                data = await getScanResults(targetUrl);
            }
            
            setResults(data.alerts || []);
            setCoverage(data.coverage || []);
            setTriage(data.triage || null);
            addLog(`${data.alerts?.length || 0} alertas encontrados.`);
            return data;
        } catch {
            addLog('Falha ao carregar resultados.');
            return null;
        }
    };

    const filteredResults = results?.filter((alert) => {
        // Filter by Risk
        if (riskFilter !== 'ALL' && alert.risk.toUpperCase() !== riskFilter) return false;

        // Filter by Source
        if (sourceFilter === 'STATIC') {
            return alert.sourceid === 'static_analysis';
        }
        if (sourceFilter === 'DYNAMIC') {
            return alert.sourceid !== 'static_analysis';
        }

        return true;
    });

    const groupedResults = Object.values(
        (filteredResults || []).reduce((acc: Record<string, any>, alert: ScanAlert) => {
            const key = alert.alert;
            if (!acc[key]) {
                acc[key] = {
                    ...alert,
                    occurrences: 1,
                    urls: [alert.url],
                };
            } else {
                acc[key].occurrences += 1;
                if (!acc[key].urls.includes(alert.url)) {
                    acc[key].urls.push(alert.url);
                }
            }
            return acc;
        }, {})
    ).sort((a: any, b: any) => b.occurrences - a.occurrences);

    const handleCopyJira = (alert: any) => {
        const remediation = alert.remediations?.[0];
        
        const text = `h1. [Vulnerabilidade] ${alert.alert}

*Gravidade:* ${alert.risk}
*Origem:* ${alert.sourceid === 'static_analysis' ? 'Análise Estática' : 'ZAP Scanner'}
*Afeta:* ${alert.occurrences} ocorrência(s) (${alert.urls.length} URLs únicas)
*Exemplo URL:* ${alert.method} ${alert.urls[0]}

h2. Descrição
${alert.description}

h2. Solução Recomendada
${remediation?.recommendation || 'Consultar documentação técnica.'}
${remediation?.why_it_matters ? `\n*Por que importa:* ${remediation.why_it_matters}` : ''}

h2. Evidência
${remediation?.evidence || alert.evidence || 'N/A'}
`;
        
        const copyToClipboard = () => {
            if (navigator.clipboard && window.isSecureContext) {
                return navigator.clipboard.writeText(text);
            } else {
                return new Promise<void>((resolve, reject) => {
                    const textArea = document.createElement("textarea");
                    textArea.value = text;
                    textArea.style.position = "fixed";
                    textArea.style.left = "-999999px";
                    textArea.style.top = "-999999px";
                    document.body.appendChild(textArea);
                    textArea.focus();
                    textArea.select();
                    try {
                        document.execCommand('copy');
                        resolve();
                    } catch (error) {
                        reject(error);
                    } finally {
                        textArea.remove();
                    }
                });
            }
        };

        copyToClipboard().then(() => {
            setCopiedId(alert.alert);
            setTimeout(() => setCopiedId(null), 2000);
        }).catch(err => {
            console.error('Falha ao copiar:', err);
            alert('Falha ao copiar. Verifique as permissões do navegador.');
        });
    };

    return (
        <div className="p-8 space-y-8 h-full flex flex-col">
            <header className="flex justify-between items-end border-b border-white/10 pb-6 shrink-0">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
                        <Zap className="w-8 h-8 text-yellow-400" />
                        Centro de Scan Avançado
                    </h1>
                    <p className="text-gray-400 mt-2">Análise profunda de vulnerabilidades (DAST)</p>
                </div>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 flex-1 min-h-0">
                <div className="space-y-6">
                    <div className="glass-panel p-6 rounded-lg">
                        <h2 className="text-xl font-bold mb-4 flex items-center gap-2 text-white">
                            <Play className="w-5 h-5 text-cyber-primary" /> Configuração
                        </h2>
                        <form onSubmit={handleScan} className="space-y-4">
                            <div>
                                <label className="block text-xs font-bold text-gray-400 mb-1 uppercase">URL do Alvo</label>
                                <input
                                    type="url"
                                    required
                                    placeholder="http://loja-teste.com"
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
                                        className={`p-3 rounded border text-sm font-bold transition-colors ${scanType === 'nuclei'
                                            ? 'bg-blue-500/20 border-blue-500 text-blue-400'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:bg-white/10'
                                            }`}
                                    >
                                        ⚡ Recon (Nuclei)
                                        <span className="block text-[10px] font-normal opacity-70 mt-1">Footprint & CVEs</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setScanType('spider')}
                                        className={`p-3 rounded border text-sm font-bold transition-colors ${scanType === 'spider'
                                            ? 'bg-cyber-primary/20 border-cyber-primary text-cyber-primary'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:bg-white/10'
                                            }`}
                                    >
                                        🕷️ Spider (Passivo)
                                        <span className="block text-[10px] font-normal opacity-70 mt-1">Mapeamento & Estrutura</span>
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            if (isAdmin) setScanType('active');
                                            else alert('O Active Scan (Intrusivo) está desabilitado para visitantes por segurança. Use a Master API Key.');
                                        }}
                                        className={`p-3 rounded border text-sm font-bold transition-colors ${!isAdmin ? 'opacity-50 cursor-not-allowed bg-white/5 border-white/10 text-gray-500' : scanType === 'active'
                                            ? 'bg-red-500/20 border-red-500 text-red-500'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:bg-white/10'
                                            }`}
                                    >
                                        🔥 Active (Intrusivo)
                                        <span className="block text-[10px] font-normal opacity-70 mt-1">{!isAdmin ? 'Restrito' : 'Ataques Simulados'}</span>
                                    </button>
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={(scanStatus && scanStatus.status !== 'completed') || !targetUrl || (!isAdmin && scanType === 'active')}
                                className="w-full bg-cyber-primary text-black font-bold py-3 rounded hover:bg-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {scanStatus && scanStatus.status === 'scanning' ? 'ESCANEANDO...' : 'INICIAR SCAN'}
                            </button>
                        </form>
                    </div>

                    <div className="glass-panel p-6 rounded-lg flex flex-col h-[300px]">
                        <h2 className="text-sm font-bold mb-4 flex items-center gap-2 text-gray-400 uppercase tracking-wider">
                            <Activity className="w-4 h-4" /> Logs de Execução
                        </h2>
                        <div className="bg-black/50 rounded flex-1 p-4 font-mono text-xs text-green-400 overflow-y-auto space-y-1 border border-white/5">
                            {logs.length === 0 && <span className="text-gray-600 italic">Aguardando comando...</span>}
                            {logs.map((log, i) => (
                                <div key={i}>{log}</div>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="lg:col-span-2 glass-panel p-6 rounded-lg flex flex-col min-h-0">
                    <div className="flex flex-col mb-6 gap-4">
                        <div className="flex justify-between items-center">
                            <div className="flex items-center gap-4">
                                <h2 className="text-xl font-bold flex items-center gap-2 text-white">
                                    <ShieldCheck className="w-5 h-5 text-cyber-secondary" />
                                    {viewMode === 'alerts' ? 'Vulnerabilidades' : 'Relatório de Cobertura'}
                                </h2>
                        {results && (
                            <div className="flex items-center gap-2 flex-wrap">
                                <div className="flex bg-white/5 rounded p-1">
                                    <button
                                        onClick={() => setViewMode('alerts')}
                                        className={`px-3 py-1 text-xs font-bold rounded transition-colors ${viewMode === 'alerts' ? 'bg-cyber-primary text-black' : 'text-gray-400 hover:text-white'}`}
                                    >Alertas</button>
                                    <button
                                        onClick={() => setViewMode('coverage')}
                                        className={`px-3 py-1 text-xs font-bold rounded transition-colors ${viewMode === 'coverage' ? 'bg-cyber-primary text-black' : 'text-gray-400 hover:text-white'}`}
                                    >Cobertura {(coverage?.length ?? 0) > 0 && `(${coverage?.length ?? 0})`}</button>
                                </div>
                                <button
                                    onClick={() => exportScanResultsCSV(results, triage as ScanTriage)}
                                    className="flex items-center gap-1 px-3 py-1 text-xs font-bold text-gray-300 bg-white/5 border border-white/10 rounded hover:bg-white/10 transition-colors"
                                >
                                    <FileDown className="w-3 h-3" />
                                    CSV
                                </button>
                                <button
                                    onClick={() => exportScanResultsPDF(results, triage as ScanTriage, coverage as CoverageItem[])}
                                    className="flex items-center gap-1 px-3 py-1 text-xs font-bold text-gray-300 bg-white/5 border border-white/10 rounded hover:bg-white/10 transition-colors"
                                >
                                    <FileDown className="w-3 h-3" />
                                    PDF
                                </button>
                            </div>
                        )}
                            </div>

                            {scanStatus && (
                                <div className="flex items-center gap-3">
                                    <div className="text-right">
                                        <p className="text-xs text-gray-400 uppercase">Progresso</p>
                                        <p className="text-xl font-bold text-cyber-primary">{scanStatus.progress}%</p>
                                    </div>
                                    <div className="w-12 h-12 relative flex items-center justify-center">
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle cx="24" cy="24" r="20" stroke="currentColor" strokeWidth="4" fill="transparent" className="text-white/10" />
                                            <circle cx="24" cy="24" r="20" stroke="currentColor" strokeWidth="4" fill="transparent" className="text-cyber-primary transition-all duration-500"
                                                strokeDasharray={125.6} strokeDashoffset={125.6 - (125.6 * scanStatus.progress) / 100}
                                            />
                                        </svg>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Filters Row */}
                        {(viewMode === 'alerts' && results) && (
                            <div className="flex flex-wrap gap-4 items-center bg-white/5 p-3 rounded-lg border border-white/5">
                                <div className="flex items-center gap-2">
                                    <span className="text-[10px] uppercase font-bold text-gray-500">Gravidade:</span>
                                    <div className="flex gap-1">
                                        {['ALL', 'High', 'Medium', 'Low'].map(level => (
                                            <button
                                                key={level}
                                                onClick={() => setRiskFilter(level === 'ALL' ? 'ALL' : level.toUpperCase())}
                                                className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors border ${(riskFilter === level.toUpperCase() || (riskFilter === 'ALL' && level === 'ALL'))
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
                                            Todas
                                        </button>
                                        <button
                                            onClick={() => setSourceFilter('STATIC')}
                                            className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors border ${sourceFilter === 'STATIC'
                                                ? 'bg-blue-400 text-black border-blue-400'
                                                : 'bg-transparent text-gray-500 border-white/10 hover:border-white/30'
                                                }`}
                                        >
                                            Estática (DB)
                                        </button>
                                        <button
                                            onClick={() => setSourceFilter('DYNAMIC')}
                                            className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-colors border ${sourceFilter === 'DYNAMIC'
                                                ? 'bg-purple-400 text-black border-purple-400'
                                                : 'bg-transparent text-gray-500 border-white/10 hover:border-white/30'
                                                }`}
                                        >
                                            Dinâmica (ZAP)
                                        </button>
                                    </div>
                                </div>
                            </div>
                        )}

                        {(viewMode === 'alerts' && triage) && (
                            <div className="bg-cyber-primary/10 border border-cyber-primary/20 rounded-lg p-4">
                                {triage.analyst_note && <p className="text-sm text-gray-200">{triage.analyst_note}</p>}
                                {(triage.risk_groups?.length ?? 0) > 0 && (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                                        {triage.risk_groups?.map((group) => (
                                            <div key={group.root_cause} className="bg-black/30 border border-white/10 rounded p-3">
                                                <div className="flex items-center justify-between gap-2">
                                                    <span className="text-xs font-bold text-white">{group.root_cause}</span>
                                                    <span className="text-[10px] uppercase text-gray-400">{group.count} · {group.highest_severity}</span>
                                                </div>
                                                <p className="text-[11px] text-gray-500 mt-2">{group.next_step}</p>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    <div className="flex-1 overflow-y-auto pr-2 space-y-3">
                        {!results && !scanStatus && (
                            <div className="h-full flex flex-col items-center justify-center text-gray-500 opacity-50">
                                <Zap className="w-16 h-16 mb-4" />
                                <p>Configure um scan para ver os resultados aqui.</p>
                            </div>
                        )}

                        {viewMode === 'alerts' && results && results.length === 0 && (
                            <div className="h-full flex items-center justify-center text-green-500">
                                <ShieldCheck className="w-12 h-12 mr-2" /> Nenhum alerta vulnerável encontrado.
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
                                                ({alert.occurrences} {alert.occurrences === 1 ? 'ocorrência' : 'ocorrências'})
                                            </span>
                                        </h3>

                                        <div className="flex gap-2 mt-1">
                                            {alert.sourceid === 'static_analysis' ? (
                                                <span className="text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold bg-blue-500/20 text-blue-400 border-blue-500/30 w-fit">
                                                    Static Analysis
                                                </span>
                                            ) : alert.sourceid === 'nuclei' ? (
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
                                            {copiedId === alert.alert ? 'Copiado!' : 'Copiar Ticket'}
                                        </button>
                                        <span className={`text-xs px-2 py-1 rounded border uppercase font-bold ${alert.risk === 'High' ? 'bg-red-500/20 text-red-500 border-red-500/30' :
                                            alert.risk === 'Medium' ? 'bg-orange-500/20 text-orange-500 border-orange-500/30' :
                                                'bg-blue-500/20 text-blue-500 border-blue-500/30'
                                            }`}>
                                            {alert.risk}
                                        </span>
                                    </div>
                                </div>
                                <p className="text-sm text-gray-300 mt-2">{alert.description}</p>
                                <div className="mt-3 text-xs text-gray-500 font-mono bg-black/30 p-2 rounded max-w-full overflow-hidden">
                                    <div><span className="font-bold text-gray-400">Exemplo Afetado:</span> {alert.method} {alert.urls[0]}</div>
                                    {alert.urls.length > 1 && (
                                        <div className="mt-2 pt-2 border-t border-white/5 text-cyber-primary cursor-pointer hover:underline">
                                            + {alert.urls.length - 1} URLs similares afetadas. Copie o ticket para ver tudo.
                                        </div>
                                    )}
                                </div>
                                {(alert.remediations?.length ?? 0) > 0 && (
                                    <div className="mt-4 space-y-3">
                                        {(alert.remediations ?? []).map((item: AlertRemediation, idx: number) => (
                                            <div key={idx} className="bg-black/30 border border-white/10 rounded p-3">
                                                <div className="flex flex-wrap justify-between gap-2 mb-2">
                                                    <h4 className="text-sm font-bold text-cyber-secondary">{item.title}</h4>
                                                    <span className="text-[10px] uppercase text-gray-400 border border-white/10 rounded px-2 py-1">
                                                        {item.category} · {item.confidence}
                                                    </span>
                                                </div>
                                                <p className="text-xs text-gray-300">{item.recommendation}</p>
                                                <p className="text-xs text-gray-500 mt-2">{item.evidence}</p>
                                                <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
                                                    <div className="bg-white/5 rounded p-2">
                                                        <p className="text-[11px] text-gray-400">Confiança</p>
                                                        <p className="text-xs text-gray-300">{item.confidence}</p>
                                                        {item.confidence_reason && <p className="text-[11px] text-gray-500 mt-1">{item.confidence_reason}</p>}
                                                    </div>
                                                    {item.next_step && (
                                                        <div className="bg-white/5 rounded p-2">
                                                            <p className="text-[11px] text-gray-400">Próximo passo</p>
                                                            <p className="text-xs text-cyber-secondary">{item.next_step}</p>
                                                        </div>
                                                    )}
                                                </div>
                                                {(item.snippets?.nginx || item.snippets?.apache) && (
                                                    <div className="grid grid-cols-1 xl:grid-cols-2 gap-2 mt-3">
                                                        {item.snippets?.nginx && (
                                                            <pre className="bg-black/50 border border-white/10 rounded p-2 text-[11px] text-gray-300 overflow-x-auto"><code>{item.snippets.nginx}</code></pre>
                                                        )}
                                                        {item.snippets?.apache && (
                                                            <pre className="bg-black/50 border border-white/10 rounded p-2 text-[11px] text-gray-300 overflow-x-auto"><code>{item.snippets.apache}</code></pre>
                                                        )}
                                                    </div>
                                                )}
                                                <div className="mt-3 bg-white/5 rounded p-2 text-[11px] text-gray-400 leading-relaxed">
                                                    {item.report_sections ? (
                                                        <div className="space-y-1">
                                                            <p><b>Risco:</b> {item.report_sections.risk}</p>
                                                            <p><b>Evidência:</b> {item.report_sections.evidence}</p>
                                                            <p><b>Impacto:</b> {item.report_sections.impact}</p>
                                                            <p><b>Recomendação:</b> {item.report_sections.recommendation}</p>
                                                        </div>
                                                    ) : item.report_text}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ))}

                        {viewMode === 'coverage' && (
                            <div className="space-y-2">
                                {coverage && coverage.map((item, i) => (
                                    <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded border border-white/5 hover:border-white/10 transition-colors">
                                        <span className="text-sm text-gray-300 font-medium">{item.name}</span>
                                        <div className="flex items-center gap-3">
                                            {item.cwe && <span className="text-[10px] text-gray-500 font-mono">CWE-{item.cwe}</span>}
                                            {item.status === 'pass' ? (
                                                <span className="text-xs font-bold text-green-500 bg-green-500/10 px-2 py-1 rounded border border-green-500/20 flex items-center gap-1">
                                                    PASS
                                                </span>
                                            ) : (
                                                <span className="text-xs font-bold text-red-500 bg-red-500/10 px-2 py-1 rounded border border-red-500/20 flex items-center gap-1">
                                                    FAIL
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                ))}
                                {!coverage && (
                                    <div className="text-center text-gray-500 py-10 italic">
                                        Detalhes de cobertura indisponíveis para este scan.
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
