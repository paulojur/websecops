'use client';

import { Zap, Play, Activity, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { startSpiderScan, startActiveScan, checkScanStatus, getScanResults } from '@/lib/api';

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
    evidence: string;
    recommendation: string;
    report_text: string;
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

export default function ScansPage() {
    const [targetUrl, setTargetUrl] = useState('');
    const [scanType, setScanType] = useState('spider');
    const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
    const [logs, setLogs] = useState<string[]>([]);
    const [results, setResults] = useState<ScanAlert[] | null>(null);
    const [coverage, setCoverage] = useState<CoverageItem[] | null>(null);
    const [riskFilter, setRiskFilter] = useState('ALL');
    const [viewMode, setViewMode] = useState<'alerts' | 'coverage'>('alerts');

    const [sourceFilter, setSourceFilter] = useState<'ALL' | 'STATIC' | 'DYNAMIC'>('ALL');

    const addLog = (msg: string) => setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev]);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!targetUrl) return;

        setScanStatus({ status: 'starting', progress: 0 });
        setLogs([]);
        setResults(null);
        setCoverage(null);
        addLog(`Iniciando Scan (${scanType === 'spider' ? 'Passivo/Spider' : 'Ativo'}) em: ${targetUrl}`);

        try {
            let data;
            if (scanType === 'spider') {
                data = await startSpiderScan(targetUrl);
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
                const data = await checkScanStatus(type, id);
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
                    loadResults();
                }
            } catch (e) {
                console.error(e);
                clearInterval(interval);
            }
        }, 5000);
    };

    const loadResults = async () => {
        try {
            addLog('Buscando resultados...');
            const data = await getScanResults(targetUrl);
            setResults(data.alerts || []);
            setCoverage(data.coverage || []);
            addLog(`${data.alerts?.length || 0} alertas encontrados.`);
        } catch {
            addLog('Falha ao carregar resultados.');
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
                                <div className="grid grid-cols-2 gap-2">
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
                                        onClick={() => setScanType('active')}
                                        className={`p-3 rounded border text-sm font-bold transition-colors ${scanType === 'active'
                                            ? 'bg-red-500/20 border-red-500 text-red-500'
                                            : 'bg-white/5 border-white/10 text-gray-400 hover:bg-white/10'
                                            }`}
                                    >
                                        🔥 Active (Intrusivo)
                                        <span className="block text-[10px] font-normal opacity-70 mt-1">Ataques Simulados</span>
                                    </button>
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={!!scanStatus || !targetUrl}
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

                        {viewMode === 'alerts' && filteredResults && filteredResults.map((alert, i) => (
                            <div key={i} className={`bg-white/5 border-l-4 p-4 rounded-r ${alert.risk === 'High' ? 'border-red-500' :
                                alert.risk === 'Medium' ? 'border-orange-500' :
                                    alert.risk === 'Low' ? 'border-yellow-500' : 'border-blue-500'
                                }`}>
                                <div className="flex justify-between items-start">
                                    <div className="flex flex-col gap-1">
                                        <h3 className={`font-bold ${alert.risk === 'High' ? 'text-red-400' :
                                            alert.risk === 'Medium' ? 'text-orange-400' : 'text-gray-200'
                                            }`}>{alert.alert}</h3>

                                        {/* Source Badge */}
                                        <div className="flex gap-2 mt-1">
                                            {alert.sourceid === 'static_analysis' ? (
                                                <span className="text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold bg-blue-500/20 text-blue-400 border-blue-500/30 w-fit">
                                                    Static Analysis
                                                </span>
                                            ) : (
                                                <span className="text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold bg-purple-500/20 text-purple-400 border-purple-500/30 w-fit">
                                                    ZAP Scanner
                                                </span>
                                            )}
                                        </div>
                                    </div>

                                    <span className={`text-xs px-2 py-1 rounded border uppercase font-bold ${alert.risk === 'High' ? 'bg-red-500/20 text-red-500 border-red-500/30' :
                                        alert.risk === 'Medium' ? 'bg-orange-500/20 text-orange-500 border-orange-500/30' :
                                            'bg-blue-500/20 text-blue-500 border-blue-500/30'
                                        }`}>
                                        {alert.risk}
                                    </span>
                                </div>
                                <p className="text-sm text-gray-300 mt-2">{alert.description}</p>
                                <div className="mt-3 text-xs text-gray-500 font-mono bg-black/30 p-2 rounded truncate max-w-full">
                                    {alert.method} {alert.url}
                                </div>
                                {(alert.remediations?.length ?? 0) > 0 && (
                                    <div className="mt-4 space-y-3">
                                        {(alert.remediations ?? []).map((item, idx) => (
                                            <div key={idx} className="bg-black/30 border border-white/10 rounded p-3">
                                                <div className="flex flex-wrap justify-between gap-2 mb-2">
                                                    <h4 className="text-sm font-bold text-cyber-secondary">{item.title}</h4>
                                                    <span className="text-[10px] uppercase text-gray-400 border border-white/10 rounded px-2 py-1">
                                                        {item.category} · {item.confidence}
                                                    </span>
                                                </div>
                                                <p className="text-xs text-gray-300">{item.recommendation}</p>
                                                <p className="text-xs text-gray-500 mt-2">{item.evidence}</p>
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
                                                    {item.report_text}
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
