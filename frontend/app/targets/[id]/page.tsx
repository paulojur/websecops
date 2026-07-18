'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ShieldAlert, ArrowLeft, Loader2, AlertTriangle, ExternalLink, ClipboardList, Wrench, FileDown } from 'lucide-react';
import { getTargetCorrelations, getTargetHistory } from '@/lib/api';
import { exportTargetCorrelationsCSV, exportTargetCorrelationsPDF } from '@/lib/export';
import Link from 'next/link';
import { getAppMode, getDemoTarget } from '@/lib/demo-targets';

type TechnologyInfo = {
    version?: string;
    category?: string;
};

type Remediation = {
    title: string;
    severity: string;
    confidence: string;
    confidence_reason?: string;
    category: string;
    root_cause?: string;
    evidence: string;
    evidence_items?: Array<{
        source: string;
        detail: string;
    }>;
    why_it_matters: string;
    recommendation: string;
    next_step?: string;
    snippets?: {
        nginx?: string;
        apache?: string;
    };
    report_sections?: {
        risk: string;
        evidence: string;
        impact: string;
        recommendation: string;
        next_step: string;
    };
    report_text: string;
};

type Correlation = {
    cve_id: string;
    description: string;
    correlation_reason?: string;
    remediation?: Remediation;
};

type SummaryItem = {
    id: string;
    severity: string;
    score?: number;
    confidence?: string;
    reason: string;
    next_step?: string;
};

type RiskGroup = {
    root_cause: string;
    count: number;
    highest_severity: string;
    next_step: string;
};

type TargetDetailsData = {
    target: {
        url: string;
        created_at?: string;
        technologies?: Record<string, TechnologyInfo | string>;
    };
    correlations: Correlation[];
    hardening?: Remediation[];
    summary?: {
        total: number;
        analyst_note?: string;
        severity_counts?: Record<string, number>;
        risk_groups?: RiskGroup[];
        top_risks: SummaryItem[];
    };
};

export default function TargetDetailsPage() {
    const params = useParams();
    const router = useRouter();
    const id = params?.id as string;
    
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [data, setData] = useState<TargetDetailsData | null>(null);
    const [history, setHistory] = useState<any[]>([]);
    const [appMode, setAppMode] = useState<'live' | 'demo'>('live');

    useEffect(() => {
        if (!id) return;

        const fetchData = async () => {
            try {
                setLoading(true);
                const mode = getAppMode();
                setAppMode(mode);

                if (mode === 'demo') {
                    const demoTarget = getDemoTarget(parseInt(id));
                    if (!demoTarget) {
                        throw new Error('Alvo local nao encontrado no modo demo.');
                    }

                    setData({
                        target: {
                            url: demoTarget.url,
                            created_at: demoTarget.created_at,
                            technologies: demoTarget.technologies,
                        },
                        correlations: demoTarget.correlations,
                        hardening: demoTarget.hardening,
                        summary: demoTarget.summary,
                    });
                    return;
                }

                const result = await getTargetCorrelations(parseInt(id));
                setData(result);
                
                try {
                    const hist = await getTargetHistory(parseInt(id));
                    setHistory(hist);
                } catch (e) {
                    console.error("No history available or error", e);
                }
            } catch (err: unknown) {
                setError(err instanceof Error ? err.message : 'Erro ao carregar detalhes do alvo.');
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [id]);

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center min-h-[60vh] text-cyber-primary">
                <Loader2 className="w-12 h-12 animate-spin mb-4" />
                <h2 className="text-xl font-bold">Buscando CVEs em tempo real...</h2>
                <p className="text-gray-400 mt-2">{appMode === 'demo' ? 'Lendo o demo local salvo no navegador.' : `Consultando a API do NVD para o alvo ${id}`}</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="p-8 text-center">
                <div className="text-red-500 mb-4 flex justify-center">
                    <AlertTriangle className="w-16 h-16" />
                </div>
                <h2 className="text-2xl font-bold text-white mb-2">Erro na Busca</h2>
                <p className="text-gray-400 mb-6">{error}</p>
                <button onClick={() => router.back()} className="px-6 py-2 bg-white/10 hover:bg-white/20 rounded transition-colors text-white font-bold">
                    Voltar
                </button>
            </div>
        );
    }

    if (!data) return null;

    const { target, correlations } = data;
    const hardening = data.hardening || [];
    const summary = data.summary || { total: correlations.length, top_risks: [], risk_groups: [] };

    const formatTechnologyValue = (value: TechnologyInfo | string) => {
        if (typeof value === 'object' && value !== null) {
            const parts = [value.version, value.category].filter(Boolean);
            return parts.join(' · ');
        }

        return String(value ?? '');
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* Header */}
            <div className="flex items-center gap-4 border-b border-white/10 pb-6">
                <Link href="/targets" className="p-2 bg-white/5 hover:bg-white/10 rounded transition-colors">
                    <ArrowLeft className="w-6 h-6 text-gray-300" />
                </Link>
                <div>
                    <h1 className="text-3xl font-black text-white flex items-center gap-3">
                        ALVO: <span className="text-cyber-primary">{target.url}</span>
                    </h1>
                    {target.created_at && (
                        <p className="text-gray-400 mt-1">
                            Adicionado em {new Date(target.created_at).toLocaleString()}
                        </p>
                    )}
                </div>
            </div>

            {/* Tecnologias */}
            <div className="bg-black/40 border border-white/10 p-6 rounded-lg">
                <h2 className="text-xl font-bold text-white mb-4">Tecnologias Detectadas</h2>
                <div className="flex flex-wrap gap-3">
                    {Object.entries(target.technologies || {}).map(([key, val]) => {
                        const displayValue = formatTechnologyValue(val);

                        return (
                            <div key={key} className="bg-white/5 px-4 py-2 rounded border border-white/10 flex items-center gap-2">
                                <span className="text-gray-400 text-sm">{key}:</span>
                                <span className="text-cyber-secondary font-bold">{displayValue || 'Sem detalhes'}</span>
                            </div>
                        );
                    })}
                    {Object.keys(target.technologies || {}).length === 0 && (
                        <p className="text-gray-500 italic">Nenhuma tecnologia identificada.</p>
                    )}
                </div>
            </div>

            {/* Histórico de Scans */}
            {appMode === 'live' && history.length > 0 && (
                <div className="bg-black/40 border border-white/10 p-6 rounded-lg">
                    <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                        <ClipboardList className="w-5 h-5 text-cyber-secondary" />
                        Histórico de Scans (DAST)
                    </h2>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-white/5 text-gray-400">
                                <tr>
                                    <th className="px-4 py-3 rounded-tl">Data do Scan</th>
                                    <th className="px-4 py-3">Tipo</th>
                                    <th className="px-4 py-3">Críticos</th>
                                    <th className="px-4 py-3">Altos</th>
                                    <th className="px-4 py-3 rounded-tr">Médios</th>
                                </tr>
                            </thead>
                            <tbody>
                                {history.map((h: any) => (
                                    <tr key={h.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                                        <td className="px-4 py-3 text-gray-300">{new Date(h.created_at).toLocaleString()}</td>
                                        <td className="px-4 py-3 font-mono text-xs uppercase text-cyber-secondary">{h.scan_type}</td>
                                        <td className="px-4 py-3 font-bold text-red-500">{h.summary?.CRITICAL || 0}</td>
                                        <td className="px-4 py-3 font-bold text-orange-500">{h.summary?.HIGH || 0}</td>
                                        <td className="px-4 py-3 font-bold text-yellow-500">{h.summary?.MEDIUM || 0}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Vulnerabilidades */}
            <div>
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                    <ShieldAlert className="w-6 h-6 text-cyber-primary" />
                    Riscos Priorizados ({summary.total})
                </h2>

                {summary.analyst_note && (
                    <div className="bg-cyber-primary/10 border border-cyber-primary/20 rounded-lg p-4 mb-4">
                        <p className="text-sm text-gray-200">{summary.analyst_note}</p>
                    </div>
                )}

                {(summary.risk_groups?.length ?? 0) > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-5">
                        {summary.risk_groups?.map((group) => (
                            <div key={group.root_cause} className="bg-white/5 border border-white/10 rounded-lg p-4">
                                <div className="flex items-center justify-between gap-2">
                                    <h3 className="text-sm font-bold text-white">{group.root_cause}</h3>
                                    <span className="text-[10px] uppercase text-gray-400 border border-white/10 rounded px-2 py-1">
                                        {group.count}
                                    </span>
                                </div>
                                <p className="text-xs text-gray-400 mt-2">{group.next_step}</p>
                            </div>
                        ))}
                    </div>
                )}

                {summary.top_risks?.length > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-5">
                        {summary.top_risks.map((item) => (
                            <div key={item.id} className="bg-white/5 border border-white/10 rounded-lg p-4">
                                <div className="flex items-center justify-between gap-3">
                                    <span className="text-cyber-primary font-bold">{item.id}</span>
                                    <span className="text-xs px-2 py-1 rounded border border-red-500/30 text-red-300 bg-red-500/10">
                                        {item.severity} {item.score ? `CVSS ${item.score}` : ''} {item.confidence ? `· ${item.confidence}` : ''}
                                    </span>
                                </div>
                                <p className="text-xs text-gray-400 mt-2">{item.reason}</p>
                                {item.next_step && <p className="text-xs text-gray-500 mt-2">Próximo passo: {item.next_step}</p>}
                            </div>
                        ))}
                    </div>
                )}
                
                {correlations.length === 0 ? (
                    <div className="bg-white/5 p-8 rounded-lg text-center border border-white/10">
                        <p className="text-gray-400 text-lg">Parabéns! Nenhuma CVE recente encontrada para as tecnologias deste alvo.</p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {correlations.map((vuln, index) => (
                            <div key={index} className="bg-black/40 border-l-4 border-cyber-primary p-6 rounded-r-lg hover:bg-white/5 transition-colors">
                                <div className="flex justify-between items-start mb-2">
                                    <h3 className="text-xl font-bold text-cyber-primary flex items-center gap-2">
                                        {vuln.cve_id}
                                        <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`} target="_blank" rel="noreferrer" className="opacity-50 hover:opacity-100 transition-opacity">
                                            <ExternalLink className="w-4 h-4" />
                                        </a>
                                    </h3>
                                </div>
                                <p className="text-xs text-gray-500 mb-3">{vuln.correlation_reason}</p>
                                <p className="text-gray-300 mb-4 leading-relaxed">{vuln.description}</p>

                                {vuln.remediation && (
                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-4">
                                        <div className="bg-white/5 border border-white/10 rounded p-4">
                                            <h4 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
                                                <Wrench className="w-4 h-4 text-cyber-secondary" />
                                                Como corrigir
                                            </h4>
                                            <p className="text-sm text-gray-300">{vuln.remediation.recommendation}</p>
                                            <p className="text-xs text-gray-500 mt-2">{vuln.remediation.why_it_matters}</p>
                                            <div className="mt-3 border-t border-white/10 pt-3 space-y-2">
                                                <p className="text-xs text-gray-400">Confiança: {vuln.remediation.confidence}</p>
                                                {vuln.remediation.confidence_reason && (
                                                    <p className="text-xs text-gray-500">{vuln.remediation.confidence_reason}</p>
                                                )}
                                                {vuln.remediation.next_step && (
                                                    <p className="text-xs text-cyber-secondary">Próximo passo: {vuln.remediation.next_step}</p>
                                                )}
                                            </div>
                                        </div>
                                        <div className="bg-black/50 border border-white/10 rounded p-4">
                                            <h4 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
                                                <ClipboardList className="w-4 h-4 text-cyber-primary" />
                                                Texto para relatório
                                            </h4>
                                            {vuln.remediation.report_sections ? (
                                                <div className="space-y-2 text-xs text-gray-300 leading-relaxed">
                                                    <p><b>Risco:</b> {vuln.remediation.report_sections.risk}</p>
                                                    <p><b>Evidência:</b> {vuln.remediation.report_sections.evidence}</p>
                                                    <p><b>Impacto:</b> {vuln.remediation.report_sections.impact}</p>
                                                    <p><b>Recomendação:</b> {vuln.remediation.report_sections.recommendation}</p>
                                                </div>
                                            ) : (
                                                <p className="text-xs text-gray-300 leading-relaxed">{vuln.remediation.report_text}</p>
                                            )}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Hardening */}
            {hardening.length > 0 && (
                <div className="bg-black/40 border border-white/10 p-6 rounded-lg">
                    <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                        <Wrench className="w-5 h-5 text-cyber-secondary" />
                        Hardening recomendado
                    </h2>
                    <div className="space-y-4">
                        {hardening.map((item, index) => (
                            <div key={index} className="bg-white/5 border border-white/10 rounded p-4">
                                <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                                    <h3 className="font-bold text-cyber-secondary">{item.title}</h3>
                                    <span className="text-[10px] uppercase text-gray-400 border border-white/10 rounded px-2 py-1">
                                        {item.category} · {item.confidence}
                                    </span>
                                </div>
                                <p className="text-sm text-gray-300 mb-3">{item.recommendation}</p>
                                {item.next_step && <p className="text-xs text-cyber-secondary mb-3">Próximo passo: {item.next_step}</p>}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                                    {item.snippets?.nginx && (
                                        <pre className="bg-black/50 border border-white/10 rounded p-3 text-xs text-gray-300 overflow-x-auto"><code>{item.snippets.nginx}</code></pre>
                                    )}
                                    {item.snippets?.apache && (
                                        <pre className="bg-black/50 border border-white/10 rounded p-3 text-xs text-gray-300 overflow-x-auto"><code>{item.snippets.apache}</code></pre>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
