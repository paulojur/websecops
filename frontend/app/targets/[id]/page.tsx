'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ShieldAlert, ArrowLeft, Loader2, AlertTriangle, ExternalLink } from 'lucide-react';
import { getTargetCorrelations } from '@/lib/api';
import Link from 'next/link';

export default function TargetDetailsPage() {
    const params = useParams();
    const router = useRouter();
    const id = params?.id as string;
    
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [data, setData] = useState<any>(null);

    useEffect(() => {
        if (!id) return;

        const fetchData = async () => {
            try {
                setLoading(true);
                const result = await getTargetCorrelations(parseInt(id));
                setData(result);
            } catch (err: any) {
                setError(err.message || 'Erro ao carregar detalhes do alvo.');
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
                <p className="text-gray-400 mt-2">Consultando a API do NVD para o alvo {id}</p>
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
                    <p className="text-gray-400 mt-1">
                        Adicionado em {new Date(target.created_at).toLocaleString()}
                    </p>
                </div>
            </div>

            {/* Tecnologias */}
            <div className="bg-black/40 border border-white/10 p-6 rounded-lg">
                <h2 className="text-xl font-bold text-white mb-4">Tecnologias Detectadas</h2>
                <div className="flex flex-wrap gap-3">
                    {Object.entries(target.technologies || {}).map(([key, val]: any) => (
                        <div key={key} className="bg-white/5 px-4 py-2 rounded border border-white/10 flex items-center gap-2">
                            <span className="text-gray-400 text-sm">{key}:</span>
                            <span className="text-cyber-secondary font-bold">{val}</span>
                        </div>
                    ))}
                    {Object.keys(target.technologies || {}).length === 0 && (
                        <p className="text-gray-500 italic">Nenhuma tecnologia identificada.</p>
                    )}
                </div>
            </div>

            {/* Vulnerabilidades */}
            <div>
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                    <ShieldAlert className="w-6 h-6 text-cyber-primary" />
                    Correlações CVE em Tempo Real ({correlations.length})
                </h2>
                
                {correlations.length === 0 ? (
                    <div className="bg-white/5 p-8 rounded-lg text-center border border-white/10">
                        <p className="text-gray-400 text-lg">Parabéns! Nenhuma CVE recente encontrada para as tecnologias deste alvo.</p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {correlations.map((vuln: any, index: number) => (
                            <div key={index} className="bg-black/40 border-l-4 border-cyber-primary p-6 rounded-r-lg hover:bg-white/5 transition-colors">
                                <div className="flex justify-between items-start mb-2">
                                    <h3 className="text-xl font-bold text-cyber-primary flex items-center gap-2">
                                        {vuln.cve_id}
                                        <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`} target="_blank" rel="noreferrer" className="opacity-50 hover:opacity-100 transition-opacity">
                                            <ExternalLink className="w-4 h-4" />
                                        </a>
                                    </h3>
                                </div>
                                <p className="text-gray-300 mb-4 leading-relaxed">{vuln.description}</p>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
