'use client';

import { Shield, Search, AlertTriangle, Info, CheckCircle } from 'lucide-react';
import { useState, useEffect } from 'react';
import { getVulnerabilities } from '@/lib/api';

import { useLanguage } from '@/lib/useLanguage';

export default function VulnsPage() {
    const { t } = useLanguage();
    const [vulns, setVulns] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        async function load() {
            try {
                const data = await getVulnerabilities(100);
                setVulns(data);
            } catch (e) {
                console.error(e);
            } finally {
                setLoading(false);
            }
        }
        load();
    }, []);

    const getSeverityColor = (severity: string) => {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20';
            case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
            case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
            default: return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
        }
    };

    return (
        <div className="p-8 space-y-8">
            <header className="flex justify-between items-end border-b border-white/10 pb-6">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
                        <Shield className="w-8 h-8 text-red-500" />
                        {t('vulnerabilitiesTitle')}
                    </h1>
                    <p className="text-gray-400 mt-2">{t('vulnerabilitiesDescription')}</p>
                </div>
            </header>

            {/* Search Bar */}
            <div className="glass-panel p-4 rounded-lg flex items-center gap-4">
                <Search className="w-5 h-5 text-gray-500" />
                <input
                    type="text"
                    placeholder="Buscar por ID (CVE-2024...), Produto ou Palavra-chave..."
                    className="flex-1 bg-transparent text-white focus:outline-none"
                />
            </div>

            <div className="space-y-4">
                {loading ? (
                    <div className="text-center py-20 text-gray-500 animate-pulse">Carregando CVEs...</div>
                ) : (
                    vulns.map((v: any) => (
                        <div key={v.id} className="bg-white/5 border border-white/10 p-6 rounded-lg hover:bg-white/10 transition-colors">
                            <div className="flex justify-between items-start mb-3">
                                <div className="flex items-center gap-3">
                                    <span className="font-mono font-bold text-lg text-white">{v.id}</span>
                                    <span className={`text-xs px-2 py-0.5 rounded border font-bold ${getSeverityColor(v.severity)}`}>
                                        {v.severity}
                                    </span>
                                </div>
                                <span className="text-xs text-gray-500">{new Date(v.published).toLocaleDateString()}</span>
                            </div>
                            <p className="text-sm text-gray-300 leading-relaxed max-w-4xl">
                                {v.description}
                            </p>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
