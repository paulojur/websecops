'use client';

import { Activity, ExternalLink, Filter } from 'lucide-react';
import { useState, useEffect } from 'react';
import { getIntelligence } from '@/lib/api';

import { useLanguage } from '@/lib/useLanguage';

export default function IntelligencePage() {
    const { t } = useLanguage();
    const [intel, setIntel] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        async function load() {
            try {
                const data = await getIntelligence(50); // Get more items
                setIntel(data);
            } catch (e) {
                console.error(e);
            } finally {
                setLoading(false);
            }
        }
        load();
    }, []);

    return (
        <div className="p-8 space-y-8">
            <header className="flex justify-between items-end border-b border-white/10 pb-6">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
                        <Activity className="w-8 h-8 text-cyber-accent" />
                        {t('intelligenceTitle')}
                    </h1>
                    <p className="text-gray-400 mt-2">{t('intelligenceDescription')}</p>
                </div>
                <button
                    onClick={async () => {
                        if (confirm('Atualizar feed agora? Isso pode levar alguns segundos.')) {
                            try {
                                await import('@/lib/api').then(m => m.syncIntelligence());
                                window.location.reload();
                            } catch (e) { alert('Erro ao sincronizar'); }
                        }
                    }}
                    className="bg-cyber-accent/20 hover:bg-cyber-accent/30 text-cyber-accent border border-cyber-accent/50 px-4 py-2 rounded text-xs font-bold transition-colors uppercase tracking-wider"
                >
                    {t('forceUpdate')}
                </button>
            </header>

            <div className="grid grid-cols-1 gap-4">
                {loading ? (
                    <div className="text-center py-20 text-gray-500 animate-pulse">{t('loadingIntelligence')}</div>
                ) : (
                    intel.map((item: any, i) => (
                        <div key={i} className="glass-panel p-6 rounded-lg flex gap-6 hover:bg-white/5 transition-colors group">
                            <div className="shrink-0 flex flex-col items-center gap-2 pt-1">
                                <div className="w-12 h-12 rounded-full bg-cyber-accent/10 flex items-center justify-center border border-cyber-accent/20 text-cyber-accent font-bold text-xs uppercase">
                                    {item.source?.substring(0, 3)}
                                </div>
                            </div>

                            <div className="flex-1">
                                <div className="flex items-center gap-3 mb-2">
                                    <span className="text-xs font-mono text-cyber-accent bg-cyber-accent/10 px-2 py-0.5 rounded">
                                        {item.source}
                                    </span>
                                    <span className="text-xs text-gray-500">
                                        {new Date(item.published).toLocaleString()}
                                    </span>
                                </div>

                                <h3 className="text-lg font-bold text-white mb-2 group-hover:text-cyber-accent transition-colors">
                                    {item.title}
                                </h3>
                                <p className="text-sm text-gray-400 mb-4 line-clamp-2">
                                    {item.description || item.summary || t('noDescription')}
                                </p>

                                <a
                                    href={item.link}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="inline-flex items-center gap-1 text-xs text-cyber-accent hover:underline font-bold"
                                >
                                    {t('readFullArticle')} <ExternalLink className="w-3 h-3" />
                                </a>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
