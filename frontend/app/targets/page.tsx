'use client';

import { ShieldAlert, Globe, Search, Plus } from 'lucide-react';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getTargets, addTarget, deleteTarget, analyzeTarget } from '@/lib/api';
import { AppMode, deleteDemoTarget, getAppMode, getDemoTargets, setAppMode, saveDemoTarget } from '@/lib/demo-targets';

export default function TargetsPage() {
    const [targets, setTargets] = useState([]);
    const [loading, setLoading] = useState(true);
    const [newTarget, setNewTarget] = useState('');
    const [appMode, setAppModeState] = useState<AppMode>('live');
    const [isAdmin, setIsAdmin] = useState(false);

    useEffect(() => {
        const mode = getAppMode();
        setAppModeState(mode);
        setIsAdmin(!!localStorage.getItem('admin_api_key'));
        loadTargets(mode);
    }, []);

    async function loadTargets(mode: AppMode) {
        try {
            const data = mode === 'demo' ? getDemoTargets() : await getTargets();
            setTargets(data);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    }

    const handleAdd = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newTarget) return;
        setLoading(true);
        try {
            if (appMode === 'demo') {
                const data = await analyzeTarget(newTarget);
                saveDemoTarget({
                    ...data.target,
                    correlations: data.correlations || [],
                    summary: data.summary || {},
                    hardening: data.hardening || {}
                });
            } else {
                await addTarget(newTarget);
            }
            setNewTarget('');
            await loadTargets(appMode);
        } catch (error) {
            console.error("Failed to add target", error);
            alert("Falha ao adicionar alvo.");
            setLoading(false);
        }
    };

    const handleModeChange = (mode: AppMode) => {
        setAppMode(mode);
        setAppModeState(mode);
        loadTargets(mode);
    };

    return (
        <div className="p-8 space-y-8">
            <header className="flex justify-between items-end border-b border-white/10 pb-6">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
                        <Globe className="w-8 h-8 text-cyber-primary" />
                        Gerenciamento de Alvos
                    </h1>
                    <p className="text-gray-400 mt-2">Monitore suas aplicações web e APIs</p>
                </div>
                <div className="flex items-center gap-3 text-xs font-mono text-gray-500">
                    <div className="flex items-center gap-1 bg-cyber-panel border border-white/10 rounded px-2 py-1">
                        {isAdmin ? (
                            <button onClick={() => handleModeChange('live')} className={`px-2 py-1 rounded ${appMode === 'live' ? 'bg-cyber-primary text-black' : 'text-gray-400'}`}>LIVE</button>
                        ) : (
                            <span className="px-2 py-1 rounded text-gray-500 line-through" title="Admin only">LIVE</span>
                        )}
                        <button onClick={() => handleModeChange('demo')} className={`px-2 py-1 rounded ${appMode === 'demo' ? 'bg-cyber-secondary text-black' : 'text-gray-400'}`}>DEMO</button>
                    </div>
                    <div>{targets.length} ALVOS ATIVOS</div>
                </div>
            </header>

            <div className="glass-panel p-4 rounded-lg border border-white/10">
                <p className="text-xs uppercase tracking-widest text-gray-400">Modo atual</p>
                <p className="text-sm text-gray-300 mt-1">{appMode === 'demo' ? 'Os alvos ficam apenas no navegador do visitante.' : 'Os alvos são salvos no backend e consultados pela API.'}</p>
            </div>

            {/* Add Target Bar */}
            <div className="glass-panel p-6 rounded-lg">
                <form onSubmit={handleAdd} className="flex gap-4">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                        <input
                            type="url"
                            placeholder="https://exemplo.jus.br"
                            className="w-full bg-black/30 border border-white/10 rounded-lg pl-10 pr-4 py-3 text-white focus:outline-none focus:border-cyber-primary transition-colors"
                            value={newTarget}
                            onChange={e => setNewTarget(e.target.value)}
                            required
                        />
                    </div>
                    <button className="bg-cyber-primary text-black font-bold px-6 py-3 rounded-lg hover:bg-white transition-colors flex items-center gap-2">
                        <Plus className="w-4 h-4" />
                        ADICIONAR
                    </button>
                </form>
            </div>

            {/* Targets Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {targets.map((t: any) => (
                    <div key={t.id} className="bg-white/5 border border-white/10 rounded-lg p-6 hover:border-cyber-primary/50 transition-colors group">
                        <div className="flex justify-between items-start mb-4">
                            <div className="p-2 bg-white/5 rounded">
                                <Globe className="w-6 h-6 text-cyber-secondary" />
                            </div>
                            {t.potential_vulns > 0 && (
                                <span className="bg-red-500/20 text-red-400 text-xs px-2 py-1 rounded font-bold border border-red-500/30 flex items-center gap-1">
                                    <ShieldAlert className="w-3 h-3" />
                                    {t.potential_vulns} RISCOS
                                </span>
                            )}
                        </div>

                        <h3 className="text-lg font-bold text-white mb-1 truncate" title={t.url}>{t.url}</h3>
                        <p className="text-xs text-gray-500 mb-4">Adicionado em: {new Date(t.created_at || Date.now()).toLocaleDateString()}</p>

                        <div className="flex flex-wrap gap-2 mb-4">
                            {Object.entries(t.technologies || {}).slice(0, 3).map(([k, v]: any) => {
                                const version = typeof v === 'object' && v.version ? ` v${v.version}` : '';
                                return (
                                    <span key={k} className="text-[10px] bg-black/40 px-2 py-1 rounded text-gray-400 border border-white/5">
                                        {k}{version}
                                    </span>
                                );
                            })}
                        </div>

                        <div className="flex gap-2 mt-auto pt-4 border-t border-white/5">
                            <Link href={`/targets/${t.id}`} className="flex-1">
                                <button className="w-full bg-white/5 hover:bg-white/10 py-2 rounded text-xs font-bold text-gray-300 transition-colors">
                                    VER DETALHES
                                </button>
                            </Link>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
