'use client';

import { ShieldAlert, Globe, Search, Plus, Loader2, Key, X } from 'lucide-react';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { getTargets, addTarget, analyzeTarget } from '@/lib/api';
import { AppMode, deleteDemoTarget, getAppMode, getDemoTargets, setAppMode, saveDemoTarget } from '@/lib/demo-targets';
import { useLanguage } from '@/lib/useLanguage';

export default function TargetsPage() {
    const { t } = useLanguage();
    const [targets, setTargets] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [adding, setAdding] = useState(false);
    const [newTarget, setNewTarget] = useState('');
    const [appMode, setAppModeState] = useState<AppMode>('demo');
    const [isAdmin, setIsAdmin] = useState(false);
    const [showKeyModal, setShowKeyModal] = useState(false);
    const [masterKeyInput, setMasterKeyInput] = useState('');

    useEffect(() => {
        const mode = getAppMode();
        setAppModeState(mode);
        const key = localStorage.getItem('admin_api_key');
        setIsAdmin(!!key);
        loadTargets(mode);
    }, []);

    async function loadTargets(mode: AppMode) {
        setLoading(true);
        try {
            const data = mode === 'demo' ? getDemoTargets() : await getTargets();
            setTargets(Array.isArray(data) ? data : []);
        } catch (e) {
            console.error('Error loading targets:', e);
            setTargets([]);
        } finally {
            setLoading(false);
        }
    }

    const handleAdd = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newTarget.trim()) return;

        let formattedUrl = newTarget.trim();
        if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
            formattedUrl = `https://${formattedUrl}`;
        }

        if (appMode === 'live' && !isAdmin) {
            setShowKeyModal(true);
            return;
        }

        setAdding(true);
        try {
            if (appMode === 'demo') {
                const data = await analyzeTarget(formattedUrl);
                const targetObj = data.target || {
                    id: Date.now(),
                    url: formattedUrl,
                    technologies: {},
                    potential_vulns: 0,
                    created_at: new Date().toISOString()
                };
                saveDemoTarget({
                    ...targetObj,
                    correlations: data.correlations || [],
                    summary: data.summary || {},
                    hardening: data.hardening || {}
                });
            } else {
                await addTarget(formattedUrl);
            }

            setNewTarget('');
            await loadTargets(appMode);
            alert(t('targetAddedSuccess'));
        } catch (error) {
            console.error('Failed to add target:', error);
            alert(t('targetAddError'));
        } finally {
            setAdding(false);
        }
    };

    const handleModeChange = (mode: AppMode) => {
        setAppMode(mode);
        setAppModeState(mode);
        loadTargets(mode);
    };

    const handleSaveKey = (e: React.FormEvent) => {
        e.preventDefault();
        if (masterKeyInput.trim()) {
            localStorage.setItem('admin_api_key', masterKeyInput.trim());
            setIsAdmin(true);
            setShowKeyModal(false);
            alert('Master Key salva com sucesso!');
        }
    };

    const handleDelete = (id: number) => {
        if (!confirm(t('areYouSure'))) return;
        if (appMode === 'demo') {
            deleteDemoTarget(id);
            loadTargets('demo');
        }
    };

    return (
        <div className="p-8 space-y-8">
            <header className="flex justify-between items-end border-b border-white/10 pb-6">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
                        <Globe className="w-8 h-8 text-cyber-primary" />
                        {t('myTargetsTitle')}
                    </h1>
                    <p className="text-gray-400 mt-2">{t('myTargetsDescription')}</p>
                </div>
                <div className="flex items-center gap-3 text-xs font-mono text-gray-500">
                    <div className="flex items-center gap-1 bg-cyber-panel border border-white/10 rounded px-2 py-1">
                        <button
                            onClick={() => handleModeChange('live')}
                            className={`px-2 py-1 rounded transition-colors ${appMode === 'live' ? 'bg-cyber-primary text-black font-bold' : 'text-gray-400 hover:text-white'}`}
                        >
                            LIVE
                        </button>
                        <button
                            onClick={() => handleModeChange('demo')}
                            className={`px-2 py-1 rounded transition-colors ${appMode === 'demo' ? 'bg-cyber-secondary text-black font-bold' : 'text-gray-400 hover:text-white'}`}
                        >
                            DEMO
                        </button>
                    </div>
                    <div>{targets.length} {t('activeTargets')}</div>
                </div>
            </header>

            <div className="glass-panel p-4 rounded-lg border border-white/10 flex justify-between items-center">
                <div>
                    <p className="text-xs uppercase tracking-widest text-gray-400">Modo Atual: <span className="text-cyber-primary font-bold">{appMode.toUpperCase()}</span></p>
                    <p className="text-xs text-gray-300 mt-1">
                        {appMode === 'demo' ? t('demoModeDesc') : t('liveModeDesc')}
                    </p>
                </div>
                {appMode === 'live' && (
                    <button
                        onClick={() => setShowKeyModal(true)}
                        className={`text-xs px-3 py-1.5 rounded border transition-colors flex items-center gap-1 ${isAdmin ? 'border-cyber-primary text-cyber-primary bg-cyber-primary/10' : 'border-white/10 text-gray-400 hover:text-white'}`}
                    >
                        <Key className="w-3.5 h-3.5" />
                        {isAdmin ? 'Master Key Configurada' : 'Configurar Master Key'}
                    </button>
                )}
            </div>

            {/* Add Target Bar */}
            <div className="glass-panel p-6 rounded-lg">
                <form onSubmit={handleAdd} className="flex gap-4">
                    <div className="relative flex-1">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                        <input
                            type="url"
                            placeholder={t('enterTargetUrl')}
                            className="w-full bg-black/30 border border-white/10 rounded-lg pl-10 pr-4 py-3 text-white focus:outline-none focus:border-cyber-primary transition-colors"
                            value={newTarget}
                            onChange={e => setNewTarget(e.target.value)}
                            required
                        />
                    </div>
                    <button
                        type="submit"
                        disabled={adding}
                        className="bg-cyber-primary text-black font-bold px-6 py-3 rounded-lg hover:bg-white transition-colors flex items-center gap-2 disabled:opacity-50"
                    >
                        {adding ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                        {t('addTargetButton')}
                    </button>
                </form>
            </div>

            {/* Targets Grid */}
            {loading ? (
                <div className="flex justify-center p-12 text-gray-500">
                    <Loader2 className="w-8 h-8 animate-spin" />
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {targets.length === 0 && (
                        <div className="col-span-full text-center p-12 text-gray-500 italic glass-panel rounded-lg">
                            {t('noTargets')}
                        </div>
                    )}
                    {targets.map((tItem: any) => (
                        <div key={tItem.id} className="bg-white/5 border border-white/10 rounded-lg p-6 hover:border-cyber-primary/50 transition-colors group flex flex-col justify-between">
                            <div>
                                <div className="flex justify-between items-start mb-4">
                                    <div className="p-2 bg-white/5 rounded">
                                        <Globe className="w-6 h-6 text-cyber-secondary" />
                                    </div>
                                    {tItem.potential_vulns > 0 && (
                                        <span className="bg-red-500/20 text-red-400 text-xs px-2 py-1 rounded font-bold border border-red-500/30 flex items-center gap-1">
                                            <ShieldAlert className="w-3 h-3" />
                                            {tItem.potential_vulns} RISCOS
                                        </span>
                                    )}
                                </div>

                                <h3 className="text-lg font-bold text-white mb-1 truncate" title={tItem.url}>{tItem.url}</h3>
                                <p className="text-xs text-gray-500 mb-4">{t('lastScanned')}: {new Date(tItem.created_at || Date.now()).toLocaleDateString()}</p>

                                <div className="flex flex-wrap gap-2 mb-4">
                                    {Object.entries(tItem.technologies || {}).slice(0, 4).map(([k, v]: any) => {
                                        const version = typeof v === 'object' && v.version ? ` v${v.version}` : '';
                                        return (
                                            <span key={k} className="text-[10px] bg-black/40 px-2 py-1 rounded text-gray-400 border border-white/5">
                                                {k}{version}
                                            </span>
                                        );
                                    })}
                                </div>
                            </div>

                            <div className="flex gap-2 pt-4 border-t border-white/5">
                                <Link href={`/targets/${tItem.id}`} className="flex-1">
                                    <button className="w-full bg-white/5 hover:bg-white/10 py-2 rounded text-xs font-bold text-gray-300 transition-colors">
                                        {t('viewDetails')}
                                    </button>
                                </Link>
                                {appMode === 'demo' && (
                                    <button
                                        onClick={() => handleDelete(tItem.id)}
                                        className="px-3 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded text-xs font-bold transition-colors"
                                    >
                                        {t('delete')}
                                    </button>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}

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
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
