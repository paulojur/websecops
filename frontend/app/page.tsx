'use client';

import { useEffect, useState } from 'react';
import { getVulnerabilities, getIntelligence, getStats, getTargets, addTarget, getTargetCorrelations, deleteTarget, syncVulnerabilities } from '@/lib/api';
import { ShieldAlert, Terminal, Activity, Globe, Zap, Cpu, X, Trash, RefreshCw, Search, LayoutDashboard } from 'lucide-react';
import { motion } from 'framer-motion';
import SeverityChart from './components/SeverityChart';
import { AppMode, deleteDemoTarget, getAppMode, getDemoTargets, setAppMode, saveDemoTarget } from '@/lib/demo-targets';

export default function Home() {
  const [vulns, setVulns] = useState([]);
  const [intel, setIntel] = useState([]);
  const [stats, setStats] = useState({ total_tracked: 0, critical_count: 0, high_count: 0 });
  const [targets, setTargets] = useState([]);
  const [newTarget, setNewTarget] = useState('');
  const [loadingTarget, setLoadingTarget] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<any>(null);
  const [correlations, setCorrelations] = useState([]);
  const [loadingCorrelations, setLoadingCorrelations] = useState(false);
  const [riskFilter, setRiskFilter] = useState('');
  const [isSyncing, setIsSyncing] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [appMode, setAppModeState] = useState<AppMode>('demo');

  useEffect(() => {
    setAppModeState(getAppMode());
    setIsAdmin(!!localStorage.getItem('admin_api_key'));
  }, []);
  useEffect(() => {
    async function fetchData(mode: AppMode) {
      try {
        const v = await getVulnerabilities(10);
        const i = await getIntelligence(10);
        const s = await getStats();
        const t = mode === 'demo' ? getDemoTargets() : await getTargets();
        setVulns(v);
        setIntel(i);
        setStats(s);
        setTargets(t);
      } catch (e) {
        console.error("Failed to fetch data", e);
      }
    }

    fetchData(appMode);
    const interval = appMode === 'live' ? setInterval(() => fetchData(appMode), 30000) : undefined;
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [appMode]);

  useEffect(() => {
    if (!selectedTarget) return;

    const handleEsc = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setSelectedTarget(null);
      }
    };

    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [selectedTarget]);

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget) return;

    setLoadingTarget(true);
    try {
      if (appMode === 'demo') {
        // Real scan but local storage only
        const { analyzeTarget } = await import('@/lib/api');
        const data = await analyzeTarget(newTarget);
        saveDemoTarget(data.target);
      } else {
        await addTarget(newTarget);
      }
      setNewTarget('');
      // Refresh list
      const t = appMode === 'demo' ? getDemoTargets() : await getTargets();
      setTargets(t);
      alert('Target scanned successfully!');
    } catch (error) {
      alert('Failed to scan target.');
      console.error(error);
    } finally {
      setLoadingTarget(false);
    }
  };

  const handleOpenCorrelations = async (target: any) => {
    if (target.potential_vulns === 0) return;

    setSelectedTarget(target);
    setLoadingCorrelations(true);
    try {
      if (appMode === 'demo') {
        // Demo targets already have correlations packed from the analyze endpoint
        setCorrelations(Array.isArray(target.correlations) ? target.correlations : []);
      } else {
        const data = await getTargetCorrelations(target.id);
        setCorrelations(Array.isArray(data.correlations) ? data.correlations : []);
      }
    } catch (e) {
      console.error("Failed to load correlations", e);
    } finally {
      setLoadingCorrelations(false);
    }
  }

  const handleDeleteTarget = async (id: number) => {
    if (!confirm('Are you sure you want to remove this target?')) return;

    try {
      if (appMode === 'demo') {
        deleteDemoTarget(id);
      } else {
        await deleteTarget(id);
      }
      const t = appMode === 'demo' ? getDemoTargets() : await getTargets();
      setTargets(t);
    } catch (e) {
      console.error("Failed to delete target", e);
      alert('Failed to delete target');
    }
  }

  const handleSync = async () => {
    setIsSyncing(true);
    try {
      await syncVulnerabilities();
      alert('Database synchronization started. It may take a few moments to reflect changes.');
      // Refresh all data
      const v = await getVulnerabilities(10);
      const mode = getAppMode();
      setAppModeState(mode);
      setIsAdmin(!!localStorage.getItem('admin_api_key'));
      const s = await getStats();
      setVulns(v);
      setStats(s);
    } catch (e) {
      console.error("Sync failed", e);
      alert('Failed to synchronize database.');
    } finally {
      setIsSyncing(false);
    }
  }

  const filteredCorrelations = (correlations || []).filter((c: any) => {
    if (!riskFilter) return true;
    const search = riskFilter.toLowerCase();
    return (
      c.description?.toLowerCase().includes(search) ||
      c.title?.toLowerCase().includes(search) ||
      c.id?.toLowerCase().includes(search) ||
      c.cve_id?.toLowerCase().includes(search) ||
      c.matched_keyword?.toLowerCase().includes(search)
    );
  });

  return (
    <div className="p-8 text-white relative w-full h-full">
      {/* Risk Details Modal */}
      {selectedTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setSelectedTarget(null)}
        >
          <div
            className="bg-cyber-dark border border-cyber-primary rounded-lg w-full max-w-2xl max-h-[80vh] flex flex-col shadow-[0_0_50px_rgba(0,255,255,0.2)]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 border-b border-white/10 flex justify-between items-center bg-white/5">
              <div>
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-6 h-6 text-red-500" />
                  Security Risks Analysis
                </h2>
                <p className="text-sm text-gray-400 font-mono mt-1">{selectedTarget.url}</p>
              </div>
              <button onClick={() => setSelectedTarget(null)} className="text-gray-400 hover:text-white">
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="bg-black/20 px-6 py-3 border-b border-white/5">
              <div className="relative">
                <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter by subject, CVE or keywords..."
                  className="w-full bg-white/5 border border-white/10 rounded pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-cyber-primary transition-colors"
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value)}
                  autoFocus
                />
              </div>
            </div>

            <div className="p-6 overflow-y-auto flex-1 scrollbar-thin">
              {loadingCorrelations ? (
                <div className="flex justify-center p-8 text-cyber-primary animate-pulse">Analyzing Risk Vectors...</div>
              ) : (
                <div className="space-y-4">
                  {filteredCorrelations.length === 0 ? (
                    <p className="text-gray-500 text-center">
                      {riskFilter ? 'No vulnerabilities match your filter.' : 'No specific public exploits linked to detected version (Generic alert).'}
                    </p>
                  ) : (
                    filteredCorrelations.map((c: any, i) => (
                      <div key={i} className="bg-white/5 border-l-4 border-red-500 p-4 rounded-r">
                        <div className="flex justify-between items-start mb-2">
                          <span className="font-bold text-red-400">{c.id || c.cve_id}</span>
                          <span className="text-[10px] uppercase bg-white/10 px-2 py-0.5 rounded text-gray-300">
                            {c.confidence || 'LOW'}
                          </span>
                        </div>
                        <p className="text-sm text-gray-300">{c.description}</p>
                        {c.correlation_reason && <p className="text-xs text-gray-500 mt-2">{c.correlation_reason}</p>}
                        {c.confidence_reason && <p className="text-xs text-gray-500 mt-1">{c.confidence_reason}</p>}
                        <div className="mt-2 text-xs text-gray-500">
                          Published: {new Date(c.published).toLocaleDateString()} | Severity: {c.severity}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Background Decor */}
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-accent animate-pulse" />
      <div className="absolute -top-40 -right-40 w-96 h-96 bg-cyber-primary/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-cyber-secondary/10 rounded-full blur-3xl pointer-events-none" />

      {/* Header */}
      <header className="flex justify-between items-center mb-12 relative z-10 border-b border-white/10 pb-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tighter flex items-center gap-3 text-white">
            <LayoutDashboard className="w-8 h-8 text-cyber-primary" />
            Visão Geral
          </h1>
          <p className="text-gray-400 text-sm mt-1 uppercase tracking-widest pl-12">Monitoramento em Tempo Real</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2 bg-cyber-panel border border-white/10 rounded px-2 py-1">
            {isAdmin ? (
                <button
                  onClick={() => { setAppMode('live'); setAppModeState('live'); }}
                  className={`px-3 py-1 rounded uppercase tracking-wider transition-colors ${appMode === 'live' ? 'bg-cyber-primary text-black' : 'text-gray-400 hover:text-white'}`}
                >
                  LIVE
                </button>
            ) : (
                <span className="px-3 py-1 rounded uppercase tracking-wider text-gray-500 line-through" title="Admin only">LIVE</span>
            )}
            <button
              onClick={() => { setAppMode('demo'); setAppModeState('demo'); }}
              className={`px-3 py-1 rounded uppercase tracking-wider transition-colors ${appMode === 'demo' ? 'bg-cyber-secondary text-black' : 'text-gray-400 hover:text-white'}`}
            >
              DEMO
            </button>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-ping" />
            <span>MONITORING ACTIVE</span>
          </div>
          <div className="bg-cyber-panel border border-white/10 px-4 py-2 rounded">
            v2.1.0-DEV
          </div>
          {isAdmin && (
              <button
                onClick={handleSync}
                disabled={isSyncing}
                className="flex items-center gap-2 bg-cyber-panel border border-white/10 px-4 py-2 rounded hover:bg-white/5 transition-colors text-xs font-mono uppercase tracking-wider hover:text-cyber-primary"
              >
                <RefreshCw className={`w-3 h-3 ${isSyncing ? 'animate-spin' : ''}`} />
                {isSyncing ? 'UPDATING...' : 'SYNC DB'}
              </button>
          )}
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
        <div className="glass-panel p-4 rounded-lg border border-white/10">
          <p className="text-[10px] uppercase tracking-widest text-gray-400">Modo atual</p>
          <h2 className="text-lg font-bold text-white mt-1">{appMode === 'demo' ? 'Demo local' : 'Live com backend'}</h2>
          <p className="text-sm text-gray-400 mt-2">{appMode === 'demo' ? 'Os dados são escaneados em tempo real no backend, mas salvos apenas no seu navegador.' : 'Os alvos e correlações vêm diretamente da base inteligente.'}</p>
        </div>
        <div className="glass-panel p-4 rounded-lg border border-white/10">
          <p className="text-[10px] uppercase tracking-widest text-gray-400">Em 2 minutos</p>
          <h2 className="text-lg font-bold text-white mt-1">Cadastre, detecte, priorize</h2>
          <p className="text-sm text-gray-400 mt-2">1. Adicione um alvo. 2. Veja a tecnologia detectada. 3. Abra a correlação com motivo e confiança.</p>
        </div>
        <div className="glass-panel p-4 rounded-lg border border-white/10">
          <p className="text-[10px] uppercase tracking-widest text-gray-400">Scan sob demanda</p>
          <h2 className="text-lg font-bold text-white mt-1">ZAP apenas quando precisar</h2>
          <p className="text-sm text-gray-400 mt-2">O profile de scan fica desligado por padrão para manter o stack viável em máquinas pequenas.</p>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
        <StatCard title="TOTAL VULNERABILITIES" value={stats.total_tracked} icon={Globe} color="text-blue-400" />
        <StatCard title="CRITICAL THREATS" value={stats.critical_count} icon={Zap} color="text-red-500" isAlert />
        <StatCard title="HIGH SEVERITY" value={stats.high_count} icon={ShieldAlert} color="text-orange-400" />

        <div className="glass-panel p-4 rounded-lg flex flex-col items-center justify-center relative min-h-[160px]">
          <h3 className="text-xs text-gray-400 uppercase tracking-widest absolute top-4 left-4">THREAT DISTRIBUTION</h3>
          <SeverityChart stats={stats} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 ">
        {/* Vulnerabilities Feed */}
        <div className="lg:col-span-2 space-y-8">
          <div className="glass-panel p-6 rounded-lg overflow-hidden flex flex-col h-[500px]">
            <h2 className="text-xl font-bold mb-6 flex items-center gap-2 text-cyber-secondary">
              <Cpu className="w-5 h-5" /> WEB VULNERABILITIES DETECTED
            </h2>
            <div className="overflow-y-auto pr-2 space-y-3 flex-1 scrollbar-thin">
              {vulns.map((v: any, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.1 }}
                  className="p-4 bg-white/5 border-l-2 border-cyber-secondary/50 hover:bg-white/10 transition-all rounded-r"
                >
                  <div className="flex justify-between items-start">
                    <span className="font-mono text-cyber-secondary font-bold text-lg">{v.id}</span>
                    <span className={`px-2 py-1 rounded text-xs font-bold ${getSeverityColor(v.severity)}`}>
                      {v.severity}
                    </span>
                  </div>
                  <p className="text-gray-300 text-sm mt-2 line-clamp-2">{v.description}</p>
                  {v.correlation_reason && (
                    <p className="text-xs text-gray-500 mt-2 line-clamp-2">{v.correlation_reason}</p>
                  )}
                  <div className="text-xs text-gray-500 mt-2 flex justify-between">
                    <span>Source: {v.source}</span>
                    <span>{new Date(v.published).toLocaleDateString()}</span>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>

          {/* Inventory / Targets Widget */}
          <div className="glass-panel p-6 rounded-lg overflow-hidden flex flex-col h-[400px]">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-xl font-bold flex items-center gap-2 text-cyber-primary">
                <Globe className="w-5 h-5" /> TECH STACK INVENTORY
              </h2>
              <form onSubmit={handleAddTarget} className="flex gap-2">
                <input
                  type="url"
                  placeholder="https://example.com"
                  className="bg-black/30 border border-white/10 rounded px-3 py-1 text-sm text-white focus:outline-none focus:border-cyber-primary"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  required
                />
                <button
                  type="submit"
                  disabled={loadingTarget}
                  className="bg-cyber-primary text-black px-3 py-1 rounded text-sm font-bold hover:bg-white transition-colors disabled:opacity-50"
                >
                  {loadingTarget ? 'SCANNING...' : 'SCAN'}
                </button>
              </form>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 overflow-y-auto pr-2">
              {targets.map((t: any) => (
                <div key={t.id} className={`p-4 bg-white/5 border ${t.potential_vulns > 0 ? 'border-red-500/50' : 'border-white/5'} rounded hover:border-cyber-primary/50 transition-colors relative`}>
                  <h3 className="font-mono text-sm font-bold text-cyber-primary truncate" title={t.url}>{t.url}</h3>

                  {appMode === 'demo' && (
                    <div className="absolute top-2 left-2 text-[10px] uppercase tracking-widest bg-cyber-secondary/15 text-cyber-secondary border border-cyber-secondary/20 px-2 py-0.5 rounded">
                      local demo
                    </div>
                  )}

                  {/* Risk Badge */}
                  {t.potential_vulns > 0 && (
                    <div
                      onClick={() => handleOpenCorrelations(t)}
                      className="absolute top-2 right-2 flex items-center gap-1 bg-red-500/20 text-red-400 px-2 py-0.5 rounded text-[10px] font-bold border border-red-500/30 animate-pulse cursor-pointer hover:bg-red-500/30 transition-colors"
                    >
                      <ShieldAlert className="w-3 h-3" />
                      {t.potential_vulns} POTENTIAL VULNS
                    </div>
                  )}

                  <div className="mt-3 flex flex-wrap gap-2">
                    {Object.entries(t.technologies || {}).map(([k, v]: any) => {
                      const detail = typeof v === 'object' && v !== null
                        ? [v.version, v.category].filter(Boolean).join(' · ')
                        : String(v ?? '');

                      return (
                        <span key={k} className="text-[10px] bg-white/10 px-2 py-0.5 rounded text-gray-300 border border-white/5">
                          <b className="text-white">{k}</b>
                          {detail ? ` · ${detail}` : ''}
                        </span>
                      );
                    })}
                    {Object.keys(t.technologies || {}).length === 0 && (
                      <span className="text-xs text-gray-500 italic">No technologies detected</span>
                    )}
                  </div>
                  <div className="mt-2 text-[10px] text-gray-500 flex justify-between items-end">
                    <span>Last Scan: {t.last_scan ? new Date(t.last_scan).toLocaleString() : 'Never'}</span>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDeleteTarget(t.id); }}
                      className="text-gray-500 hover:text-red-500 transition-colors"
                      title="Remove Target"
                    >
                      <Trash className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Intelligence Feed */}
        <div className="glass-panel p-6 rounded-lg overflow-hidden flex flex-col relative h-[930px]">
          <div className="absolute top-0 right-0 p-4 opacity-20">
            <Terminal className="w-24 h-24" />
          </div>
          <h2 className="text-xl font-bold mb-6 flex items-center gap-2 text-cyber-accent">
            <Activity className="w-5 h-5" /> INTELLIGENCE STREAM
          </h2>
          <div className="overflow-y-auto pr-2 space-y-4 flex-1">
            {intel.map((item: any, i) => (
              <div key={i} className="border-b border-white/5 pb-4 last:border-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px] uppercase tracking-wider bg-cyber-accent/20 text-cyber-accent px-2 py-0.5 rounded">
                    {item.source}
                  </span>
                  <span className="text-xs text-gray-500">{new Date(item.published).toLocaleTimeString()}</span>
                </div>
                <a href={item.link} target="_blank" className="font-semibold text-sm hover:text-cyber-accent transition-colors block mb-1">
                  {item.title}
                </a>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, color, isAlert }: any) {
  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      className={`glass-panel p-6 rounded-lg relative overflow-hidden ${isAlert ? 'border-red-500/30' : ''} min-h-[160px] flex flex-col justify-between`}
    >
      <div className="flex justify-between items-start relative z-10">
        <div>
          <p className="text-xs text-gray-400 uppercase tracking-widest">{title}</p>
          <h3 className={`text-4xl font-bold mt-2 ${color} text-glow`}>{value}</h3>
        </div>
        <Icon className={`w-8 h-8 ${color} opacity-80`} />
      </div>
      {isAlert && <div className="absolute inset-0 bg-red-500/5 animate-pulse" />}
    </motion.div>
  )
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'CRITICAL': return 'bg-red-500/20 text-red-500';
    case 'HIGH': return 'bg-orange-500/20 text-orange-500';
    case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-500';
    case 'LOW': return 'bg-blue-500/20 text-blue-500';
    default: return 'bg-gray-500/20 text-gray-400';
  }
}
