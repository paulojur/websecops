'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Sparkles, Key, ArrowRight, X, Check, Globe } from 'lucide-react';
import { useLanguage } from '@/lib/useLanguage';

export default function WelcomeModal() {
    const { t, language, setLanguage } = useLanguage();
    const [isOpen, setIsOpen] = useState(false);
    const [dontShowAgain, setDontShowAgain] = useState(false);

    useEffect(() => {
        // Check if user has already seen or dismissed the welcome modal
        const hasSeen = localStorage.getItem('websecops_seen_welcome');
        if (!hasSeen) {
            // Small timeout for smooth initial page load
            const timer = setTimeout(() => setIsOpen(true), 600);
            return () => clearTimeout(timer);
        }
    }, []);

    const handleClose = () => {
        setIsOpen(false);
        if (dontShowAgain) {
            localStorage.setItem('websecops_seen_welcome', 'true');
        }
    };

    const handleStartDemo = () => {
        localStorage.setItem('websecops_seen_welcome', 'true');
        setIsOpen(false);
    };

    const handleOpenAdminLogin = () => {
        localStorage.setItem('websecops_seen_welcome', 'true');
        setIsOpen(false);
        // Dispatch custom event to trigger AdminLogin modal
        window.dispatchEvent(new Event('open-admin-login'));
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
                    <motion.div
                        initial={{ opacity: 0, scale: 0.9, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.9, y: 20 }}
                        transition={{ duration: 0.3, ease: 'easeOut' }}
                        className="bg-cyber-dark border border-cyber-primary/40 rounded-2xl w-full max-w-2xl overflow-hidden shadow-[0_0_50px_rgba(0,255,255,0.15)] flex flex-col relative"
                    >
                        {/* Top Decorative Neon Line */}
                        <div className="h-1 w-full bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-accent animate-pulse" />

                        {/* Header */}
                        <div className="p-6 pb-4 border-b border-white/10 flex justify-between items-start bg-white/5 relative">
                            <div className="flex items-center gap-4">
                                <div className="w-12 h-12 rounded-xl bg-cyber-primary/10 border border-cyber-primary/30 flex items-center justify-center shrink-0">
                                    <Shield className="w-7 h-7 text-cyber-primary animate-pulse" />
                                </div>
                                <div>
                                    <div className="flex items-center gap-2">
                                        <h2 className="text-2xl font-bold text-white tracking-tight">
                                            {t('welcomeTitle')}
                                        </h2>
                                        <span className="bg-cyber-secondary/20 text-cyber-secondary border border-cyber-secondary/30 text-[10px] uppercase font-mono px-2 py-0.5 rounded-full font-bold">
                                            {t('welcomeBadge')}
                                        </span>
                                    </div>
                                    <p className="text-xs text-gray-400 mt-1">
                                        {t('welcomeSubtitle')}
                                    </p>
                                </div>
                            </div>

                            {/* Controls: Language Switcher & Close */}
                            <div className="flex items-center gap-3">
                                <button
                                    onClick={() => setLanguage(language === 'pt' ? 'en' : 'pt')}
                                    className="flex items-center gap-1.5 bg-white/5 hover:bg-white/10 border border-white/10 text-gray-300 px-2.5 py-1 rounded text-xs font-mono transition-colors"
                                    title="Alternar idioma / Switch language"
                                >
                                    <Globe className="w-3.5 h-3.5 text-cyber-primary" />
                                    <span className="uppercase font-bold">{language}</span>
                                </button>
                                <button
                                    onClick={handleClose}
                                    className="text-gray-400 hover:text-white p-1 transition-colors"
                                    aria-label="Close"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            </div>
                        </div>

                        {/* Content Body */}
                        <div className="p-6 space-y-6 overflow-y-auto max-h-[70vh] scrollbar-thin">
                            {/* Feature Cards Grid */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {/* DEMO Card */}
                                <div className="glass-panel p-5 rounded-xl border border-cyber-primary/30 bg-cyber-primary/5 hover:border-cyber-primary/60 transition-all flex flex-col justify-between group relative overflow-hidden">
                                    <div className="absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity">
                                        <Sparkles className="w-16 h-16 text-cyber-primary" />
                                    </div>
                                    <div>
                                        <div className="flex items-center gap-2 mb-2">
                                            <span className="w-2.5 h-2.5 rounded-full bg-cyber-primary animate-ping" />
                                            <h3 className="font-bold text-cyber-primary text-base">
                                                {t('welcomeDemoTitle')}
                                            </h3>
                                        </div>
                                        <p className="text-xs text-gray-300 leading-relaxed">
                                            {t('welcomeDemoDesc')}
                                        </p>
                                    </div>
                                    <div className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between text-[11px] text-cyber-primary font-mono font-semibold">
                                        <span>✓ Zero Cadastro</span>
                                        <span>✓ Teste Grátis</span>
                                    </div>
                                </div>

                                {/* LIVE Card */}
                                <div className="glass-panel p-5 rounded-xl border border-white/10 bg-white/5 hover:border-cyber-secondary/40 transition-all flex flex-col justify-between group relative overflow-hidden">
                                    <div className="absolute top-0 right-0 p-3 opacity-10 group-hover:opacity-20 transition-opacity">
                                        <Key className="w-16 h-16 text-cyber-secondary" />
                                    </div>
                                    <div>
                                        <div className="flex items-center gap-2 mb-2">
                                            <Key className="w-4 h-4 text-cyber-secondary" />
                                            <h3 className="font-bold text-white text-base">
                                                {t('welcomeLiveTitle')}
                                            </h3>
                                        </div>
                                        <p className="text-xs text-gray-400 leading-relaxed">
                                            {t('welcomeLiveDesc')}
                                        </p>
                                    </div>
                                    <div className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between text-[11px] text-gray-400 font-mono">
                                        <span>🔒 Requer Master API Key</span>
                                    </div>
                                </div>
                            </div>

                            {/* Enterprise Architecture & Privacy-by-Design Note */}
                            <div className="bg-cyber-accent/10 rounded-xl p-4 border border-cyber-accent/30 space-y-1 text-xs">
                                <div className="text-[11px] font-mono text-cyber-accent font-bold uppercase tracking-wider flex items-center gap-1.5">
                                    {t('welcomeArchitectureBadge')}
                                </div>
                                <p className="text-[11px] text-gray-300 leading-relaxed font-sans mt-1">
                                    {t('welcomeArchitectureDesc')}
                                </p>
                            </div>

                            {/* Interactive Highlights */}
                            <div className="bg-black/30 rounded-xl p-4 border border-white/5 space-y-2 text-xs text-gray-300 font-mono">
                                <div className="text-[11px] text-cyber-primary uppercase tracking-wider font-bold mb-1">
                                    ⚡ Recursos Prontos para Testar:
                                </div>
                                <div className="flex items-center gap-2">
                                    <Check className="w-3.5 h-3.5 text-cyber-primary shrink-0" />
                                    <span>Análise em tempo real de alvos web via Wappalyzer + CVE Correlation.</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Check className="w-3.5 h-3.5 text-cyber-primary shrink-0" />
                                    <span>Simulação interativa de Scans DAST (Nuclei & ZAP) com terminal em tempo real.</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Check className="w-3.5 h-3.5 text-cyber-primary shrink-0" />
                                    <span>Exportação de relatórios profissionais em PDF, CSV e tickets prontos para o Jira.</span>
                                </div>
                            </div>
                        </div>

                        {/* Footer Actions */}
                        <div className="p-6 pt-4 border-t border-white/10 bg-white/5 flex flex-col sm:flex-row justify-between items-center gap-4">
                            <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
                                <input
                                    type="checkbox"
                                    checked={dontShowAgain}
                                    onChange={(e) => setDontShowAgain(e.target.checked)}
                                    className="rounded border-white/20 bg-black/40 text-cyber-primary focus:ring-cyber-primary/50"
                                />
                                <span>{t('welcomeDontShow')}</span>
                            </label>

                            <div className="flex items-center gap-3 w-full sm:w-auto">
                                <button
                                    onClick={handleOpenAdminLogin}
                                    className="px-4 py-2 rounded-xl border border-white/20 text-gray-300 hover:text-white hover:bg-white/10 text-xs font-mono transition-colors w-full sm:w-auto flex items-center justify-center gap-1.5"
                                >
                                    <Key className="w-3.5 h-3.5 text-cyber-secondary" />
                                    {t('welcomeEnterKey')}
                                </button>
                                <button
                                    onClick={handleStartDemo}
                                    className="px-5 py-2.5 rounded-xl bg-cyber-primary text-black font-bold text-xs hover:bg-white transition-all shadow-[0_0_20px_rgba(0,255,255,0.4)] w-full sm:w-auto flex items-center justify-center gap-2 uppercase tracking-wider"
                                >
                                    {t('welcomeStartDemo')}
                                    <ArrowRight className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
}
