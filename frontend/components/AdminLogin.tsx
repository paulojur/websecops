'use client';

import { useState, useEffect } from 'react';
import { Lock, Unlock, X } from 'lucide-react';
import { getAppMode, setAppMode } from '@/lib/demo-targets';

export default function AdminLogin() {
    const [isOpen, setIsOpen] = useState(false);
    const [apiKey, setApiKey] = useState('');
    const [isLoggedIn, setIsLoggedIn] = useState(false);

    useEffect(() => {
        const stored = localStorage.getItem('admin_api_key');
        if (stored) {
            setIsLoggedIn(true);
        } else {
            // Force demo mode for anonymous visitors
            if (getAppMode() !== 'demo') {
                setAppMode('demo');
                window.dispatchEvent(new Event('storage'));
            }
        }
    }, []);

    const handleLogin = (e: React.FormEvent) => {
        e.preventDefault();
        if (apiKey) {
            localStorage.setItem('admin_api_key', apiKey);
            setIsLoggedIn(true);
            setIsOpen(false);
            setAppMode('live'); // Unlock live mode
            window.dispatchEvent(new Event('storage'));
            window.location.reload(); // Reload to apply API key in memory
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('admin_api_key');
        setIsLoggedIn(false);
        setAppMode('demo');
        window.dispatchEvent(new Event('storage'));
        window.location.reload();
    };

    return (
        <>
            <button
                onClick={() => setIsOpen(true)}
                className="fixed bottom-4 right-4 p-2 rounded-full bg-black/50 border border-white/10 hover:bg-white/10 transition-colors z-50 group"
                title={isLoggedIn ? "Admin Mode Ativo" : "Visitor Mode"}
            >
                {isLoggedIn ? (
                    <Unlock className="w-4 h-4 text-cyber-primary" />
                ) : (
                    <Lock className="w-4 h-4 text-gray-500 group-hover:text-white" />
                )}
            </button>

            {isOpen && (
                <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 backdrop-blur-sm">
                    <div className="bg-[#0a0a0a] border border-white/10 p-6 rounded-lg w-full max-w-sm relative">
                        <button 
                            onClick={() => setIsOpen(false)}
                            className="absolute top-4 right-4 text-gray-400 hover:text-white"
                        >
                            <X className="w-5 h-5" />
                        </button>
                        
                        <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                            <Lock className="w-5 h-5 text-cyber-primary" />
                            Acesso Administrativo
                        </h2>
                        
                        {isLoggedIn ? (
                            <div>
                                <p className="text-gray-400 mb-6 text-sm">
                                    Você está autenticado. O "Live Mode" (Scans ZAP e Banco de Dados) está habilitado.
                                </p>
                                <button
                                    onClick={handleLogout}
                                    className="w-full bg-red-500/20 text-red-500 border border-red-500/50 py-2 rounded font-bold hover:bg-red-500 hover:text-white transition-colors"
                                >
                                    Sair do Modo Admin
                                </button>
                            </div>
                        ) : (
                            <form onSubmit={handleLogin} className="space-y-4">
                                <p className="text-gray-400 text-sm mb-4">
                                    Visitantes só têm acesso ao Demo Mode para proteger a infraestrutura. Insira a Master API Key para desbloquear.
                                </p>
                                <div>
                                    <input
                                        type="password"
                                        placeholder="Master API Key"
                                        value={apiKey}
                                        onChange={(e) => setApiKey(e.target.value)}
                                        className="w-full bg-black/50 border border-white/10 rounded p-3 text-white focus:border-cyber-primary outline-none"
                                        autoFocus
                                    />
                                </div>
                                <button
                                    type="submit"
                                    className="w-full bg-cyber-primary text-black font-bold py-2 rounded hover:bg-white transition-colors"
                                >
                                    Autenticar
                                </button>
                            </form>
                        )}
                    </div>
                </div>
            )}
        </>
    );
}
