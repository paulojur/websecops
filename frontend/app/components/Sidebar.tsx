'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LayoutDashboard, Target, ShieldAlert, Newspaper, Settings, Zap } from 'lucide-react';

const menuItems = [
    { name: 'Dashboard', icon: LayoutDashboard, path: '/' },
    { name: 'Meus Alvos', icon: Target, path: '/targets' },
    { name: 'Centro de Scan', icon: Zap, path: '/scans' },
    { name: 'Vulnerabilidades', icon: ShieldAlert, path: '/vulns' },
    { name: 'Inteligência', icon: Newspaper, path: '/intelligence' },
];

export default function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="w-64 h-screen bg-cyber-panel border-r border-white/5 flex flex-col shrink-0 z-50">
            {/* Logo Area */}
            <div className="p-6 border-b border-white/5 flex items-center gap-3">
                <Zap className="w-8 h-8 text-cyber-primary" />
                <div>
                    <h1 className="font-bold text-white tracking-wider">WEB<span className="text-cyber-primary">SECOPS</span></h1>
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest">QA Security</p>
                </div>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-4 space-y-2">
                {menuItems.map((item) => {
                    const isActive = pathname === item.path;
                    return (
                        <Link
                            key={item.path}
                            href={item.path}
                            className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group ${isActive
                                ? 'bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/20 shadow-[0_0_15px_rgba(0,255,157,0.1)]'
                                : 'text-gray-400 hover:text-white hover:bg-white/5'
                                }`}
                        >
                            <item.icon className={`w-5 h-5 ${isActive ? 'text-cyber-primary' : 'text-gray-500 group-hover:text-white'}`} />
                            <span className="font-medium text-sm">{item.name}</span>
                            {isActive && (
                                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-cyber-primary box-shadow-[0_0_10px_currentColor]" />
                            )}
                        </Link>
                    );
                })}
            </nav>

            {/* Footer / User */}
            <div className="p-4 border-t border-white/5 mx-4 mb-4">
                <div className="flex items-center gap-3 p-3 rounded bg-black/20 border border-white/5">
                    <div className="w-8 h-8 rounded bg-gradient-to-tr from-cyber-secondary to-blue-600 flex items-center justify-center font-bold text-xs text-white">
                        QA
                    </div>
                    <div className="overflow-hidden">
                        <p className="text-xs font-bold text-white truncate">QA Engineer</p>
                        <p className="text-[10px] text-gray-400 truncate">Security Dept.</p>
                    </div>
                    <Settings className="w-4 h-4 text-gray-500 ml-auto cursor-pointer hover:text-white" />
                </div>
            </div>
        </aside>
    );
}
