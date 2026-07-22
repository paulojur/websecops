export type AppMode = 'live' | 'demo';

const DEMO_MODE_KEY = 'websecops_app_mode';
const DEMO_TARGETS_KEY = 'websecops_demo_targets';

export function getAppMode(): AppMode {
    if (typeof window === 'undefined') return 'demo';
    const mode = localStorage.getItem(DEMO_MODE_KEY);
    if (!mode) {
        // Default to demo for new visitors (LinkedIn showcase)
        localStorage.setItem(DEMO_MODE_KEY, 'demo');
        return 'demo';
    }
    return mode as AppMode;
}

export function setAppMode(mode: AppMode) {
    if (typeof window !== 'undefined') {
        localStorage.setItem(DEMO_MODE_KEY, mode);
    }
}

export function getDemoTargets(): any[] {
    if (typeof window === 'undefined') return [];
    try {
        const data = localStorage.getItem(DEMO_TARGETS_KEY);
        return data ? JSON.parse(data) : [];
    } catch {
        return [];
    }
}

export function saveDemoTarget(targetData: any) {
    if (typeof window === 'undefined') return;
    const targets = getDemoTargets();
    
    // Ensure we don't duplicate by URL
    const existingIndex = targets.findIndex(t => t.url === targetData.url);
    if (existingIndex >= 0) {
        targets[existingIndex] = targetData;
    } else {
        targets.unshift(targetData);
    }
    
    localStorage.setItem(DEMO_TARGETS_KEY, JSON.stringify(targets));
}

export function deleteDemoTarget(id: number) {
    if (typeof window === 'undefined') return;
    const targets = getDemoTargets();
    const filtered = targets.filter((t: any) => t.id !== id);
    localStorage.setItem(DEMO_TARGETS_KEY, JSON.stringify(filtered));
}

export function getDemoTarget(id: number): any {
    const targets = getDemoTargets();
    return targets.find((t: any) => t.id === id) || null;
}

const DEMO_SCAN_HISTORY_KEY = 'websecops_demo_scan_history';

export function getDemoScanHistory(): any[] {
    if (typeof window === 'undefined') return [];
    try {
        const data = localStorage.getItem(DEMO_SCAN_HISTORY_KEY);
        return data ? JSON.parse(data) : [];
    } catch {
        return [];
    }
}

export function saveDemoScanHistory(scanData: any) {
    if (typeof window === 'undefined') return;
    const history = getDemoScanHistory();
    history.unshift({
        id: Date.now().toString(),
        created_at: new Date().toISOString(),
        ...scanData
    });
    localStorage.setItem(DEMO_SCAN_HISTORY_KEY, JSON.stringify(history.slice(0, 30)));
}
