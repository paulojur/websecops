import axios from 'axios';

const api = axios.create({
    baseURL: '/api/v1',
    headers: {
        'Content-Type': 'application/json',
    },
});

api.interceptors.request.use((config) => {
    if (typeof window !== 'undefined') {
        const apiKey = localStorage.getItem('admin_api_key');
        if (apiKey) {
            config.headers['X-API-Key'] = apiKey;
        }
    }
    return config;
});

export const getVulnerabilities = async (limit = 20) => {
    const response = await api.get(`/vulnerabilities/?limit=${limit}`);
    return response.data;
};

export const getIntelligence = async (limit = 20) => {
    const response = await api.get(`/intelligence/?limit=${limit}`);
    return response.data;
};

export const getStats = async () => {
    const response = await api.get(`/vulnerabilities/stats`);
    return response.data;
}

export const getTargets = async () => {
    const response = await api.get(`/targets/`);
    return response.data;
}

export const addTarget = async (url: string) => {
    const response = await api.post(`/targets/scan`, { url });
    return response.data;
}

export const analyzeTarget = async (url: string) => {
    const response = await api.post(`/targets/analyze`, { url });
    return response.data;
}

export const getTargetCorrelations = async (id: number) => {
    const response = await api.get(`/targets/${id}/correlations`);
    return response.data;
}

export const deleteTarget = async (id: number) => {
    const response = await api.delete(`/targets/${id}`);
    return response.data;
}

export const syncVulnerabilities = async () => {
    const response = await api.post(`/vulnerabilities/sync`);
    return response.data;
}

export const syncIntelligence = async () => {
    const response = await api.post(`/intelligence/sync`);
    return response.data;
}

// ZAP / Scan related
export const startSpiderScan = async (url: string) => {
    const response = await api.post(`/zap/spider`, null, { params: { target_url: url } });
    return response.data;
}

export const startActiveScan = async (url: string) => {
    const response = await api.post(`/zap/active`, null, { params: { target_url: url } });
    return response.data;
}

export const checkScanStatus = async (type: string, id: string) => {
    const response = await api.get(`/zap/status/${type}/${id}`);
    return response.data;
}

export const getScanResults = async (url: string) => {
    const response = await api.get(`/zap/results`, { params: { target_url: url } });
    return response.data;
}

export const saveScanHistory = async (url: string, type: string, alerts?: any[]) => {
    const response = await api.post(`/zap/save-history`, { target_url: url, scan_type: type, alerts });
    return response.data;
}

export const getTargetHistory = async (id: number) => {
    const response = await api.get(`/targets/${id}/history`);
    return response.data;
}


// Nuclei / Scan related
export const startNucleiScan = async (url: string) => {
    const response = await api.post(`/nuclei/scan`, { url });
    return response.data;
}

export const checkNucleiStatus = async (id: string) => {
    const response = await api.get(`/nuclei/status`, { params: { scanId: id } });
    return response.data;
}

export const getNucleiResults = async (id: string) => {
    const response = await api.get(`/nuclei/results`, { params: { scanId: id } });
    return response.data;
}

