import axios from 'axios';

function resolveApiBaseUrl() {
    const configuredUrl = process.env.NEXT_PUBLIC_API_URL?.trim();

    if (configuredUrl) {
        return `${configuredUrl.replace(/\/$/, '')}/api/v1`;
    }

    if (typeof window !== 'undefined') {
        const runtimeUrl = new URL(window.location.href);
        runtimeUrl.port = '8001';
        runtimeUrl.pathname = '/api/v1';
        runtimeUrl.search = '';
        runtimeUrl.hash = '';
        return runtimeUrl.toString().replace(/\/$/, '');
    }

    return 'http://localhost:8000/api/v1';
}

const api = axios.create({
    baseURL: resolveApiBaseUrl(),
    headers: {
        'Content-Type': 'application/json',
    },
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

export default api;
