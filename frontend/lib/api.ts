import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:8000/api/v1',
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

export default api;
