import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Users CRUD API
export const getUsers = () => api.get('/users/');
export const getUser = (id) => api.get(`/users/${id}`);
export const createUser = (data) => api.post('/users/', data);
export const updateUser = (id, data) => api.put(`/users/${id}`, data);
export const deleteUser = (id) => api.delete(`/users/${id}`);

// Reports CRUD API
export const getReports = () => api.get('/reports/');
export const getReport = (id) => api.get(`/reports/${id}`);
export const uploadReport = (formData) => api.post('/reports/upload', formData, {
  headers: { 'Content-Type': 'multipart/form-data' },
});
export const updateReport = (id, data) => api.put(`/reports/${id}`, data);
export const deleteReport = (id) => api.delete(`/reports/${id}`);

// Vulnerabilities CRUD API
export const getVulnerabilities = () => api.get('/vulnerabilities/');
export const getVulnerability = (id) => api.get(`/vulnerabilities/${id}`);
export const createVulnerability = (data) => api.post('/vulnerabilities/', data);
export const updateVulnerability = (id, data) => api.put(`/vulnerabilities/${id}`, data);
export const deleteVulnerability = (id) => api.delete(`/vulnerabilities/${id}`);

// Knowledge Base CRUD API
export const getKnowledgeBase = () => api.get('/knowledge-base/');
export const getKnowledgeBaseEntry = (id) => api.get(`/knowledge-base/${id}`);
export const createKnowledgeBase = (data) => api.post('/knowledge-base/', data);
export const updateKnowledgeBase = (id, data) => api.put(`/knowledge-base/${id}`, data);
export const deleteKnowledgeBase = (id) => api.delete(`/knowledge-base/${id}`);

export default api;