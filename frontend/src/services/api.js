import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
});

// Request interceptor to add JWT authorization token dynamically
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token expiry / unauthenticated requests
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear token and user session, redirect to login
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  login: async (email, password) => {
    const response = await api.post('/auth/login', { email, password });
    if (response.data.access_token) {
      localStorage.setItem('token', response.data.access_token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    return response.data;
  },
  register: async (name, email, password) => {
    const response = await api.post('/users/', { name, email, password });
    return response.data;
  },
  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch (e) {
      console.error('Logout error on server', e);
    }
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },
  changePassword: async (email, oldPassword, newPassword) => {
    const response = await api.put('/auth/change-password', {
      email,
      old_password: oldPassword,
      new_password: newPassword,
    });
    return response.data;
  }
};

export const reportAPI = {
  getReports: async () => {
    const response = await api.get('/reports/');
    return response.data;
  },
  uploadReport: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/reports/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  deleteReport: async (id) => {
    const response = await api.delete(`/reports/${id}`);
    return response.data;
  },
  getDownloadUrl: (id) => {
    const token = localStorage.getItem('token');
    return `${API_BASE_URL}/reports/${id}/download?token=${token}`;
  }
};

export const vulnerabilityAPI = {
  getVulnerabilities: async () => {
    const response = await api.get('/vulnerabilities/');
    return response.data;
  },
  getVulnerability: async (id) => {
    const response = await api.get(`/vulnerabilities/${id}`);
    return response.data;
  },
  updateVulnerability: async (id, severity, status) => {
    const response = await api.put(`/vulnerabilities/${id}`, { severity, status });
    return response.data;
  },
  deleteVulnerability: async (id) => {
    const response = await api.delete(`/vulnerabilities/${id}`);
    return response.data;
  }
};

export const kbAPI = {
  getKBItems: async () => {
    const response = await api.get('/knowledge-base/');
    return response.data;
  },
  getKBItem: async (cweId) => {
    const response = await api.get(`/knowledge-base/${cweId}`);
    return response.data;
  }
};

export const auditAPI = {
  getLogs: async () => {
    const response = await api.get('/logs/');
    return response.data;
  }
};

export default api;
