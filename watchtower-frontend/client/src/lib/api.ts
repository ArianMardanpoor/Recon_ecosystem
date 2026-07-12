import axios from 'axios';

// در هر دو فایل api.ts و client.ts

const API_BASE_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? '/api' : 'http://localhost:3131/');
const API_TOKEN = import.meta.env.VITE_API_TOKEN;

if (import.meta.env.DEV && !API_TOKEN) {
  console.warn("⚠️ VITE_API_TOKEN is not set! Please define it in your .env file (see .env.example).");
}

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'X-API-Token': API_TOKEN || '', 
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Response interceptor to extract data and handle errors
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response) {
      const message = error.response.data?.message || error.response.statusText;
      console.error(`API Error (${error.response.status}):`, message);
    } else if (error.request) {
      console.error('API Error: No response from server');
    } else {
      console.error('API Error:', error.message);
    }
    return Promise.reject(error);
  }
);

// Export API methods with correct endpoint names
export const api = {
  // Dashboard
  getGlobalStats: () => apiClient.get('/stats'),
  
  // Subdomains
  getSubdomains: (params: Record<string, any>) => apiClient.get('/subdomains', { params }),
  
  // Programs
  getPrograms: (params: Record<string, any>) => apiClient.get('/programs', { params }),
  getProgramDetail: (name: string) => apiClient.get(`/programs/${name}`),
  
  // HTTP Services (endpoint is /api/http)
  getHttpServices: (params: Record<string, any>) => apiClient.get('/http', { params }),
  
  // Live Subdomains (endpoint is /api/lives)
  getLiveSubdomains: (params: Record<string, any>) => apiClient.get('/lives', { params }),
  
  // Assets
  getAssets: (params: Record<string, any>) => apiClient.get('/assets', { params }),
};
