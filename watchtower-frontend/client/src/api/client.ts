import axios from 'axios';

// In development use relative /api so Vite proxy can forward requests to backend (avoids CORS)
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
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export async function downloadExport(path: string, params: Record<string, any> = {}) {
  return await apiClient.get(path, { params, responseType: 'blob' });
}
