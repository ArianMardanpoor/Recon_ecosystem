import axios from 'axios';

// In development use relative /api so Vite proxy can forward requests to backend (avoids CORS)
const API_URL = import.meta.env.DEV ? '/api' : import.meta.env.VITE_API_URL || 'http://localhost:3131/';
const API_TOKEN = import.meta.env.VITE_API_TOKEN || 'a21uc0lzeTcK';

export const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'X-API-Token': API_TOKEN,
    'Content-Type': 'application/json',
  },
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
