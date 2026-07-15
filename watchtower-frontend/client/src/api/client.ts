import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? '/api' : 'http://localhost:3131/');

// اضافه کردن هشدار مربوط به VPS
if (!import.meta.env.VITE_API_URL) {
  console.warn("⚠️ لطفاً VITE_API_URL را به آدرس فعلی سرور VPS تنظیم کنید (مثلاً http://<VPS_IP>:3131/api). در حال حاضر از مقدار پیش‌فرض استفاده می‌شود.");
}

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Response interceptor to extract data and handle errors
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    let errorMessage = 'An unknown error occurred';

    if (error.response) {
      // The request was made and the server responded with a status code outside the 2xx range
      errorMessage = error.response.data?.message || error.response.statusText;
      console.error(`API Error (${error.response.status}):`, errorMessage);
    } else if (error.request) {
      // The request was made but no response was received (CORS or Network Failure)
      errorMessage = 'Network Error: No response from server. This may be a CORS issue or the backend is down.';
      console.error(errorMessage);
    } else {
      // Something happened in setting up the request
      errorMessage = error.message;
      console.error('API Error:', errorMessage);
    }
    
    // Rethrow with a clear Error object so the UI can catch and display it
    return Promise.reject(new Error(errorMessage));
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

export async function downloadExport(
  path: string,
  params: Record<string, any> = {}
) {
  return apiClient.get(path, {
    params,
    responseType: 'blob',
  });
}