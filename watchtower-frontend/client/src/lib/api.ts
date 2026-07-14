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
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export async function downloadExport(path: string, params: Record<string, any> = {}) {
  return await apiClient.get(path, { params, responseType: 'blob' });
}