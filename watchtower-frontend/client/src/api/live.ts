import { apiClient } from './client';

export async function getLiveSubdomains(filters: Record<string, any>) {
  return apiClient.get('/lives', { params: filters });
}

export async function getAssets(filters: Record<string, any>) {
  return apiClient.get('/assets', { params: filters });
}

// این تابع جدید رو اضافه کن
export async function exportLiveIPsAPI(filters: Record<string, any>) {
  const response = await apiClient.get('/export/lives/ips', { 
    params: filters,
    responseType: 'blob' 
  });
  
  // اگر apiClient دارای Interceptor باشه و مستقیماً فایل (Blob) رو برگردونده باشه
  if (response instanceof Blob) {
    return response;
  }
  
  // اگر ساختار استاندارد Axios دست‌نخورده باقی مونده باشه
  return response.data || response;
}