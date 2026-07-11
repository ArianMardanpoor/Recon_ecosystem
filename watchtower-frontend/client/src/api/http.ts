// client/src/api/http.ts
import { apiClient } from './client'; //[cite: 3]

export const updateTestedStatus = async (subdomain: string, tested: boolean) => {
  const response = await apiClient.post('/tested', { subdomain, tested }); //[cite: 3]
  return response.data; //[cite: 3]
};

export async function getHttpServices(filters: Record<string, any>) {
  return apiClient.get('/http', { params: filters }); //[cite: 3]
}

// تابع جدید اضافه شده برای صفحه جزئیات
export async function getHttpServiceDetail(subdomain: string) {
  const response = await apiClient.get(`/api/http/${encodeURIComponent(subdomain)}`);
  return response.data;
}