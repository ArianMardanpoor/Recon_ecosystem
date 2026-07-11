import { apiClient } from './client'; //[cite: 3]

export const updateTestedStatus = async (subdomain: string, tested: boolean) => {
  const response = await apiClient.post('/tested', { subdomain, tested }); //[cite: 3]
  return response.data; //[cite: 3]
};

export async function getHttpServices(filters: Record<string, any>) {
  return apiClient.get('/http', { params: filters }); //[cite: 3]
}

export async function getHttpServiceDetail(subdomain: string) {
  // بدون await و بدون .data، دقیقاً مثل تابع بالایی
  return apiClient.get(`/http/${encodeURIComponent(subdomain)}`);
}