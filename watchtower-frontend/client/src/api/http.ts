import { apiClient } from './client'; // مسیر apiClient خودت رو چک کن

export const updateTestedStatus = async (subdomain: string, tested: boolean) => {
  const response = await apiClient.post('/tested', { subdomain, tested }); 
  return response.data;
};
export async function getHttpServices(filters: Record<string, any>) {
  return apiClient.get('/http', { params: filters });
}
