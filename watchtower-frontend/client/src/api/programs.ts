import { apiClient } from './client';

export async function getPrograms(filters: Record<string, any>) {
  return apiClient.get('/programs', { params: filters });
}
