import { apiClient } from './client';

export async function getGlobalStats() {
  return apiClient.get('/stats');
}

export async function getTimelineStats(params?: Record<string, any>) {
  return apiClient.get('/stats/timeline', { params });
}