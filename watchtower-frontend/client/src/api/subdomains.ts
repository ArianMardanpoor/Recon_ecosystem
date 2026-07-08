import { apiClient } from './client';

export interface SubdomainFilters {
  program?: string;
  programs?: string; // لیست جدا شده با کاما
  scope?: string;
  provider?: string;
  providers?: string; // لیست جدا شده با کاما
  search?: string;
  has_http?: string; // 'true' یا 'false'
  has_live?: string; // 'true' یا 'false'
  created_after?: string;
  created_before?: string;
  updated_after?: string;
  updated_before?: string;
  only_new?: string; // 'true'
  sort?: string;
  page?: number;
  per_page?: number;
}

export const getSubdomains = async (params: SubdomainFilters = {}) => {
  // چون در client.ts baseURL رو روی /api تنظیم کردیم، اینجا فقط /subdomains رو می‌نویسیم
  return await apiClient.get('/subdomains', { params });
};