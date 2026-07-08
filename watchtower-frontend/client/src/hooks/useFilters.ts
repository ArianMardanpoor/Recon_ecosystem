import { useState, useCallback } from 'react';
import { useLocation } from 'wouter';

export function useFilters(defaultFilters: Record<string, string> = { page: '1', per_page: '100' }) {
  const [location, navigate] = useLocation();

  // منبع اصلی فیلترها حالا State ری‌اکت هست، نه URL
  const [filters, setFilters] = useState<Record<string, string>>(() => {
    // فقط در بار اول لود شدن، فیلترها رو از URL می‌خونیم
    const url = new URL(window.location.href);
    const params = url.searchParams;
    const currentFilters = { ...defaultFilters };
    params.forEach((value, key) => {
      currentFilters[key] = value;
    });
    return currentFilters;
  });

  // آپدیت کردن یک فیلتر خاص
  const setFilter = useCallback(
    (key: string, value: string | number | boolean | undefined) => {
      const newFilters = { ...filters };

      if (value === undefined || value === '' || value === null) {
        delete newFilters[key];
      } else {
        newFilters[key] = String(value);
      }

      // وقتی فیلتری غیر از صفحه عوض میشه، بریم صفحه اول
      if (key !== 'page' && key !== 'per_page') {
        newFilters.page = '1';
      }

      // ۱. اول استیت ری‌اکت رو آپدیت می‌کنیم تا سریع رندر بشه
      setFilters(newFilters);

      // ۲. بعد URL رو برای ذخیره مسیر آپدیت می‌کنیم
      const params = new URLSearchParams();
      Object.entries(newFilters).forEach(([k, v]) => {
        if (v !== undefined && v !== '') {
          params.set(k, v);
        }
      });

      navigate(`${location}?${params.toString()}`);
    },
    [filters, location, navigate]
  );

  // ریست کردن همه فیلترها
  const resetFilters = useCallback(() => {
    setFilters(defaultFilters);
    const params = new URLSearchParams(defaultFilters);
    navigate(`${location}?${params.toString()}`);
  }, [location, navigate, defaultFilters]);

  return { filters, setFilter, resetFilters };
}