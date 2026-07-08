import { useCallback } from 'react';
import { useFilters } from './useFilters';

export function usePagination(defaultPerPage = 50) {
  const { filters, setFilter } = useFilters({ page: '1', per_page: defaultPerPage.toString() });

  const page = Math.max(1, parseInt(filters.page || '1', 10));
  const perPage = Math.max(1, parseInt(filters.per_page || defaultPerPage.toString(), 10));

  // Set page with bounds checking
  const setPage = useCallback(
    (newPage: number) => {
      const validPage = Math.max(1, newPage);
      setFilter('page', validPage.toString());
    },
    [setFilter]
  );

  // Set items per page and reset to page 1
  const setPerPage = useCallback(
    (newPerPage: number) => {
      const validPerPage = Math.max(1, newPerPage);
      setFilter('per_page', validPerPage.toString());
      // Note: setFilter already resets page to 1 for non-page filters
    },
    [setFilter]
  );

  return { page, perPage, setPage, setPerPage };
}
