import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Download, AlertCircle, SlidersHorizontal } from 'lucide-react';
import { Layout } from '@/components/Layout';
import { DataTable } from '@/components/DataTable';
import { HttpFilters } from '@/components/HttpFilters';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch'; // ایمپورت سوییچ برای ستون
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useFilters } from '@/hooks/useFilters';
import { useDebounce } from '@/hooks/useDebounce';
// ایمپورت تابع آپدیت از فایل http (مطمئن شو مسیر درسته)
import { getHttpServices, updateTestedStatus } from '@/api/http';
import { downloadExport } from '@/api/client';
import { showToast } from '@/lib/toast';

const DEFAULT_FILTERS = { page: '1', per_page: '50' };

const getStatusColor = (code: number) => {
  if (!code) return '';
  if (code >= 200 && code < 300) return 'bg-green-500/20 text-green-400 border-green-500/30';
  if (code >= 300 && code < 400) return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  if (code >= 400 && code < 500) return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
  if (code >= 500) return 'bg-red-500/20 text-red-400 border-red-500/30';
  return '';
};

export default function HttpServices() {
  const queryClient = useQueryClient();
  const { filters, setFilter, resetFilters } = useFilters(DEFAULT_FILTERS);
  const debouncedFilters = useDebounce(filters, 500);

  const page = parseInt(filters.page || '1', 10);
  const perPage = parseInt(filters.per_page || '50', 10);

  // تابع Mutation برای تغییر وضعیت تست
  const toggleTestedMutation = useMutation({
    mutationFn: ({ subdomain, tested }: { subdomain: string; tested: boolean }) =>
      updateTestedStatus(subdomain, tested),
    onSuccess: () => {
      // رفرش کردن دیتاها بعد از آپدیت موفق
      queryClient.invalidateQueries({ queryKey: ['http'] });
      showToast.success('Status Updated', 'Target testing status has been updated.');
    },
    onError: () => {
      showToast.error('Update Failed', 'Could not update the tested status.');
    },
  });

  const allColumns = [
    { 
      key: 'url', 
      label: 'URL', 
      render: (val: any, row: any) => {
        const displayText = val || row.subdomain || '-';
        if (displayText === '-') return <span className="text-muted-foreground text-xs">-</span>;
        const href = displayText.startsWith('http') ? displayText : `https://${displayText}`;
        
        return (
          <a 
            href={href} 
            target="_blank" 
            rel="noopener noreferrer" 
            className="font-mono text-xs text-blue-400 hover:text-blue-300 hover:underline break-all transition-colors"
            title={displayText} 
          >
            {displayText}
          </a>
        );
      } 
    },
    { 
      key: 'status_code', 
      label: 'Status', 
      render: (val: any) => (
        <Badge variant="outline" className={`font-mono text-[11px] ${getStatusColor(val)}`}>
          {val || '-'}
        </Badge>
      )
    },
    { 
      key: 'title', 
      label: 'Title', 
      render: (val: any) => <span className="text-xs truncate block max-w-[200px]" title={val}>{val || '-'}</span> 
    },
    { 
      key: 'tech', 
      label: 'Technology', 
      render: (val: any) => (
        <div className="flex flex-wrap gap-1">
          {Array.isArray(val) && val.length > 0 ? val.map((t: string) => (
            <Badge key={t} variant="secondary" className="text-[10px] px-1.5 py-0.5 bg-purple-500/20 text-purple-300 border-purple-500/30">
              {t}
            </Badge>
          )) : <span className="text-muted-foreground text-xs">-</span>}
        </div>
      )
    },
    { 
      key: 'providers', 
      label: 'Providers', 
      render: (val: any) => (
        <div className="flex flex-wrap gap-1">
          {Array.isArray(val) && val.length > 0 ? val.map((p: string) => (
            <Badge key={p} variant="secondary" className="text-[10px] px-1.5 py-0.5 bg-sky-500/20 text-sky-300 border-sky-500/30">
              {p}
            </Badge>
          )) : <span className="text-muted-foreground text-xs">-</span>}
        </div>
      )
    },
    { key: 'program_name', label: 'Program' },
    // ستون جدید Tested
    { 
      key: 'tested', 
      label: 'Tested', 
      render: (val: any, row: any) => (
        <Switch
          checked={val === true}
          onCheckedChange={(checked) => 
            toggleTestedMutation.mutate({ subdomain: row.subdomain, tested: checked })
          }
          disabled={toggleTestedMutation.isPending}
        />
      )
    },
    { key: 'last_update', label: 'Last Updated' },
  ];

  // ستون tested به صورت پیش‌فرض قابل مشاهده است
  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(
    new Set(['url', 'status_code', 'title', 'tech', 'providers', 'program_name', 'tested', 'last_update'])
  );

  const toggleColumn = (key: string) => {
    setVisibleColumns(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  const columns = allColumns.filter(col => visibleColumns.has(col.key));

  const { data, isLoading, error } = useQuery<any>({
    queryKey: ['http', debouncedFilters],
    queryFn: () => getHttpServices(debouncedFilters),
    placeholderData: (previousData: any) => previousData,
  });

  const handleExport = async () => {
    try {
      const result = await downloadExport('/export/urls', debouncedFilters);
      const blob = result instanceof Blob ? result : new Blob([result], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'http-urls.txt';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
      showToast.success('Export successful', 'File downloaded successfully');
    } catch (err) {
      console.error('Export failed:', err);
      showToast.error('Export failed', 'Could not download the file');
    }
  };

  const handlePageChange = (newPage: number) => setFilter('page', String(newPage));
  const handlePerPageChange = (newPerPage: number) => {
    setFilter('per_page', String(newPerPage));
    setFilter('page', '1');
  };

  const responseData = data as any;

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-foreground">HTTP Services</h1>
            <p className="text-muted-foreground mt-1">
              {!isLoading && responseData?.total 
                ? `Showing ${(page - 1) * perPage + 1} to ${Math.min(page * perPage, responseData.total)} of ${responseData.total} HTTP services` 
                : 'Track HTTP services and endpoints'}
            </p>
          </div>

          <div className="flex gap-2">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <SlidersHorizontal className="w-4 h-4" />
                  Columns
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                {allColumns.map((col) => (
                  <DropdownMenuCheckboxItem
                    key={col.key}
                    checked={visibleColumns.has(col.key)}
                    onCheckedChange={() => toggleColumn(col.key)}
                  >
                    {col.label}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>

            <Button onClick={handleExport} disabled={!responseData?.data?.length} className="gap-2">
              <Download className="w-4 h-4" />
              Export
            </Button>
          </div>
        </div>

        <HttpFilters filters={filters} setFilter={setFilter} resetFilters={resetFilters} />

        {error && (
          <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 flex gap-3">
            <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-destructive">{error?.message || 'Failed to load HTTP services'}</p>
            </div>
          </div>
        )}

        <DataTable
          columns={columns}
          data={responseData?.data || []}
          isLoading={isLoading}
          currentPage={page}
          totalPages={responseData?.pages || 1}
          onPageChange={handlePageChange}
          perPage={perPage}
          onPerPageChange={handlePerPageChange}
          total={responseData?.total || 0}
        />
      </div>
    </Layout>
  );
}