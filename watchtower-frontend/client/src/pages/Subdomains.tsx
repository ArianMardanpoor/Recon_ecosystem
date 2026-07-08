import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Download, AlertCircle, SlidersHorizontal } from 'lucide-react';
import { Layout } from '@/components/Layout';
import { DataTable } from '@/components/DataTable';
import { SubdomainFilters } from '@/components/SubdomainFilters';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useFilters } from '@/hooks/useFilters';
import { useDebounce } from '@/hooks/useDebounce';
import { getSubdomains } from '@/api/subdomains';
import { downloadExport } from '@/api/client';
import { showToast } from '@/lib/toast';

const DEFAULT_FILTERS = { page: '1', per_page: '50' };

export default function Subdomains() {
  const { filters, setFilter, resetFilters } = useFilters(DEFAULT_FILTERS);
  const debouncedFilters = useDebounce(filters, 500);

  const page = parseInt(filters.page || '1', 10);
  const perPage = parseInt(filters.per_page || '50', 10);

  const allColumns = [
    { 
      key: 'subdomain', 
      label: 'Subdomain', 
      render: (val: any) => {
        const displayText = val || '-';
        
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
    { key: 'program_name', label: 'Program' },
    { key: 'scope', label: 'Scope' },
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
    { key: 'created_date', label: 'Created Date' },
    { key: 'last_update', label: 'Last Updated' },
  ];

  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(
    new Set(['subdomain', 'program_name', 'scope', 'providers', 'last_update'])
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
    queryKey: ['subdomains', debouncedFilters],
    queryFn: () => getSubdomains(debouncedFilters),
    placeholderData: (previousData: any) => previousData,
  });

  const handleExport = async () => {
    try {
      const result = await downloadExport('/export/subdomains', debouncedFilters);
      const blob = result instanceof Blob ? result : new Blob([result], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'subdomains.txt';
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
            <h1 className="text-3xl font-bold text-foreground">Subdomains Inventory</h1>
            <p className="text-muted-foreground mt-1">
              {!isLoading && responseData?.total 
                ? `Showing ${(page - 1) * perPage + 1} to ${Math.min(page * perPage, responseData.total)} of ${responseData.total} subdomains` 
                : 'Manage and filter subdomains'}
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

        <SubdomainFilters filters={filters} setFilter={setFilter} resetFilters={resetFilters} />

        {error && (
          <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 flex gap-3">
            <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-destructive">{error?.message || 'Failed to load subdomains'}</p>
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