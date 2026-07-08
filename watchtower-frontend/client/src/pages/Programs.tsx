import { useQuery } from '@tanstack/react-query';
import { Download, AlertCircle, Shield, ShieldOff, ChevronLeft, ChevronRight } from 'lucide-react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { useFilters } from '@/hooks/useFilters';
import { getPrograms } from '@/api/programs';
import { downloadExport } from '@/api/client';
import { showToast } from '@/lib/toast';

const DEFAULT_FILTERS = { page: '1', per_page: '50' };

export default function Programs() {
  const { filters, setFilter } = useFilters(DEFAULT_FILTERS);

  const page = parseInt(filters.page || '1', 10);
  const perPage = parseInt(filters.per_page || '50', 10);

  const { data, isLoading, error } = useQuery<any>({
    queryKey: ['programs', filters],
    queryFn: () => getPrograms(filters),
    placeholderData: (previousData: any) => previousData,
  });

  const handleExport = async () => {
    try {
      const result = await downloadExport('/export/programs', filters);
      const blob = result instanceof Blob ? result : new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'programs.json';
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

  const responseData = data as any;
  const programs = responseData?.data || [];
  const totalPages = responseData?.pages || 1;
  const total = responseData?.total || 0;

  return (
    <Layout>
      <div className="space-y-6">
        {/* هدر صفحه */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-foreground tracking-tight">Programs Directory</h1>
            <p className="text-muted-foreground mt-1 text-sm">
              {!isLoading && total 
                ? `Showing ${(page - 1) * perPage + 1} to ${Math.min(page * perPage, total)} of ${total} programs` 
                : 'Manage your security programs'}
            </p>
          </div>

          <Button onClick={handleExport} disabled={!programs.length} className="gap-2">
            <Download className="w-4 h-4" />
            Export
          </Button>
        </div>

        {/* خطای سرور */}
        {error && (
          <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 flex gap-3">
            <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-destructive">{error?.message || 'Failed to load programs'}</p>
            </div>
          </div>
        )}

        {/* حالت لودینگ (اسکلتون کارت‌ها) */}
        {isLoading && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="h-52 rounded-xl bg-muted/30 border border-border animate-pulse" />
            ))}
          </div>
        )}

        {/* گرید کارت‌ها */}
        {!isLoading && !error && (
          <>
            {programs.length === 0 ? (
              <div className="text-center py-16 text-muted-foreground">No programs found.</div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {programs.map((program: any) => (
                  <div 
                    key={program.program_name} 
                    className="flex flex-col justify-between bg-card border border-border rounded-xl p-5 hover:border-indigo-500/40 transition-all duration-200 shadow-sm hover:shadow-md hover:shadow-indigo-500/5 group"
                  >
                    {/* بخش بالای کارت: اسم و تاریخ */}
                    <div>
                      <h3 className="text-lg font-bold text-foreground truncate group-hover:text-indigo-400 transition-colors" title={program.program_name}>
                        {program.program_name || 'Unknown'}
                      </h3>
                      <p className="text-[11px] text-muted-foreground mt-1">
                        Added: {program.created_date || 'Unknown'}
                      </p>
                    </div>

                    {/* بخش وسط: شمارنده اسکوپ‌ها */}
                    <div className="flex items-center gap-4 mt-5 text-sm">
                      <div className="flex items-center gap-1.5 text-indigo-300">
                        <Shield className="w-4 h-4" />
                        <span className="font-medium">{Array.isArray(program.scopes) ? program.scopes.length : 0}</span>
                        <span className="text-muted-foreground text-xs">Scopes</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-rose-400">
                        <ShieldOff className="w-4 h-4" />
                        <span className="font-medium">{Array.isArray(program.outofscopes) ? program.outofscopes.length : 0}</span>
                        <span className="text-muted-foreground text-xs">Out</span>
                      </div>
                    </div>

                    {/* بخش پایین: دکمه‌های اکشن */}
                    <div className="mt-5 pt-4 border-t border-border/80 grid grid-cols-3 gap-2">
                      <Button variant="ghost" size="sm" className="text-xs text-muted-foreground hover:text-foreground">
                        Subs
                      </Button>
                      <Button variant="ghost" size="sm" className="text-xs text-muted-foreground hover:text-foreground">
                        Live
                      </Button>
                      <Button variant="ghost" size="sm" className="text-xs text-muted-foreground hover:text-foreground">
                        HTTP
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* صفحه‌بندی دستی (چون DataTable رو حذف کردیم) */}
            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-2 mt-8">
                <Button
                  variant="outline"
                  size="icon"
                  className="w-8 h-8"
                  onClick={() => handlePageChange(page - 1)}
                  disabled={page <= 1}
                >
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                
                <span className="text-sm text-muted-foreground px-2">
                  Page <span className="font-bold text-foreground">{page}</span> of {totalPages}
                </span>
                
                <Button
                  variant="outline"
                  size="icon"
                  className="w-8 h-8"
                  onClick={() => handlePageChange(page + 1)}
                  disabled={page >= totalPages}
                >
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
}