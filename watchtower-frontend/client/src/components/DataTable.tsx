import { ChevronLeft, ChevronRight, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface DataTableProps {
  columns: Array<{
    key: string;
    label: string;
    render?: (value: any, row: any) => React.ReactNode;
  }>;
  data: any[];
  isLoading?: boolean;
  currentPage?: number;
  totalPages?: number;
  onPageChange?: (page: number) => void;
  perPage?: number;
  onPerPageChange?: (perPage: number) => void;
  total?: number;
}

export function DataTable({
  columns,
  data,
  isLoading,
  currentPage = 1,
  totalPages = 1,
  onPageChange,
  perPage = 100,
  onPerPageChange,
  total = 0,
}: DataTableProps) {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 bg-card border border-border rounded-lg">
        <div className="flex flex-col items-center gap-2">
          <Loader2 className="w-8 h-8 animate-spin text-accent" />
          <p className="text-sm text-muted-foreground">Loading data...</p>
        </div>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 bg-card border border-border rounded-lg">
        <div className="text-center">
          <p className="text-sm text-muted-foreground">No data found</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Table */}
      <div className="border border-border rounded-lg overflow-hidden bg-card shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10">
              <tr className="border-b border-border bg-muted/50">
                {columns.map((col) => (
                  <th
                    key={col.key}
                    className="px-4 py-3 text-left font-semibold text-foreground"
                  >
                    {col.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((row, idx) => (
                <tr
                  key={idx}
                  className={cn(
                    'border-b border-border transition-colors duration-150',
                    idx % 2 === 0 ? 'bg-background' : 'bg-muted/20',
                    'hover:bg-muted/40 hover:shadow-sm'
                  )}
                >
                  {columns.map((col) => (
                    <td key={col.key} className="px-4 py-3 text-foreground truncate">
                      {col.render ? col.render(row[col.key], row) : row[col.key]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {total > 0 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-card border border-border rounded-lg p-4">
          <div className="text-sm text-muted-foreground">
            Showing <span className="font-semibold text-foreground">{(currentPage - 1) * perPage + 1}</span> to{' '}
            <span className="font-semibold text-foreground">
              {Math.min(currentPage * perPage, total)}
            </span>{' '}
            of <span className="font-semibold text-foreground">{total}</span> entries
          </div>

          <div className="flex items-center gap-4">
            <select
              value={perPage}
              onChange={(e) => onPerPageChange?.(Number(e.target.value))}
              className="bg-background border border-border rounded px-2 py-1 text-sm text-foreground outline-none focus:ring-2 focus:ring-accent"
            >
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
              <option value={100}>100 per page</option>
              <option value={500}>500 per page</option>
            </select>

            <div className="flex items-center gap-1">
              <Button
                onClick={() => onPageChange?.(currentPage - 1)}
                disabled={currentPage <= 1}
                variant="outline"
                size="sm"
              >
                <ChevronLeft className="w-4 h-4" />
              </Button>

              <div className="px-3 py-1 text-sm font-medium text-foreground bg-muted rounded">
                {currentPage} / {totalPages}
              </div>

              <Button
                onClick={() => onPageChange?.(currentPage + 1)}
                disabled={currentPage >= totalPages}
                variant="outline"
                size="sm"
              >
                <ChevronRight className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
