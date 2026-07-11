// client/src/pages/HttpServices.tsx
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'; //[cite: 2]
import { Download, AlertCircle, SlidersHorizontal, ExternalLink } from 'lucide-react'; // ExternalLink اضافه شد
import { Link } from 'wouter'; // Link اضافه شد
import { Layout } from '@/components/Layout'; //[cite: 2]
import { DataTable } from '@/components/DataTable'; //[cite: 2]
import { HttpFilters } from '@/components/HttpFilters'; //[cite: 2]
import { Button } from '@/components/ui/button'; //[cite: 2]
import { Badge } from '@/components/ui/badge'; //[cite: 2]
import { Switch } from '@/components/ui/switch'; //[cite: 2]
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'; //[cite: 2]
import { useFilters } from '@/hooks/useFilters'; //[cite: 2]
import { useDebounce } from '@/hooks/useDebounce'; //[cite: 2]
import { getHttpServices, updateTestedStatus } from '@/api/http'; //[cite: 2]
import { downloadExport } from '@/api/client'; //[cite: 2]
import { showToast } from '@/lib/toast'; //[cite: 2]

const DEFAULT_FILTERS = { page: '1', per_page: '50' }; //[cite: 2]

const getStatusColor = (code: number) => { //[cite: 2]
  if (!code) return ''; //[cite: 2]
  if (code >= 200 && code < 300) return 'bg-green-500/20 text-green-400 border-green-500/30'; //[cite: 2]
  if (code >= 300 && code < 400) return 'bg-blue-500/20 text-blue-400 border-blue-500/30'; //[cite: 2]
  if (code >= 400 && code < 500) return 'bg-orange-500/20 text-orange-400 border-orange-500/30'; //[cite: 2]
  if (code >= 500) return 'bg-red-500/20 text-red-400 border-red-500/30'; //[cite: 2]
  return ''; //[cite: 2]
}; //[cite: 2]

export default function HttpServices() { //[cite: 2]
  const queryClient = useQueryClient(); //[cite: 2]
  const { filters, setFilter, resetFilters } = useFilters(DEFAULT_FILTERS); //[cite: 2]
  const debouncedFilters = useDebounce(filters, 500); //[cite: 2]

  const page = parseInt(filters.page || '1', 10); //[cite: 2]
  const perPage = parseInt(filters.per_page || '50', 10); //[cite: 2]

  const toggleTestedMutation = useMutation({ //[cite: 2]
    mutationFn: ({ subdomain, tested }: { subdomain: string; tested: boolean }) => //[cite: 2]
      updateTestedStatus(subdomain, tested), //[cite: 2]
    onSuccess: () => { //[cite: 2]
      queryClient.invalidateQueries({ queryKey: ['http'] }); //[cite: 2]
      showToast.success('Status Updated', 'Target testing status has been updated.'); //[cite: 2]
    }, //[cite: 2]
    onError: () => { //[cite: 2]
      showToast.error('Update Failed', 'Could not update the tested status.'); //[cite: 2]
    }, //[cite: 2]
  }); //[cite: 2]

  const allColumns = [ //[cite: 2]
    { 
      key: 'url', 
      label: 'URL', 
      render: (val: any, row: any) => { //[cite: 2]
        const displayText = val || row.subdomain || '-'; //[cite: 2]
        if (displayText === '-') return <span className="text-muted-foreground text-xs">-</span>; //[cite: 2]
        const href = displayText.startsWith('http') ? displayText : `https://${displayText}`; //[cite: 2]
        
        return ( //[cite: 2]
          <div className="flex items-center gap-2 group">
            <Link href={`/http-services/${encodeURIComponent(row.subdomain)}`}>
              <span 
                className="font-mono text-xs text-blue-400 hover:text-blue-300 hover:underline cursor-pointer transition-colors break-all"
                title="View Dashboard Details"
              >
                {displayText}
              </span>
            </Link>
            <a 
              href={href} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="text-muted-foreground hover:text-white transition-colors opacity-0 group-hover:opacity-100"
              title="Open Target Externally" 
            >
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        );
      } 
    },
    { 
      key: 'status_code', 
      label: 'Status', 
      render: (val: any) => ( //[cite: 2]
        <Badge variant="outline" className={`font-mono text-[11px] ${getStatusColor(val)}`}> 
          {val || '-'} 
        </Badge> 
      ) //[cite: 2]
    }, //[cite: 2]
    { 
      key: 'title', 
      label: 'Title', 
      render: (val: any) => <span className="text-xs truncate block max-w-[200px]" title={val}>{val || '-'}</span>  //[cite: 2]
    }, //[cite: 2]
    { 
      key: 'tech', 
      label: 'Technology', 
      render: (val: any) => ( //[cite: 2]
        <div className="flex flex-wrap gap-1"> 
          {Array.isArray(val) && val.length > 0 ? val.map((t: string) => ( //[cite: 2]
            <Badge key={t} variant="secondary" className="text-[10px] px-1.5 py-0.5 bg-purple-500/20 text-purple-300 border-purple-500/30"> 
              {t} 
            </Badge> 
          )) : <span className="text-muted-foreground text-xs">-</span>} 
        </div> //[cite: 2]
      ) //[cite: 2]
    }, //[cite: 2]
    { 
      key: 'providers', 
      label: 'Providers', 
      render: (val: any) => ( //[cite: 2]
        <div className="flex flex-wrap gap-1"> 
          {Array.isArray(val) && val.length > 0 ? val.map((p: string) => ( //[cite: 2]
            <Badge key={p} variant="secondary" className="text-[10px] px-1.5 py-0.5 bg-sky-500/20 text-sky-300 border-sky-500/30"> 
              {p} 
            </Badge> 
          )) : <span className="text-muted-foreground text-xs">-</span>} 
        </div> //[cite: 2]
      ) //[cite: 2]
    }, //[cite: 2]
    { key: 'program_name', label: 'Program' }, //[cite: 2]
    { 
      key: 'tested', 
      label: 'Tested', 
      render: (val: any, row: any) => ( //[cite: 2]
        <Switch //[cite: 2]
          checked={val === true} //[cite: 2]
          onCheckedChange={(checked) =>  //[cite: 2]
            toggleTestedMutation.mutate({ subdomain: row.subdomain, tested: checked }) //[cite: 2]
          } //[cite: 2]
          disabled={toggleTestedMutation.isPending} //[cite: 2]
        /> //[cite: 2]
      ) //[cite: 2]
    }, //[cite: 2]
    { key: 'last_update', label: 'Last Updated' }, //[cite: 2]
  ]; //[cite: 2]

  const [visibleColumns, setVisibleColumns] = useState<Set<string>>( //[cite: 2]
    new Set(['url', 'status_code', 'title', 'tech', 'providers', 'program_name', 'tested', 'last_update']) //[cite: 2]
  ); //[cite: 2]

  const toggleColumn = (key: string) => { //[cite: 2]
    setVisibleColumns(prev => { //[cite: 2]
      const next = new Set(prev); //[cite: 2]
      if (next.has(key)) next.delete(key); else next.add(key); //[cite: 2]
      return next; //[cite: 2]
    }); //[cite: 2]
  }; //[cite: 2]

  const columns = allColumns.filter(col => visibleColumns.has(col.key)); //[cite: 2]

  const { data, isLoading, error } = useQuery<any>({ //[cite: 2]
    queryKey: ['http', debouncedFilters], //[cite: 2]
    queryFn: () => getHttpServices(debouncedFilters), //[cite: 2]
    placeholderData: (previousData: any) => previousData, //[cite: 2]
  }); //[cite: 2]

  const handleExport = async () => { //[cite: 2]
    try { //[cite: 2]
      const result = await downloadExport('/export/urls', debouncedFilters); //[cite: 2]
      const blob = result instanceof Blob ? result : new Blob([result], { type: 'text/plain' }); //[cite: 2]
      const url = window.URL.createObjectURL(blob); //[cite: 2]
      const anchor = document.createElement('a'); //[cite: 2]
      anchor.href = url; //[cite: 2]
      anchor.download = 'http-urls.txt'; //[cite: 2]
      document.body.appendChild(anchor); //[cite: 2]
      anchor.click(); //[cite: 2]
      anchor.remove(); //[cite: 2]
      window.URL.revokeObjectURL(url); //[cite: 2]
      showToast.success('Export successful', 'File downloaded successfully'); //[cite: 2]
    } catch (err) { //[cite: 2]
      console.error('Export failed:', err); //[cite: 2]
      showToast.error('Export failed', 'Could not download the file'); //[cite: 2]
    } //[cite: 2]
  }; //[cite: 2]

  const handlePageChange = (newPage: number) => setFilter('page', String(newPage)); //[cite: 2]
  const handlePerPageChange = (newPerPage: number) => { //[cite: 2]
    setFilter('per_page', String(newPerPage)); //[cite: 2]
    setFilter('page', '1'); //[cite: 2]
  }; //[cite: 2]

  const responseData = data as any; //[cite: 2]

  return ( //[cite: 2]
    <Layout> 
      <div className="space-y-6"> 
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4"> 
          <div> 
            <h1 className="text-3xl font-bold text-foreground">HTTP Services</h1> 
            <p className="text-muted-foreground mt-1"> 
              {!isLoading && responseData?.total  //[cite: 2]
                ? `Showing ${(page - 1) * perPage + 1} to ${Math.min(page * perPage, responseData.total)} of ${responseData.total} HTTP services`  //[cite: 2]
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
                {allColumns.map((col) => ( //[cite: 2]
                  <DropdownMenuCheckboxItem //[cite: 2]
                    key={col.key} //[cite: 2]
                    checked={visibleColumns.has(col.key)} //[cite: 2]
                    onCheckedChange={() => toggleColumn(col.key)} //[cite: 2]
                  > 
                    {col.label} 
                  </DropdownMenuCheckboxItem> //[cite: 2]
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

        {error && ( //[cite: 2]
          <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 flex gap-3"> 
            <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" /> 
            <div> 
              <p className="text-sm font-medium text-destructive">{error?.message || 'Failed to load HTTP services'}</p> 
            </div> 
          </div> //[cite: 2]
        )} 

        <DataTable //[cite: 2]
          columns={columns} //[cite: 2]
          data={responseData?.data || []} //[cite: 2]
          isLoading={isLoading} //[cite: 2]
          currentPage={page} //[cite: 2]
          totalPages={responseData?.pages || 1} //[cite: 2]
          onPageChange={handlePageChange} //[cite: 2]
          perPage={perPage} //[cite: 2]
          onPerPageChange={handlePerPageChange} //[cite: 2]
          total={responseData?.total || 0} //[cite: 2]
        /> 
      </div> 
    </Layout> //[cite: 2]
  );
}