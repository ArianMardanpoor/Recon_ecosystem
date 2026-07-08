import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Search, RotateCcw } from 'lucide-react';

interface SubdomainFiltersProps {
  filters: Record<string, string>;
  setFilter: (key: string, value: string | number | boolean | undefined) => void;
  resetFilters: () => void;
}

export function SubdomainFilters({ filters, setFilter, resetFilters }: SubdomainFiltersProps) {
  return (
    <div className="bg-card border rounded-lg p-4 space-y-4 shadow-sm">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 items-end">
        
        {/* جستجوی عمومی */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Search Subdomain</Label>
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="e.g. api.example.com"
              className="pl-8"
              value={filters.search || ''}
              onChange={(e) => setFilter('search', e.target.value)}
            />
          </div>
        </div>

        {/* فیلتر پروایدر */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Provider</Label>
          <Input
            placeholder="e.g. subfinder, amass"
            value={filters.provider || ''}
            onChange={(e) => setFilter('provider', e.target.value)}
          />
        </div>

        {/* فیلتر وضعیت لایو بودن */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Has Live IP</Label>
          <Select
            value={filters.has_live || 'any'}
            onValueChange={(val) => setFilter('has_live', val === 'any' ? undefined : val)}
          >
            <SelectTrigger>
              <SelectValue placeholder="Any" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Any</SelectItem>
              <SelectItem value="true">Yes (Live)</SelectItem>
              <SelectItem value="false">No (Dead)</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* فیلتر وضعیت HTTP */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Has HTTP Service</Label>
          <Select
            value={filters.has_http || 'any'}
            onValueChange={(val) => setFilter('has_http', val === 'any' ? undefined : val)}
          >
            <SelectTrigger>
              <SelectValue placeholder="Any" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Any</SelectItem>
              <SelectItem value="true">Yes</SelectItem>
              <SelectItem value="false">No</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* فیلتر مرتب‌سازی */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Sort By</Label>
          <Select
            value={filters.sort || '-created_date'}
            onValueChange={(val) => setFilter('sort', val)}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="-created_date">Newest First</SelectItem>
              <SelectItem value="created_date">Oldest First</SelectItem>
              <SelectItem value="-last_update">Recently Updated</SelectItem>
              <SelectItem value="subdomain">Alphabetical (A-Z)</SelectItem>
              <SelectItem value="-subdomain">Alphabetical (Z-A)</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* سوییچ فقط ساب‌دامین‌های جدید */}
        <div className="flex items-center gap-3 py-2">
          <Switch
            id="only_new"
            checked={filters.only_new === 'true'}
            onCheckedChange={(checked) => setFilter('only_new', checked ? 'true' : undefined)}
          />
          <Label htmlFor="only_new" className="text-sm font-medium cursor-pointer">
            Only New (24h)
          </Label>
        </div>
        
      </div>

      {/* دکمه ریست فیلترها */}
      <div className="flex justify-end pt-2 border-t">
        <Button variant="ghost" size="sm" onClick={resetFilters} className="gap-1.5 text-muted-foreground hover:text-foreground">
          <RotateCcw className="w-3.5 h-3.5" />
          Reset Filters
        </Button>
      </div>
    </div>
  );
}