import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Search, RotateCcw } from 'lucide-react';

interface LiveFiltersProps {
  filters: Record<string, string>;
  setFilter: (key: string, value: string | number | boolean | undefined) => void;
  resetFilters: () => void;
}

export function LiveFilters({ filters, setFilter, resetFilters }: LiveFiltersProps) {
  return (
    <div className="bg-card border rounded-lg p-4 space-y-4 shadow-sm">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 items-end">
        
        {/* جستجوی ساب‌دامین */}
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

        {/* فیلتر IP خاص */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">IP Address</Label>
          <Input
            placeholder="e.g. 1.2.3.4"
            value={filters.ip || ''}
            onChange={(e) => setFilter('ip', e.target.value)}
          />
        </div>

        {/* فیلتر نام CDN */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">CDN Name</Label>
          <Input
            placeholder="e.g. cloudflare"
            value={filters.cdn || ''}
            onChange={(e) => setFilter('cdn', e.target.value)}
          />
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
            </SelectContent>
          </Select>
        </div>

        {/* سوییچ‌ها */}
        <div className="flex items-center gap-6 py-2 col-span-1 md:col-span-2 lg:col-span-4">
          <div className="flex items-center gap-2">
            <Switch
              id="has_cdn"
              checked={filters.has_cdn === 'true'}
              onCheckedChange={(checked) => setFilter('has_cdn', checked ? 'true' : undefined)}
            />
            <Label htmlFor="has_cdn" className="text-sm font-medium cursor-pointer">Has CDN</Label>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="live_has_http"
              checked={filters.has_http === 'true'}
              onCheckedChange={(checked) => setFilter('has_http', checked ? 'true' : undefined)}
            />
            <Label htmlFor="live_has_http" className="text-sm font-medium cursor-pointer">Has HTTP</Label>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="live_only_new"
              checked={filters.only_new === 'true'}
              onCheckedChange={(checked) => setFilter('only_new', checked ? 'true' : undefined)}
            />
            <Label htmlFor="live_only_new" className="text-sm font-medium cursor-pointer">Only New (24h)</Label>
          </div>
        </div>

      </div>

      {/* دکمه ریست */}
      <div className="flex justify-end pt-2 border-t">
        <Button variant="ghost" size="sm" onClick={resetFilters} className="gap-1.5 text-muted-foreground hover:text-foreground">
          <RotateCcw className="w-3.5 h-3.5" />
          Reset Filters
        </Button>
      </div>
    </div>
  );
}