import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Search, RotateCcw } from 'lucide-react';

interface HttpFiltersProps {
  filters: Record<string, string>;
  setFilter: (key: string, value: string | number | boolean | undefined) => void;
  resetFilters: () => void;
}

export function HttpFilters({ filters, setFilter, resetFilters }: HttpFiltersProps) {
  // Helper to determine the current value for the Scan Status dropdown
  const getScanStatusValue = () => {
    if (filters.scan_statuses === 'clean,findings,confirmed_vuln') return 'scanned';
    if (filters.scan_status) return filters.scan_status;
    return 'all';
  };

  return (
    <div className="bg-card border rounded-lg p-4 space-y-4 shadow-sm">
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4 items-end">
        
        {/* Search URL / Title */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Search URL / Title</Label>
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="e.g. login, wordpress"
              className="pl-8"
              value={filters.search || ''}
              onChange={(e) => setFilter('search', e.target.value)}
            />
          </div>
        </div>

        {/* Program */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Program</Label>
          <Input
            placeholder="e.g. luminor"
            value={filters.program || ''}
            onChange={(e) => setFilter('program', e.target.value)}
          />
        </div>

        {/* Status Code */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Status Code</Label>
          <Input
            placeholder="e.g. 200, 403 or 200-299"
            value={filters.status_code || ''}
            onChange={(e) => setFilter('status_code', e.target.value)}
          />
        </div>

        {/* Technology */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Technology</Label>
          <Input
            placeholder="e.g. nginx, wordpress"
            value={filters.tech || ''}
            onChange={(e) => setFilter('tech', e.target.value)}
          />
        </div>

        {/* Provider */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Provider</Label>
          <Input
            placeholder="e.g. subfinder, crtsh"
            value={filters.provider || ''}
            onChange={(e) => setFilter('provider', e.target.value)}
          />
        </div>

        {/* Tested Status */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Tested Status</Label>
          <Select
            value={filters.tested === undefined ? 'all' : String(filters.tested)}
            onValueChange={(val) => setFilter('tested', val === 'all' ? undefined : val)}
          >
            <SelectTrigger>
              <SelectValue placeholder="All Targets" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Targets</SelectItem>
              <SelectItem value="true">Tested Only</SelectItem>
              <SelectItem value="false">Untested Only</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Scan Status (NEW) */}
        <div className="space-y-1.5">
          <Label className="text-sm font-medium">Scan Status</Label>
          <Select
            value={getScanStatusValue()}
            onValueChange={(val) => {
              if (val === 'all') {
                setFilter('scan_statuses', undefined);
                setFilter('scan_status', undefined);
              } else if (val === 'scanned') {
                setFilter('scan_status', undefined);
                setFilter('scan_statuses', 'clean,findings,confirmed_vuln');
              } else {
                setFilter('scan_statuses', undefined);
                setFilter('scan_status', val);
              }
            }}
          >
            <SelectTrigger>
              <SelectValue placeholder="Any Scan Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Any Scan Status</SelectItem>
              <SelectItem value="scanned">Scanned Only (Any Result)</SelectItem>
              <SelectItem value="not_scanned">Not Scanned Yet</SelectItem>
              <SelectItem value="clean">Clean (No Findings)</SelectItem>
              <SelectItem value="findings">Has Findings</SelectItem>
              <SelectItem value="confirmed_vuln">Confirmed Vulnerability</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Sort By */}
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
              <SelectItem value="-last_scan_date">Recently Scanned</SelectItem>
              <SelectItem value="status_code">Status Code (Asc)</SelectItem>
              <SelectItem value="-status_code">Status Code (Desc)</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Switches */}
        <div className="flex items-center gap-6 py-2 col-span-1 md:col-span-3 lg:col-span-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Switch
              id="has_tech"
              checked={filters.has_tech === 'true'}
              onCheckedChange={(checked) => setFilter('has_tech', checked ? 'true' : undefined)}
            />
            <Label htmlFor="has_tech" className="text-sm font-medium cursor-pointer whitespace-nowrap">Has Tech</Label>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="has_favicon"
              checked={filters.has_favicon === 'true'}
              onCheckedChange={(checked) => setFilter('has_favicon', checked ? 'true' : undefined)}
            />
            <Label htmlFor="has_favicon" className="text-sm font-medium cursor-pointer whitespace-nowrap">Has Favicon</Label>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="only_single_provider"
              checked={filters.only_single_provider === 'true'}
              onCheckedChange={(checked) => setFilter('only_single_provider', checked ? 'true' : undefined)}
            />
            <Label htmlFor="only_single_provider" className="text-sm font-medium cursor-pointer whitespace-nowrap">
              Single Provider Only
            </Label>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="only_new_http"
              checked={filters.only_new === 'true'}
              onCheckedChange={(checked) => setFilter('only_new', checked ? 'true' : undefined)}
            />
            <Label htmlFor="only_new_http" className="text-sm font-medium cursor-pointer whitespace-nowrap">Only New (24h)</Label>
          </div>

          <div className="flex items-center gap-2">
            <Switch
              id="only_changed"
              checked={filters.only_changed === 'true'}
              onCheckedChange={(checked) => setFilter('only_changed', checked ? 'true' : undefined)}
            />
            <Label htmlFor="only_changed" className="text-sm font-medium cursor-pointer whitespace-nowrap">Only Changed (24h)</Label>
          </div>
        </div>

      </div>

      <div className="flex justify-end pt-2 border-t">
        <Button variant="ghost" size="sm" onClick={resetFilters} className="gap-1.5 text-muted-foreground hover:text-foreground">
          <RotateCcw className="w-3.5 h-3.5" />
          Reset Filters
        </Button>
      </div>
    </div>
  );
}