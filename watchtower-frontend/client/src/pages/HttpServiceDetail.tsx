// client/src/pages/HttpServiceDetail.tsx
import { useState } from 'react';
import { useParams, Link } from 'wouter';
import { useQuery } from '@tanstack/react-query';
import { 
  ArrowLeft, Copy, Check, ShieldAlert, ShieldCheck, 
  Terminal, Globe, ExternalLink, Shield, Server, FileCode, KeyRound, AlertCircle 
} from 'lucide-react';
import { Layout } from '@/components/Layout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { getHttpServiceDetail } from '@/api/http';
import { showToast } from '@/lib/toast';

const TRANSLATE_REFLECTION: Record<string, string> = {
  'source_reflection': 'انعکاس در Source',
  'dom_sink_injection': 'تزریق در DOM Sink',
  'header_injection': 'تزریق در هدر',
  'json_body_injection': 'تزریق در بدنه JSON',
  'parameter_discovered': 'کشف پارامتر مخفی',
  'candidate_generated': 'کاندید تولید شده'
};

const getConfidenceStyles = (confidence: string) => {
  switch (confidence) {
    case 'HIGH':
      return 'bg-red-500/10 border-red-500 text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.2)] animate-pulse';
    case 'MEDIUM':
      return 'bg-orange-500/10 border-orange-500 text-orange-400';
    case 'LOW':
      return 'bg-gray-500/10 border-gray-500 text-gray-400';
    default:
      return 'bg-gray-500/10 border-gray-500 text-gray-400';
  }
};

const getScanStatusUI = (status: string) => {
  switch (status) {
    case 'confirmed_vuln':
      return { label: 'Confirmed Vulnerable', className: 'bg-red-500 border-red-500 text-white shadow-[0_0_20px_rgba(239,68,68,0.5)]', icon: ShieldAlert };
    case 'findings':
      return { label: 'Findings Discovered', className: 'bg-yellow-500/20 border-yellow-500 text-yellow-500', icon: AlertCircle };
    case 'clean':
      return { label: 'Clean', className: 'bg-green-500/20 border-green-500 text-green-400', icon: ShieldCheck };
    default:
      return { label: 'Not Scanned', className: 'bg-gray-500/20 border-gray-600 text-gray-400', icon: Shield };
  }
};

const getStatusCodeColor = (code: number) => {
  if (code >= 200 && code < 300) return 'text-green-400 border-green-500/30 bg-green-500/10';
  if (code >= 300 && code < 400) return 'text-blue-400 border-blue-500/30 bg-blue-500/10';
  if (code >= 400 && code < 500) return 'text-orange-400 border-orange-500/30 bg-orange-500/10';
  if (code >= 500) return 'text-red-400 border-red-500/30 bg-red-500/10';
  return 'text-gray-400 border-gray-500/30 bg-gray-500/10';
};

export default function HttpServiceDetail() {
  const { subdomain: encodedSubdomain } = useParams<{ subdomain: string }>();
  const subdomain = encodedSubdomain ? decodeURIComponent(encodedSubdomain) : '';
  const [copied, setCopied] = useState(false);
  const [filterConfidence, setFilterConfidence] = useState('ALL');

  const { data, isLoading, error } = useQuery({
    queryKey: ['httpDetail', subdomain],
    queryFn: () => getHttpServiceDetail(subdomain),
    enabled: !!subdomain,
  });

  const handleCopy = (text: string, isAll = false) => {
    navigator.clipboard.writeText(text);
    if (!isAll) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } else {
      showToast.success('Copied', 'All URLs copied to clipboard');
    }
  };

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center h-full">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
        </div>
      </Layout>
    );
  }

  if (error || !data) {
    return (
      <Layout>
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-6">
          <h2 className="text-xl font-bold text-destructive mb-2">Error Loading Data</h2>
          <p className="text-muted-foreground">{error?.message || 'Failed to load details for this target.'}</p>
          <Link href="/http-services">
            <Button variant="outline" className="mt-4">Back to Services</Button>
          </Link>
        </div>
      </Layout>
    );
  }

  const { 
    url, title, status_code, tech, ips, headers, favicon, 
    passive_urls, crawled_urls, discovered_params, scan_status, last_scan_date, findings 
  } = data;

  const StatusInfo = getScanStatusUI(scan_status);
  const filteredFindings = filterConfidence === 'ALL' 
    ? findings || [] 
    : (findings || []).filter((f: any) => f.confidence === filterConfidence);

  const isCompletelyEmpty = scan_status === 'not_scanned' && 
                            (!passive_urls?.length) && 
                            (!crawled_urls?.length) && 
                            (!discovered_params?.length);

  return (
    <Layout>
      <div className="space-y-6 animate-in fade-in zoom-in-95 duration-500">
        
        {/* هدر بالای صفحه */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-black/40 border border-white/5 p-6 rounded-xl backdrop-blur-sm">
          <div className="flex items-center gap-4">
            <Link href="/http-services">
              <Button variant="ghost" size="icon" className="h-10 w-10 text-muted-foreground hover:text-white">
                <ArrowLeft className="h-5 w-5" />
              </Button>
            </Link>
            
            <div>
              <div className="flex items-center gap-3">
                <h1 
                  className="text-2xl sm:text-3xl font-mono font-bold text-white cursor-pointer hover:text-primary transition-colors flex items-center gap-2"
                  onClick={() => handleCopy(subdomain)}
                  title="Click to copy"
                >
                  {subdomain}
                  {copied ? <Check className="w-5 h-5 text-green-500" /> : <Copy className="w-4 h-4 text-muted-foreground" />}
                </h1>
                {url && (
                  <a href={url.startsWith('http') ? url : `https://${url}`} target="_blank" rel="noreferrer" className="text-muted-foreground hover:text-white transition-colors">
                    <ExternalLink className="w-5 h-5" />
                  </a>
                )}
              </div>
              <p className="text-muted-foreground text-sm mt-1">{title || 'No Title Available'}</p>
            </div>
          </div>

          <div className="flex flex-col items-end gap-2">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className={`px-3 py-1 text-sm font-mono ${getStatusCodeColor(status_code)}`}>
                {status_code || 'N/A'}
              </Badge>
              <Badge variant="outline" className={`px-3 py-1 text-sm flex items-center gap-2 ${StatusInfo.className}`}>
                <StatusInfo.icon className="w-4 h-4" />
                {StatusInfo.label}
              </Badge>
            </div>
            {last_scan_date && (
              <span className="text-xs text-muted-foreground font-mono">Last Scanned: {new Date(last_scan_date).toLocaleString()}</span>
            )}
          </div>
        </div>

        {/* اطلاعات کلی (Grid) */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <Card className="bg-black/20 border-white/5">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2 text-muted-foreground"><Server className="w-4 h-4"/> Tech Stack</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {tech?.length ? tech.map((t: string) => (
                  <Badge key={t} variant="secondary" className="bg-purple-500/10 text-purple-400 border-purple-500/20">{t}</Badge>
                )) : <span className="text-sm text-muted-foreground">-</span>}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-white/5">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2 text-muted-foreground"><Globe className="w-4 h-4"/> IP Addresses</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {ips?.length ? ips.map((ip: string) => (
                  <Badge key={ip} variant="outline" className="font-mono text-xs">{ip}</Badge>
                )) : <span className="text-sm text-muted-foreground">-</span>}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-black/20 border-white/5 md:col-span-2 xl:col-span-2">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2 text-muted-foreground"><FileCode className="w-4 h-4"/> Notable Headers</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm font-mono">
                {headers?.['server'] && <div><span className="text-muted-foreground">Server:</span> <span className="text-sky-400">{headers['server']}</span></div>}
                {headers?.['x-powered-by'] && <div><span className="text-muted-foreground">X-Powered-By:</span> <span className="text-sky-400">{headers['x-powered-by']}</span></div>}
                {!headers?.['server'] && !headers?.['x-powered-by'] && <span className="text-muted-foreground">-</span>}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Empty State */}
        {isCompletelyEmpty ? (
          <div className="flex flex-col items-center justify-center py-20 border border-dashed border-white/10 rounded-xl bg-black/10">
            <Terminal className="w-16 h-16 text-muted-foreground/30 mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">Target Not Scanned</h3>
            <p className="text-muted-foreground text-center max-w-md">
              این هدف هنوز توسط موتورهای شناسایی و اسکنر آسیب‌پذیری بررسی نشده است. برای مشاهده جزئیات بیشتر، اسکن را اجرا کنید.
            </p>
          </div>
        ) : (
          /* Tabs */
          <Tabs defaultValue="findings" className="w-full">
            <TabsList className="bg-black/40 border border-white/5 p-1 mb-6">
              <TabsTrigger value="findings" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-2">
                <ShieldAlert className="w-4 h-4" />
                Findings ({findings?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="passive" className="gap-2">
                <Activity className="w-4 h-4" />
                Passive URLs ({passive_urls?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="crawled" className="gap-2">
                <Globe className="w-4 h-4" />
                Crawled URLs ({crawled_urls?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="params" className="gap-2">
                <KeyRound className="w-4 h-4" />
                Parameters ({discovered_params?.length || 0})
              </TabsTrigger>
            </TabsList>

            {/* بخش Findings */}
            <TabsContent value="findings" className="space-y-4">
              <div className="flex justify-end mb-4">
                <select 
                  className="bg-black/50 border border-white/10 text-sm rounded-md px-3 py-1.5 outline-none focus:ring-1 focus:ring-primary text-white"
                  value={filterConfidence}
                  onChange={(e) => setFilterConfidence(e.target.value)}
                >
                  <option value="ALL">All Confidences</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              {filteredFindings.length === 0 ? (
                <div className="text-center py-10 bg-black/20 rounded-xl border border-white/5">
                  <ShieldCheck className="w-12 h-12 text-green-500/50 mx-auto mb-3" />
                  <p className="text-muted-foreground">هیچ موردی با این فیلتر یافت نشد یا هدف امن است.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {filteredFindings.map((finding: any, idx: number) => (
                    <div key={idx} className={`p-5 rounded-xl border flex flex-col md:flex-row gap-4 justify-between items-start ${getConfidenceStyles(finding.confidence)}`}>
                      <div className="space-y-2 w-full">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className="font-bold border-current bg-transparent">
                            {finding.confidence}
                          </Badge>
                          <span className="font-mono text-sm break-all">{finding.url}</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mt-3 text-sm">
                          <div>
                            <span className="text-muted-foreground text-xs uppercase block">Parameter</span>
                            <span className="font-mono font-bold text-white">{finding.vulnerable_parameter || 'N/A'}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground text-xs uppercase block">Reflection Type</span>
                            <span className="text-white">{TRANSLATE_REFLECTION[finding.reflection_type] || finding.reflection_type}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground text-xs uppercase block">Source</span>
                            <span className="text-white font-mono">{finding.discovery_source}</span>
                          </div>
                        </div>
                        
                        {finding.context?.allowed_chars && finding.context.allowed_chars.length > 0 && (
                          <div className="mt-3 bg-black/40 p-3 rounded-lg border border-white/5">
                            <span className="text-xs text-muted-foreground block mb-1">Allowed Characters Check:</span>
                            <div className="font-mono text-xs text-green-400 break-words">
                              {finding.context.allowed_chars.join(', ')}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </TabsContent>

            {/* بخش Passive URLs */}
            <TabsContent value="passive">
              <Card className="bg-black/20 border-white/5">
                <CardHeader className="flex flex-row items-center justify-between pb-4">
                  <CardTitle className="text-lg">Passive Recon URLs (Wayback/GAU)</CardTitle>
                  <Button variant="outline" size="sm" onClick={() => handleCopy(passive_urls.join('\n'), true)} disabled={!passive_urls?.length}>
                    <Copy className="w-4 h-4 mr-2" /> Copy All
                  </Button>
                </CardHeader>
                <CardContent>
                  {passive_urls?.length ? (
                    <div className="max-h-[500px] overflow-y-auto bg-black/40 rounded-lg p-4 font-mono text-xs border border-white/5 space-y-1">
                      {passive_urls.map((u: string, idx: number) => (
                        <a key={idx} href={u} target="_blank" rel="noreferrer" className="block text-purple-400 hover:text-purple-300 truncate hover:underline">
                          {u}
                        </a>
                      ))}
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-sm text-center py-6">هیچ آدرس پسیوی یافت نشد.</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* بخش Crawled URLs */}
            <TabsContent value="crawled">
              <Card className="bg-black/20 border-white/5">
                <CardHeader className="flex flex-row items-center justify-between pb-4">
                  <CardTitle className="text-lg">Crawled URLs (Katana)</CardTitle>
                  <Button variant="outline" size="sm" onClick={() => handleCopy(crawled_urls.join('\n'), true)} disabled={!crawled_urls?.length}>
                    <Copy className="w-4 h-4 mr-2" /> Copy All
                  </Button>
                </CardHeader>
                <CardContent>
                  {crawled_urls?.length ? (
                    <div className="max-h-[500px] overflow-y-auto bg-black/40 rounded-lg p-4 font-mono text-xs border border-white/5 space-y-1">
                      {crawled_urls.map((u: string, idx: number) => (
                        <a key={idx} href={u} target="_blank" rel="noreferrer" className="block text-blue-400 hover:text-blue-300 truncate hover:underline">
                          {u}
                        </a>
                      ))}
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-sm text-center py-6">هیچ آدرسی کرال نشده است.</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* بخش Parameters */}
            <TabsContent value="params">
              <Card className="bg-black/20 border-white/5">
                <CardHeader>
                  <CardTitle className="text-lg">Discovered Parameters</CardTitle>
                  <CardDescription>پارامترهای کشف شده توسط ابزارهایی نظیر x8 و فازینگ.</CardDescription>
                </CardHeader>
                <CardContent>
                  {discovered_params?.length ? (
                    <div className="flex flex-wrap gap-2">
                      <TooltipProvider>
                        {discovered_params.map((param: string, idx: number) => (
                          <Tooltip key={idx}>
                            <TooltipTrigger asChild>
                              <Badge variant="outline" className="px-3 py-1.5 font-mono bg-sky-500/10 text-sky-400 border-sky-500/20 cursor-default hover:bg-sky-500/20 transition-colors">
                                {param}
                              </Badge>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Discovered Parameter: {param}</p>
                            </TooltipContent>
                          </Tooltip>
                        ))}
                      </TooltipProvider>
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-sm text-center py-6">پارامتری یافت نشد.</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

          </Tabs>
        )}
      </div>
    </Layout>
  );
}