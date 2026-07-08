import { useState, useEffect } from 'react';
import { BarChart3, Globe, Radio, Server, Box, FolderGit2, Loader2, TrendingUp } from 'lucide-react';
import { Layout } from '@/components/Layout';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge'; // برای نمایش زیبای ترندها
import { getGlobalStats } from '@/api/stats'; // استفاده از فانکشن جدید

interface StatCard {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  trend?: number; // آمار ۲۴ ساعت اخیر
  color: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        setIsLoading(true);
        const data = await getGlobalStats(); // دریافت دیتا از /api/stats
        setStats(data);
      } catch (err) {
        console.error('Failed to fetch stats:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchStats();
  }, []);

  // کلیدها دقیقاً منطبق با خروجی app.py هستن
  const statCards: StatCard[] = [
    {
      icon: <FolderGit2 className="w-6 h-6" />,
      label: 'Programs',
      value: stats?.programs || 0,
      color: 'from-blue-500 to-blue-600',
    },
    {
      icon: <Globe className="w-6 h-6" />,
      label: 'Subdomains',
      value: stats?.subdomains || 0,
      trend: stats?.new_subdomains_24h, // آمار جدید ۲۴ ساعته
      color: 'from-purple-500 to-purple-600',
    },
    {
      icon: <Radio className="w-6 h-6" />,
      label: 'Live Subdomains',
      value: stats?.live || 0,
      trend: stats?.new_live_24h,
      color: 'from-green-500 to-green-600',
    },
    {
      icon: <Server className="w-6 h-6" />,
      label: 'HTTP Services',
      value: stats?.http || 0,
      trend: stats?.new_http_24h,
      color: 'from-orange-500 to-orange-600',
    },
    {
      icon: <Box className="w-6 h-6" />,
      label: 'Total Assets',
      // جمع کل دارایی‌ها
      value: (stats?.subdomains || 0) + (stats?.live || 0) + (stats?.http || 0),
      color: 'from-pink-500 to-pink-600',
    },
  ];

  return (
    <Layout>
      <div className="space-y-8">
        {/* Header */}
        <div className="animate-fade-in">
          <h1 className="text-4xl font-bold text-foreground">Dashboard</h1>
          <p className="text-muted-foreground mt-2">Welcome to Watchtower - Your security monitoring hub</p>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="flex items-center justify-center h-64">
            <div className="flex flex-col items-center gap-2">
              <Loader2 className="w-8 h-8 animate-spin text-accent" />
              <p className="text-sm text-muted-foreground">Loading statistics...</p>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        {!isLoading && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 animate-slide-in-right">
            {statCards.map((stat, idx) => (
              <Card
                key={idx}
                className="p-6 hover:shadow-lg transition-all duration-300 hover:-translate-y-1 cursor-pointer group card-hover"
                style={{ animationDelay: `${idx * 50}ms` }}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">{stat.label}</p>
                    <p className="text-3xl font-bold text-foreground">{stat.value}</p>
                    {/* نمایش ترند ۲۴ ساعته اگه وجود داشت */}
                    {stat.trend !== undefined && stat.trend > 0 && (
                      <div className="flex items-center gap-1 mt-2">
                        <Badge variant="secondary" className="bg-green-500/20 text-green-400 border-green-500/30 gap-1 text-[10px] px-1.5 py-0.5">
                          <TrendingUp className="w-3 h-3" />
                          +{stat.trend} (24h)
                        </Badge>
                      </div>
                    )}
                  </div>

                  <div
                    className={`w-12 h-12 rounded-lg bg-gradient-to-br ${stat.color} flex items-center justify-center text-white shadow-lg group-hover:shadow-xl transition-shadow`}
                  >
                    {stat.icon}
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}

        {/* Recent Activity Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* 24h Summary */}
          <Card className="p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Last 24 Hours Summary</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <span className="text-sm text-muted-foreground">New Subdomains</span>
                <span className="text-sm font-bold text-purple-500">{stats?.new_subdomains_24h || 0}</span>
              </div>
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <span className="text-sm text-muted-foreground">New Live Subdomains</span>
                <span className="text-sm font-bold text-green-500">{stats?.new_live_24h || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">New HTTP Services</span>
                <span className="text-sm font-bold text-orange-500">{stats?.new_http_24h || 0}</span>
              </div>
            </div>
          </Card>

          {/* System Status */}
          <Card className="p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">System Status</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">API Status</span>
                <span className="inline-flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  <span className="text-sm font-medium text-green-600">Connected</span>
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Database</span>
                <span className="inline-flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  <span className="text-sm font-medium text-green-600">Healthy</span>
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Last Sync</span>
                <span className="text-sm font-medium text-foreground">{stats?.timestamp || 'Just now'}</span>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </Layout>
  );
}