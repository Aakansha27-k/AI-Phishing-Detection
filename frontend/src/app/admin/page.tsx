"use client";

import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, ShieldX, Activity, BarChart3, Users } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";

type AnalyticsData = {
  total_scans: number;
  phishing_count: number;
  suspicious_count: number;
  safe_count: number;
  recent_scans: any[];
};

const COLORS = ["#10b981", "#f59e0b", "#ef4444"];

export default function AdminDashboard() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        const res = await fetch("http://localhost:8000/api/admin/analytics");
        if (res.ok) {
          const result = await res.json();
          setData(result);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchAnalytics();
  }, []);

  if (loading || !data) {
    return <div className="py-20 text-center text-gray-400">Loading Analytics...</div>;
  }

  const pieData = [
    { name: "Safe", value: data.safe_count },
    { name: "Suspicious", value: data.suspicious_count },
    { name: "Phishing", value: data.phishing_count },
  ];

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Activity className="w-8 h-8 text-primary" /> Admin Analytics
        </h1>
        <div className="text-sm text-gray-400">System Health: <span className="text-safe">Online</span></div>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-card border border-border p-6 rounded-xl shadow-sm">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-blue-500/10 text-blue-500 rounded-lg"><BarChart3 className="w-6 h-6" /></div>
            <div>
              <p className="text-sm text-gray-400 font-medium">Total Scans</p>
              <p className="text-3xl font-bold">{data.total_scans}</p>
            </div>
          </div>
        </div>
        <div className="bg-card border border-border p-6 rounded-xl shadow-sm">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-safe/10 text-safe rounded-lg"><ShieldCheck className="w-6 h-6" /></div>
            <div>
              <p className="text-sm text-gray-400 font-medium">Safe URLs</p>
              <p className="text-3xl font-bold">{data.safe_count}</p>
            </div>
          </div>
        </div>
        <div className="bg-card border border-border p-6 rounded-xl shadow-sm">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-suspicious/10 text-suspicious rounded-lg"><ShieldAlert className="w-6 h-6" /></div>
            <div>
              <p className="text-sm text-gray-400 font-medium">Suspicious</p>
              <p className="text-3xl font-bold">{data.suspicious_count}</p>
            </div>
          </div>
        </div>
        <div className="bg-card border border-border p-6 rounded-xl shadow-sm">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-phishing/10 text-phishing rounded-lg"><ShieldX className="w-6 h-6" /></div>
            <div>
              <p className="text-sm text-gray-400 font-medium">Phishing Blocked</p>
              <p className="text-3xl font-bold">{data.phishing_count}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Charts */}
        <div className="bg-card border border-border p-6 rounded-xl shadow-sm lg:col-span-1">
          <h2 className="text-xl font-bold mb-6">Threat Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#111116', borderColor: '#1f1f2e', color: '#fff' }} 
                  itemStyle={{ color: '#fff' }} 
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-card border border-border p-6 rounded-xl shadow-sm lg:col-span-2">
          <h2 className="text-xl font-bold mb-6 flex items-center justify-between">
            Recent Activity Feed
            <span className="text-sm font-normal text-gray-400">Showing last 10 scans</span>
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-[#111116] border-b border-border text-gray-400">
                <tr>
                  <th className="px-4 py-3 font-semibold">URL</th>
                  <th className="px-4 py-3 font-semibold">Risk Level</th>
                  <th className="px-4 py-3 font-semibold">Score</th>
                  <th className="px-4 py-3 font-semibold">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.recent_scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-white/5 transition-colors">
                    <td className="px-4 py-3 truncate max-w-[200px]" title={scan.url}>{scan.url}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex px-2 py-1 rounded text-xs font-medium border ${
                        scan.risk_level === "Safe" ? "bg-safe/10 text-safe border-safe/20" :
                        scan.risk_level === "Suspicious" ? "bg-suspicious/10 text-suspicious border-suspicious/20" :
                        "bg-phishing/10 text-phishing border-phishing/20"
                      }`}>
                        {scan.risk_level || scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono">{scan.risk_score?.toFixed(1) || "-"}</td>
                    <td className="px-4 py-3 text-gray-400">{new Date(scan.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
