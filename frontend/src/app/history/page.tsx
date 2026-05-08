"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns"; // Note: might need date-fns, or just use basic js
import { ShieldCheck, AlertTriangle, ShieldX, Clock } from "lucide-react";

type ScanResult = {
  id: string;
  url: string;
  status: string;
  risk_score: number | null;
  risk_level: string | null;
  created_at: string;
};

export default function HistoryPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await fetch("http://localhost:8000/api/history");
        if (res.ok) {
          const data = await res.json();
          setHistory(data);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  if (loading) {
    return <div className="py-20 text-center text-gray-400">Loading scan history...</div>;
  }

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Threat History</h1>
        <div className="text-sm text-gray-400 bg-card px-4 py-2 rounded-full border border-border">
          {history.length} URLs Scanned
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-[#111116] border-b border-border text-gray-400 text-sm">
            <tr>
              <th className="px-6 py-4 font-semibold">URL</th>
              <th className="px-6 py-4 font-semibold">Status</th>
              <th className="px-6 py-4 font-semibold">Risk Level</th>
              <th className="px-6 py-4 font-semibold">Score</th>
              <th className="px-6 py-4 font-semibold">Time</th>
              <th className="px-6 py-4 font-semibold">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {history.map((scan) => (
              <tr key={scan.id} className="hover:bg-white/5 transition-colors">
                <td className="px-6 py-4 truncate max-w-[300px]" title={scan.url}>
                  {scan.url}
                </td>
                <td className="px-6 py-4 uppercase text-xs tracking-wider">
                  {scan.status}
                </td>
                <td className="px-6 py-4">
                  {scan.status === "completed" && scan.risk_level && (
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                      scan.risk_level === "Safe" ? "bg-safe/10 text-safe border-safe/20" :
                      scan.risk_level === "Suspicious" ? "bg-suspicious/10 text-suspicious border-suspicious/20" :
                      "bg-phishing/10 text-phishing border-phishing/20"
                    }`}>
                      {scan.risk_level === "Safe" && <ShieldCheck className="w-3.5 h-3.5" />}
                      {scan.risk_level === "Suspicious" && <AlertTriangle className="w-3.5 h-3.5" />}
                      {scan.risk_level === "Phishing" && <ShieldX className="w-3.5 h-3.5" />}
                      {scan.risk_level}
                    </span>
                  )}
                  {scan.status !== "completed" && <span className="text-gray-500">-</span>}
                </td>
                <td className="px-6 py-4 font-mono">
                  {scan.status === "completed" ? scan.risk_score?.toFixed(1) : "-"}
                </td>
                <td className="px-6 py-4 text-sm text-gray-400 flex items-center gap-2">
                  <Clock className="w-4 h-4" />
                  {new Date(scan.created_at).toLocaleString()}
                </td>
                <td className="px-6 py-4">
                  <Link href={`/scan/${scan.id}`} className="text-primary hover:underline text-sm font-medium">
                    View Report
                  </Link>
                </td>
              </tr>
            ))}
            {history.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  No scan history found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
