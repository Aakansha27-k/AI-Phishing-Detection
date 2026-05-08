"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, ShieldAlert, ShieldCheck, Loader2 } from "lucide-react";

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    
    setLoading(true);
    setError("");

    try {
      // Allow relative path for API if using rewrite, but for MVP we use absolute URL pointing to backend
      const res = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      if (!res.ok) {
        throw new Error("Failed to start scan");
      }

      const data = await res.json();
      if (data.scan_id) {
        router.push(`/scan/${data.scan_id}`);
      } else {
        throw new Error("Invalid response from server");
      }
    } catch (err: any) {
      setError(err.message || "An error occurred");
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center py-20">
      <div className="max-w-3xl w-full text-center space-y-8">
        <div className="space-y-4">
          <h1 className="text-5xl font-extrabold tracking-tight">
            Advanced <span className="text-primary">Phishing</span> Detection
          </h1>
          <p className="text-xl text-gray-400">
            Real-time AI analysis of URLs, domains, and website content to protect you from malicious threats.
          </p>
        </div>

        <div className="bg-card p-8 rounded-2xl border border-border shadow-2xl">
          <form onSubmit={handleScan} className="flex flex-col gap-4">
            <div className="relative">
              <input
                type="url"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full bg-[#1a1a24] border border-[#2d2d3f] rounded-xl px-6 py-4 text-lg outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
              />
            </div>
            {error && <p className="text-red-500 text-sm text-left">{error}</p>}
            <button
              type="submit"
              disabled={loading}
              className="bg-primary hover:bg-blue-600 text-white font-semibold rounded-xl px-6 py-4 transition-all flex items-center justify-center gap-2 disabled:opacity-70"
            >
              {loading ? (
                <>
                  <Loader2 className="w-6 h-6 animate-spin" />
                  Initiating Scan...
                </>
              ) : (
                <>
                  <Shield className="w-6 h-6" />
                  Analyze Website
                </>
              )}
            </button>
          </form>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-12 text-left">
          <div className="bg-card p-6 rounded-xl border border-border">
            <ShieldCheck className="w-10 h-10 text-safe mb-4" />
            <h3 className="font-semibold text-lg mb-2">ML Classification</h3>
            <p className="text-gray-400 text-sm">Uses Random Forest models trained on known phishing datasets.</p>
          </div>
          <div className="bg-card p-6 rounded-xl border border-border">
            <ShieldAlert className="w-10 h-10 text-suspicious mb-4" />
            <h3 className="font-semibold text-lg mb-2">Heuristic Analysis</h3>
            <p className="text-gray-400 text-sm">Extracts URL entropy, hidden iframes, and fake login patterns.</p>
          </div>
          <div className="bg-card p-6 rounded-xl border border-border">
            <Shield className="w-10 h-10 text-primary mb-4" />
            <h3 className="font-semibold text-lg mb-2">Domain Reputation</h3>
            <p className="text-gray-400 text-sm">Checks WHOIS records, registration age, and suspicious TLDs.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
