"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { Loader2, ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, ExternalLink, CheckCircle, Search } from "lucide-react";

type ScanResult = {
  id: string;
  url: string;
  status: string;
  risk_score: number | null;
  risk_level: string | null;
  ml_probability: number | null;
  heuristic_score: number | null;
  domain_reputation_score: number | null;
  features: any | null;
  error_message: string | null;
};

export default function ScanResultPage() {
  const params = useParams();
  const id = params.id as string;
  
  const [data, setData] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [showScreenshotModal, setShowScreenshotModal] = useState(false);

  useEffect(() => {
    let intervalId: NodeJS.Timeout;

    const fetchResult = async () => {
      try {
        const res = await fetch(`http://localhost:8000/api/result/${id}`);
        if (!res.ok) throw new Error("Failed to fetch scan results");
        
        const result: ScanResult = await res.json();
        setData(result);

        if (result.status === "completed" || result.status === "failed") {
          clearInterval(intervalId);
        }
      } catch (err: any) {
        setError(err.message);
        clearInterval(intervalId);
      }
    };

    fetchResult();
    intervalId = setInterval(fetchResult, 2000);

    return () => clearInterval(intervalId);
  }, [id]);

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-red-500">
        <AlertTriangle className="w-16 h-16 mb-4" />
        <h2 className="text-2xl font-bold">Error</h2>
        <p>{error}</p>
      </div>
    );
  }

  if (!data || data.status === "pending" || data.status === "scanning") {
    return (
      <div className="max-w-2xl mx-auto py-20 space-y-8">
        <div className="text-center space-y-4 mb-12">
          <div className="relative mx-auto w-24 h-24 mb-6">
            <div className="absolute inset-0 border-4 border-primary/30 border-t-primary rounded-full animate-spin"></div>
            <ShieldAlert className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 text-primary w-8 h-8" />
          </div>
          <h2 className="text-3xl font-bold">Analyzing URL...</h2>
          <p className="text-gray-400">Please wait while PhishGuard AI evaluates the threat level.</p>
        </div>

        {/* Scan Timeline */}
        <div className="bg-card border border-border p-8 rounded-xl space-y-6 relative overflow-hidden">
          <div className="absolute top-0 left-0 w-1 h-full bg-border ml-10"></div>
          
          <div className="relative flex items-center gap-6">
            <div className={`w-6 h-6 rounded-full border-4 z-10 ${data?.status ? 'bg-primary border-primary' : 'bg-[#111116] border-border'}`}></div>
            <div className={`text-lg ${data?.status ? 'text-white' : 'text-gray-500'}`}>Initiating Scan Queue</div>
          </div>
          <div className="relative flex items-center gap-6">
            <div className={`w-6 h-6 rounded-full border-4 z-10 ${data?.status === 'scanning' || data?.status === 'completed' ? 'bg-primary border-primary animate-pulse' : 'bg-[#111116] border-border'}`}></div>
            <div className={`text-lg ${data?.status === 'scanning' || data?.status === 'completed' ? 'text-white' : 'text-gray-500'}`}>URL & Domain Reputation Check</div>
          </div>
          <div className="relative flex items-center gap-6">
            <div className={`w-6 h-6 rounded-full border-4 z-10 ${data?.status === 'scanning' || data?.status === 'completed' ? 'bg-primary border-primary animate-pulse' : 'bg-[#111116] border-border'}`}></div>
            <div className={`text-lg ${data?.status === 'scanning' || data?.status === 'completed' ? 'text-white' : 'text-gray-500'}`}>HTML Inspection & Screenshot</div>
          </div>
          <div className="relative flex items-center gap-6">
            <div className={`w-6 h-6 rounded-full border-4 z-10 ${data?.status === 'scanning' || data?.status === 'completed' ? 'bg-primary border-primary animate-pulse' : 'bg-[#111116] border-border'}`}></div>
            <div className={`text-lg ${data?.status === 'scanning' || data?.status === 'completed' ? 'text-white' : 'text-gray-500'}`}>Machine Learning Classification</div>
          </div>
        </div>
      </div>
    );
  }

  if (data.status === "failed") {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-red-500 space-y-4">
        <ShieldX className="w-20 h-20" />
        <h2 className="text-3xl font-bold">Scan Failed</h2>
        <div className="bg-red-500/10 border border-red-500/20 p-6 rounded-xl max-w-lg text-center">
          <p>{data.error_message}</p>
        </div>
      </div>
    );
  }

  const isSafe = data.risk_level === "Safe";
  const isSuspicious = data.risk_level === "Suspicious";
  const isPhishing = data.risk_level === "Phishing";

  const levelColor = isSafe ? "text-safe" : isSuspicious ? "text-suspicious" : "text-phishing";
  const bgLevelColor = isSafe ? "bg-safe/10 border-safe/20" : isSuspicious ? "bg-suspicious/10 border-suspicious/20" : "bg-phishing/10 border-phishing/20";
  const Icon = isSafe ? ShieldCheck : isSuspicious ? AlertTriangle : ShieldX;

  // Build Explanations List based on features
  const explanations = [];
  if (data.features) {
    if (data.features.has_brand_impersonation) explanations.push("Detected brand impersonation in URL/Domain.");
    if (data.features.has_suspicious_title) explanations.push("Suspicious keywords found in page title (e.g. 'login', 'verify').");
    if (data.features.has_password_input) explanations.push("Login/Password form detected on page.");
    if (data.features.form_action_mismatch) explanations.push("Form submits data to a different external domain.");
    if (data.features.has_ip_in_domain) explanations.push("URL uses an IP address instead of a domain name.");
    if (data.features.is_shortener) explanations.push("URL shortener service detected (often used to hide destinations).");
    if (data.features.has_suspicious_tld) explanations.push("Uses a top-level domain frequently associated with spam/phishing.");
    if (data.features.domain_age_days > -1 && data.features.domain_age_days < 30) explanations.push(`Newly registered domain (only ${data.features.domain_age_days} days old).`);
    if (data.features.has_iframe && data.features.has_iframe > 2) explanations.push("Excessive use of iframes detected.");
    if (data.features.is_https === 0) explanations.push("Connection is NOT secure (No HTTPS).");
  }

  const confidenceText = isSafe ? "High confidence that this site is safe." : "High confidence of a potential threat because:";

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-20">
      
      {/* Header Section */}
      <div className={`p-8 rounded-2xl border ${bgLevelColor} flex flex-col md:flex-row items-center justify-between gap-6 shadow-lg`}>
        <div className="flex items-center gap-6">
          <div className={`p-5 rounded-full bg-black/30 ${levelColor}`}>
            <Icon className="w-14 h-14" />
          </div>
          <div>
            <h1 className="text-4xl font-black flex items-center gap-3">
              {data.risk_level} Website
            </h1>
            <a href={data.url} target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white flex items-center gap-2 mt-2 break-all text-lg font-mono">
              {data.url} <ExternalLink className="w-5 h-5" />
            </a>
          </div>
        </div>
        <div className="text-center bg-black/40 px-10 py-5 rounded-xl border border-white/10">
          <p className="text-sm text-gray-400 uppercase tracking-widest mb-1 font-bold">Threat Score</p>
          <div className={`text-6xl font-black ${levelColor}`}>
            {data.risk_score?.toFixed(1)}<span className="text-3xl text-gray-500">/100</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Scores & Explanations */}
        <div className="lg:col-span-2 space-y-8">
          
          {/* Confidence Explanation */}
          <div className="bg-card border border-border rounded-xl p-8 shadow-sm">
            <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
              <ShieldAlert className="w-6 h-6 text-primary" /> AI Confidence Explanation
            </h2>
            <div className="bg-[#111116] p-6 rounded-xl border border-[#1f1f2e]">
              <p className="text-lg font-medium mb-4">{confidenceText}</p>
              {explanations.length > 0 ? (
                <ul className="space-y-3">
                  {explanations.map((exp, idx) => (
                    <li key={idx} className="flex items-start gap-3">
                      <AlertTriangle className={`w-5 h-5 mt-0.5 shrink-0 ${isSafe ? 'text-safe' : 'text-phishing'}`} />
                      <span className="text-gray-300">{exp}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-gray-500">No specific threat indicators found in heuristics.</p>
              )}
            </div>
          </div>

          {/* Detailed Scores */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-card border border-border p-6 rounded-xl">
              <h3 className="text-gray-400 mb-2 font-medium">ML Probability</h3>
              <div className="text-4xl font-bold">{data.ml_probability?.toFixed(1)}%</div>
              <div className="w-full bg-gray-800 h-2 mt-4 rounded-full overflow-hidden">
                <div className="bg-primary h-full" style={{ width: `${data.ml_probability}%` }}></div>
              </div>
            </div>
            <div className="bg-card border border-border p-6 rounded-xl">
              <h3 className="text-gray-400 mb-2 font-medium">Heuristic Score</h3>
              <div className="text-4xl font-bold">{data.heuristic_score?.toFixed(1)} <span className="text-xl text-gray-500">/100</span></div>
              <div className="w-full bg-gray-800 h-2 mt-4 rounded-full overflow-hidden">
                <div className="bg-purple-500 h-full" style={{ width: `${data.heuristic_score}%` }}></div>
              </div>
            </div>
            <div className="bg-card border border-border p-6 rounded-xl">
              <h3 className="text-gray-400 mb-2 font-medium">Domain Reputation</h3>
              <div className="text-4xl font-bold">{data.domain_reputation_score?.toFixed(1)} <span className="text-xl text-gray-500">/100</span></div>
              <div className="w-full bg-gray-800 h-2 mt-4 rounded-full overflow-hidden">
                <div className="bg-pink-500 h-full" style={{ width: `${data.domain_reputation_score}%` }}></div>
              </div>
            </div>
          </div>

        </div>

        {/* Right Column: Screenshot & Tech details */}
        <div className="space-y-8">
          
          {/* Screenshot */}
          <div className="bg-card border border-border rounded-xl p-6 shadow-sm">
            <h3 className="text-xl font-bold mb-4 flex items-center justify-between">
              Live Screenshot
              {data.features?.has_screenshot && (
                <button onClick={() => setShowScreenshotModal(true)} className="text-primary hover:text-white transition-colors">
                  <Search className="w-5 h-5" />
                </button>
              )}
            </h3>
            
            <div className="aspect-[4/3] bg-black rounded-lg border border-[#1f1f2e] overflow-hidden relative group cursor-pointer" onClick={() => data.features?.has_screenshot && setShowScreenshotModal(true)}>
              {data.features?.has_screenshot ? (
                <>
                  <img 
                    src={`http://localhost:8000/api/screenshot/${id}`} 
                    alt="Website Screenshot" 
                    className="w-full h-full object-cover object-top opacity-80 group-hover:opacity-100 transition-opacity"
                  />
                  <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                    <span className="bg-black/80 text-white px-4 py-2 rounded-full font-medium flex items-center gap-2">
                      <Search className="w-4 h-4" /> View Full Page
                    </span>
                  </div>
                </>
              ) : (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-500">
                  <ShieldX className="w-12 h-12 mb-2 opacity-50" />
                  <p>Screenshot Unavailable</p>
                </div>
              )}
            </div>
          </div>

          {/* Quick Technical Specs */}
          <div className="bg-card border border-border rounded-xl p-6">
            <h3 className="text-lg font-bold mb-4 border-b border-border pb-3">Technical Data</h3>
            <ul className="space-y-3 text-sm">
              <li className="flex justify-between">
                <span className="text-gray-400">Entropy</span>
                <span className="font-mono">{data.features?.entropy?.toFixed(2)}</span>
              </li>
              <li className="flex justify-between">
                <span className="text-gray-400">URL Length</span>
                <span className="font-mono">{data.features?.url_length} chars</span>
              </li>
              <li className="flex justify-between">
                <span className="text-gray-400">Domain Length</span>
                <span className="font-mono">{data.features?.domain_length} chars</span>
              </li>
              <li className="flex justify-between">
                <span className="text-gray-400">HTTPS Encryption</span>
                <span className="font-mono">{data.features?.is_https ? "Enabled" : "Missing"}</span>
              </li>
              <li className="flex justify-between">
                <span className="text-gray-400">External Scripts</span>
                <span className="font-mono">{data.features?.num_external_scripts}</span>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Fullscreen Screenshot Modal */}
      {showScreenshotModal && (
        <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-4" onClick={() => setShowScreenshotModal(false)}>
          <div className="relative max-w-5xl w-full max-h-[90vh] flex flex-col bg-[#111116] rounded-xl overflow-hidden border border-border shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <div className="p-4 border-b border-border flex justify-between items-center bg-black">
              <h3 className="font-bold text-lg">Full Page Screenshot</h3>
              <button onClick={() => setShowScreenshotModal(false)} className="text-gray-400 hover:text-white bg-white/5 p-2 rounded-lg">
                Close
              </button>
            </div>
            <div className="overflow-auto flex-grow p-4 bg-[#0a0a0f]">
              <img 
                src={`http://localhost:8000/api/screenshot/${id}`} 
                alt="Full Website Screenshot" 
                className="w-full rounded border border-border shadow-md"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
