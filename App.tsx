import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, Search, 
  Terminal, Server, Globe, AlertOctagon, Loader2, Star,
  Lock, CreditCard, FileJson, Layout, Upload, XCircle,
  WifiOff
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid } from 'recharts';

import Sidebar from './components/Sidebar';
import { analyzeVulnerabilities, detectPhishing } from './services/geminiService';
import { User, ScanResult, SecurityRisk } from './types';

declare global {
  interface Window {
    FlutterwaveCheckout: any;
  }
}

// --- MOCK DATA CONSTANTS ---

const MOCK_CHART_DATA = [
  { name: 'Mon', threats: 4, secure: 24 },
  { name: 'Tue', threats: 7, secure: 18 },
  { name: 'Wed', threats: 2, secure: 35 },
  { name: 'Thu', threats: 12, secure: 20 },
  { name: 'Fri', threats: 5, secure: 28 },
  { name: 'Sat', threats: 1, secure: 15 },
  { name: 'Sun', threats: 3, secure: 12 },
];

// --- COMPONENTS ---

const RiskBadge: React.FC<{ risk: string }> = ({ risk }) => {
  const colors = {
    [SecurityRisk.LOW]: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
    [SecurityRisk.MEDIUM]: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    [SecurityRisk.HIGH]: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    [SecurityRisk.CRITICAL]: 'bg-red-500/20 text-red-500 border-red-500/50',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-bold border ${colors[risk as SecurityRisk] || colors.LOW}`}>
      {risk}
    </span>
  );
};

const AuthPage: React.FC<{ onLogin: () => void }> = ({ onLogin }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [isLoading, setIsLoading] = useState(false);

  const handleAuth = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    // Simulate API call
    setTimeout(() => {
      setIsLoading(false);
      onLogin();
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-cyber-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-cyber-800 border border-cyber-700 rounded-2xl p-8 shadow-2xl">
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 bg-cyber-700 rounded-full flex items-center justify-center">
              <Shield className="w-8 h-8 text-cyber-500" />
            </div>
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">SecurBot AI</h1>
          <p className="text-cyber-400">Enterprise Grade Cyber Defense</p>
        </div>

        <form onSubmit={handleAuth} className="space-y-4">
          {!isLogin && (
            <div>
              <label className="block text-sm font-medium text-cyber-300 mb-1">Full Name</label>
              <input type="text" className="w-full bg-cyber-900 border border-cyber-600 rounded-lg p-3 text-white focus:border-cyber-500 outline-none" placeholder="John Doe" />
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-cyber-300 mb-1">Email Address</label>
            <input type="email" className="w-full bg-cyber-900 border border-cyber-600 rounded-lg p-3 text-white focus:border-cyber-500 outline-none" placeholder="security@company.com" />
          </div>
          <div>
            <label className="block text-sm font-medium text-cyber-300 mb-1">Password</label>
            <input type="password" className="w-full bg-cyber-900 border border-cyber-600 rounded-lg p-3 text-white focus:border-cyber-500 outline-none" placeholder="••••••••" />
          </div>
          
          <button 
            type="submit" 
            disabled={isLoading}
            className="w-full bg-cyber-500 hover:bg-cyber-400 text-cyber-900 font-bold py-3 rounded-lg transition-all flex items-center justify-center gap-2"
          >
            {isLoading ? <Loader2 className="animate-spin" /> : (isLogin ? 'Sign In' : 'Create Account')}
          </button>
        </form>

        <div className="mt-6 text-center">
          <button 
            onClick={() => setIsLogin(!isLogin)}
            className="text-cyber-400 hover:text-cyber-500 text-sm"
          >
            {isLogin ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
          </button>
        </div>
      </div>
    </div>
  );
};

const PaymentLock: React.FC<{ onSuccess: () => void, userEmail: string }> = ({ onSuccess, userEmail }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isConfigValid, setIsConfigValid] = useState(false);
  const [envMode, setEnvMode] = useState<'TEST' | 'LIVE' | null>(null);

  // In a real environment, this key is injected by the CI/CD pipeline or backend server.
  // We use the provided key as a fallback for this demo environment to ensure functionality.
  const RUNTIME_PUBLIC_KEY = process.env.FLUTTERWAVE_PUBLIC_KEY || 'FLWPUBK-2283d9d85c854253a59b635a730a2c8d-X';

  // Validate configuration on mount (simulating runtime check)
  useEffect(() => {
    const validateEnvironment = () => {
      // 1. Check for Script Availability
      if (typeof window.FlutterwaveCheckout === 'undefined') {
        setError("Payment Gateway Error: SDK not loaded. Check internet connection.");
        return;
      }

      // 2. Validate Public Key presence and format
      // Note: Flutterwave keys can start with FLWPUBK_ (v3 standard) or FLWPUBK- (legacy/other regions)
      if (!RUNTIME_PUBLIC_KEY) {
        setError("Configuration Error: Missing 'FLUTTERWAVE_PUBLIC_KEY' in environment variables.");
        return;
      }

      if (!RUNTIME_PUBLIC_KEY.startsWith("FLWPUBK_") && !RUNTIME_PUBLIC_KEY.startsWith("FLWPUBK-")) {
        setError("Configuration Error: Invalid 'FLUTTERWAVE_PUBLIC_KEY'. Key must start with 'FLWPUBK_' or 'FLWPUBK-'.");
        return;
      }

      // 3. Determine Environment Mode based on key content
      if (RUNTIME_PUBLIC_KEY.includes("_TEST") || RUNTIME_PUBLIC_KEY.includes("-TEST")) {
        setEnvMode('TEST');
      } else {
        setEnvMode('LIVE');
      }

      setIsConfigValid(true);
      setError(null);
    };

    validateEnvironment();
  }, [RUNTIME_PUBLIC_KEY]);

  const makePayment = () => {
    if (!isConfigValid) return;

    setLoading(true);
    setError(null);

    try {
      const config = {
        public_key: RUNTIME_PUBLIC_KEY,
        tx_ref: "tx-" + Date.now(),
        amount: 10,
        currency: "USD",
        payment_options: "card,mobilemoney,ussd",
        customer: {
          email: userEmail,
          name: "Security User",
        },
        customizations: {
          title: "SecurBot AI Access",
          description: "One-time Lifetime Access",
          logo: "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        },
        callback: (data: any) => {
          if (data.status === "successful") {
            onSuccess();
          } else {
             setError("Transaction failed. Please try again.");
          }
        },
        onclose: () => {
          setLoading(false);
        },
      };

      window.FlutterwaveCheckout(config);
    } catch (err) {
      console.error("Payment initialization failed", err);
      setError("Failed to initialize payment gateway.");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-900 flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-cyber-800 border border-cyber-700 rounded-2xl p-8 shadow-[0_0_50px_rgba(100,255,218,0.1)] text-center relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-2 bg-cyber-500"></div>
        
        <div className="w-20 h-20 bg-cyber-900 rounded-full flex items-center justify-center mx-auto mb-6 border-2 border-cyber-500 relative">
          <Lock className="w-10 h-10 text-cyber-500" />
          {envMode && (
            <div className={`absolute -bottom-2 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
              envMode === 'TEST' 
                ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50' 
                : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50'
            }`}>
              {envMode} MODE
            </div>
          )}
        </div>

        <h2 className="text-3xl font-bold text-white mb-2">Access Restricted</h2>
        <p className="text-cyber-400 mb-8">
          To access the full suite of Cyber Defense tools, a one-time activation payment is required.
        </p>

        <div className="bg-cyber-900/50 p-6 rounded-xl border border-cyber-700 mb-8 text-left">
          <div className="flex justify-between items-center mb-4 border-b border-cyber-700 pb-2">
            <span className="text-white font-medium">Lifetime Access</span>
            <span className="text-2xl font-bold text-white">$10.00</span>
          </div>
          <ul className="space-y-3">
            <li className="flex items-center gap-3 text-sm text-cyber-300">
              <CheckCircle size={16} className="text-cyber-500" /> Unlimited Vulnerability Scans
            </li>
            <li className="flex items-center gap-3 text-sm text-cyber-300">
               <CheckCircle size={16} className="text-cyber-500" /> Advanced Phishing Detection
            </li>
             <li className="flex items-center gap-3 text-sm text-cyber-300">
               <CheckCircle size={16} className="text-cyber-500" /> API Security Monitoring
            </li>
          </ul>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-900/30 border border-red-500/50 rounded-lg text-red-200 text-sm flex items-start gap-2 text-left animate-pulse">
            <div className="mt-0.5 shrink-0">
               {error.includes("Internet") ? <WifiOff className="w-5 h-5" /> : <XCircle className="w-5 h-5" />}
            </div>
            <div>{error}</div>
          </div>
        )}

        <button 
          onClick={makePayment}
          disabled={loading || !isConfigValid}
          className={`w-full font-bold py-4 rounded-lg transition-all flex items-center justify-center gap-3 text-lg ${
            !isConfigValid 
              ? 'bg-cyber-700 text-cyber-500 cursor-not-allowed opacity-50'
              : 'bg-cyber-500 hover:bg-emerald-400 text-cyber-900'
          }`}
        >
          {loading ? <Loader2 className="animate-spin" /> : <CreditCard />}
          {loading ? 'Initializing Secure Gateway...' : 'Pay $10 to Unlock'}
        </button>
        
        <p className="mt-4 text-xs text-cyber-500/50">
          Secure payment via Flutterwave. No hidden subscriptions.
        </p>
      </div>
    </div>
  );
};

const VulnerabilityScanner: React.FC = () => {
  const [target, setTarget] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!target) return;
    setLoading(true);
    setResult(null);
    try {
      const data = await analyzeVulnerabilities(target, 'URL');
      setResult(data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <Globe className="text-cyber-500" /> Target Scanner
        </h2>
        <div className="flex gap-4">
          <input 
            type="text" 
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="flex-1 bg-cyber-900 border border-cyber-600 rounded-lg p-3 text-white focus:border-cyber-500 outline-none font-mono"
          />
          <button 
            onClick={handleScan}
            disabled={loading}
            className="bg-cyber-500 text-cyber-900 font-bold px-6 rounded-lg hover:bg-emerald-400 transition-colors flex items-center gap-2"
          >
            {loading ? <Loader2 className="animate-spin" /> : <Search size={20} />}
            Scan
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-cyber-800 p-8 rounded-xl border border-cyber-700 text-center animate-pulse">
          <Terminal className="w-12 h-12 text-cyber-500 mx-auto mb-4" />
          <p className="text-cyber-300 font-mono">Initializing Heuristic Analysis Engine...</p>
          <p className="text-cyber-400 text-sm mt-2">Checking OWASP Top 10 vulnerabilities</p>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-cyber-800 p-4 rounded-xl border border-cyber-700">
              <p className="text-cyber-400 text-sm">Security Score</p>
              <div className="text-4xl font-bold text-white mt-2 flex items-baseline gap-2">
                {result.score} <span className="text-sm text-cyber-500">/ 100</span>
              </div>
            </div>
            <div className="bg-cyber-800 p-4 rounded-xl border border-cyber-700">
              <p className="text-cyber-400 text-sm">Vulnerabilities Found</p>
              <div className="text-4xl font-bold text-red-400 mt-2">
                {result.vulnerabilities.length}
              </div>
            </div>
            <div className="bg-cyber-800 p-4 rounded-xl border border-cyber-700">
              <p className="text-cyber-400 text-sm">Scan Time</p>
              <div className="text-xl font-mono text-white mt-3">
                {new Date(result.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>

          <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
            <h3 className="text-lg font-bold text-white mb-4">Findings Log</h3>
            <div className="space-y-3">
              {result.vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="bg-cyber-900/50 p-4 rounded-lg border border-cyber-700 hover:border-cyber-600 transition-colors">
                  <div className="flex justify-between items-start mb-2">
                    <h4 className="text-white font-semibold">{vuln.title}</h4>
                    <RiskBadge risk={vuln.risk} />
                  </div>
                  <p className="text-cyber-400 text-sm mb-3">{vuln.description}</p>
                  <div className="bg-cyber-900 p-3 rounded text-sm font-mono text-emerald-400 border-l-2 border-emerald-500">
                    <span className="text-cyber-500 font-bold block mb-1">REMEDIATION:</span>
                    {vuln.remediation}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const ApiSecurityMonitor: React.FC = () => {
  const [inputType, setInputType] = useState<'URL' | 'SCHEMA'>('URL');
  const [inputValue, setInputValue] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!inputValue) return;
    setLoading(true);
    setResult(null);
    try {
      const data = await analyzeVulnerabilities(inputValue, 'API');
      setResult(data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result;
      if (typeof text === 'string') {
        setInputValue(text);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6">
      <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
          <Server className="text-cyber-500" /> API Security Monitor
        </h2>
        
        {/* Input Type Toggles */}
        <div className="flex gap-4 mb-6">
          <button 
            onClick={() => setInputType('URL')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              inputType === 'URL' 
                ? 'bg-cyber-600 text-white border border-cyber-500' 
                : 'bg-cyber-900 text-cyber-400 border border-cyber-700 hover:text-white'
            }`}
          >
            <Globe size={16} /> Endpoint URL
          </button>
          <button 
            onClick={() => setInputType('SCHEMA')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              inputType === 'SCHEMA' 
                ? 'bg-cyber-600 text-white border border-cyber-500' 
                : 'bg-cyber-900 text-cyber-400 border border-cyber-700 hover:text-white'
            }`}
          >
            <FileJson size={16} /> Swagger/OpenAPI Schema
          </button>
        </div>

        {/* Input Area */}
        <div className="space-y-4">
          {inputType === 'URL' ? (
            <input 
              type="text" 
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="https://api.example.com/v1"
              className="w-full bg-cyber-900 border border-cyber-600 rounded-lg p-3 text-white focus:border-cyber-500 outline-none font-mono"
            />
          ) : (
            <div className="relative group">
              <textarea 
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                placeholder='Paste your JSON or YAML OpenAPI Schema here...'
                className="w-full h-64 bg-cyber-900 border border-cyber-600 rounded-lg p-4 text-white focus:border-cyber-500 outline-none resize-none font-mono text-sm"
              />
              <div className="absolute bottom-4 right-4 opacity-70 group-hover:opacity-100 transition-opacity">
                 <label className="bg-cyber-700 hover:bg-cyber-600 text-white text-xs px-3 py-2 rounded cursor-pointer flex items-center gap-2 transition-colors border border-cyber-500/30">
                     <Upload size={14} /> Upload JSON/YAML
                     <input type="file" accept=".json,.yaml,.yml" onChange={handleFileUpload} className="hidden" />
                 </label>
              </div>
            </div>
          )}

          <button 
            onClick={handleScan}
            disabled={loading || !inputValue}
            className="w-full bg-cyber-500 text-cyber-900 font-bold py-3 rounded-lg hover:bg-emerald-400 transition-colors flex justify-center items-center gap-2"
          >
            {loading ? <Loader2 className="animate-spin" /> : <Search size={20} />}
            Analyze {inputType === 'URL' ? 'Endpoint' : 'Schema'}
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-cyber-800 p-8 rounded-xl border border-cyber-700 text-center animate-pulse">
          <Server className="w-12 h-12 text-cyber-500 mx-auto mb-4" />
          <p className="text-cyber-300 font-mono">Analyzing API Structure & Logic...</p>
          <p className="text-cyber-400 text-sm mt-2">Checking for BOLA, Rate Limiting & Data Exposure</p>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-cyber-800 p-4 rounded-xl border border-cyber-700">
              <p className="text-cyber-400 text-sm">Security Score</p>
              <div className="text-4xl font-bold text-white mt-2 flex items-baseline gap-2">
                {result.score} <span className="text-sm text-cyber-500">/ 100</span>
              </div>
            </div>
            <div className="bg-cyber-800 p-4 rounded-xl border border-cyber-700">
              <p className="text-cyber-400 text-sm">Vulnerabilities Found</p>
              <div className="text-4xl font-bold text-red-400 mt-2">
                {result.vulnerabilities.length}
              </div>
            </div>
            <div className="bg-cyber-800 p-4 rounded-xl border border-cyber-700">
              <p className="text-cyber-400 text-sm">Analysis Type</p>
              <div className="text-xl font-mono text-white mt-3">
                {inputType}
              </div>
            </div>
          </div>

          <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
             <div className="flex items-center gap-3 mb-6">
                <AlertOctagon className="text-cyber-500" />
                <h3 className="text-lg font-bold text-white">Security Assessment</h3>
             </div>
            <div className="space-y-3">
              {result.vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="bg-cyber-900/50 p-4 rounded-lg border border-cyber-700 hover:border-cyber-600 transition-colors">
                  <div className="flex justify-between items-start mb-2">
                    <h4 className="text-white font-semibold">{vuln.title}</h4>
                    <RiskBadge risk={vuln.risk} />
                  </div>
                  <p className="text-cyber-400 text-sm mb-3">{vuln.description}</p>
                  <div className="bg-cyber-900 p-3 rounded text-sm font-mono text-emerald-400 border-l-2 border-emerald-500">
                    <span className="text-cyber-500 font-bold block mb-1">RECOMMENDATION:</span>
                    {vuln.remediation}
                  </div>
                </div>
              ))}
              {result.vulnerabilities.length === 0 && (
                 <div className="text-center py-8 text-cyber-400">
                    <CheckCircle className="w-12 h-12 mx-auto mb-2 text-emerald-500 opacity-50" />
                    <p>No critical vulnerabilities detected in this analysis.</p>
                 </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const PhishingDetector: React.FC = () => {
  const [text, setText] = useState('');
  const [result, setResult] = useState<{isPhishing: boolean, confidence: number, reason: string} | null>(null);
  const [loading, setLoading] = useState(false);

  const check = async () => {
    setLoading(true);
    const res = await detectPhishing(text);
    setResult(res);
    setLoading(false);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
       <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700">
        <h2 className="text-xl font-bold text-white mb-2 flex items-center gap-2">
          <AlertOctagon className="text-red-500" /> Phishing & Spoofing Detector
        </h2>
        <p className="text-cyber-400 mb-6 text-sm">Analyze email content, SMS messages, or suspicious URLs for social engineering tactics.</p>
        
        <textarea 
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste email content or URL here..."
          className="w-full h-32 bg-cyber-900 border border-cyber-600 rounded-lg p-4 text-white focus:border-cyber-500 outline-none resize-none mb-4 font-mono text-sm"
        />
        
        <button 
          onClick={check}
          disabled={loading || !text}
          className="w-full bg-cyber-500 text-cyber-900 font-bold py-3 rounded-lg hover:bg-emerald-400 transition-colors flex justify-center items-center gap-2"
        >
          {loading ? <Loader2 className="animate-spin" /> : <Search size={20} />}
          Analyze Content
        </button>
      </div>

      {result && (
        <div className={`p-6 rounded-xl border ${result.isPhishing ? 'bg-red-900/20 border-red-500/50' : 'bg-emerald-900/20 border-emerald-500/50'}`}>
          <div className="flex items-center gap-4 mb-4">
            {result.isPhishing ? 
              <AlertTriangle className="w-10 h-10 text-red-500" /> : 
              <CheckCircle className="w-10 h-10 text-emerald-500" />
            }
            <div>
              <h3 className={`text-2xl font-bold ${result.isPhishing ? 'text-red-400' : 'text-emerald-400'}`}>
                {result.isPhishing ? 'High Probability of Phishing' : 'Likely Safe'}
              </h3>
              <p className="text-cyber-300">Confidence Score: <span className="font-mono">{result.confidence}%</span></p>
            </div>
          </div>
          <p className="text-white bg-cyber-900/50 p-4 rounded-lg border border-white/10">
            {result.reason}
          </p>
        </div>
      )}
    </div>
  );
};

const Dashboard: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Scans Today', val: '14', icon: Search, color: 'text-blue-400' },
          { label: 'Threats Blocked', val: '3', icon: Shield, color: 'text-emerald-400' },
          { label: 'Critical Vulns', val: '1', icon: AlertTriangle, color: 'text-red-500' },
          { label: 'API Health', val: '98%', icon: Server, color: 'text-purple-400' },
        ].map((stat, i) => (
          <div key={i} className="bg-cyber-800 p-4 rounded-xl border border-cyber-700">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-cyber-400 text-xs uppercase tracking-wider">{stat.label}</p>
                <h4 className="text-2xl font-bold text-white mt-1">{stat.val}</h4>
              </div>
              <stat.icon className={`${stat.color} opacity-80`} size={24} />
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700 h-[300px]">
          <h3 className="text-white font-bold mb-4">Threat Detection History</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={MOCK_CHART_DATA}>
              <CartesianGrid strokeDasharray="3 3" stroke="#233554" />
              <XAxis dataKey="name" stroke="#8892b0" />
              <YAxis stroke="#8892b0" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0a1628', borderColor: '#233554', color: '#fff' }}
                itemStyle={{ color: '#64ffda' }}
              />
              <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} />
              <Line type="monotone" dataKey="secure" stroke="#64ffda" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="bg-cyber-800 p-6 rounded-xl border border-cyber-700 h-[300px]">
           <h3 className="text-white font-bold mb-4">Scan Volume</h3>
            <ResponsiveContainer width="100%" height="100%">
            <BarChart data={MOCK_CHART_DATA}>
              <CartesianGrid strokeDasharray="3 3" stroke="#233554" />
              <XAxis dataKey="name" stroke="#8892b0" />
              <YAxis stroke="#8892b0" />
              <Tooltip 
                 contentStyle={{ backgroundColor: '#0a1628', borderColor: '#233554', color: '#fff' }}
              />
              <Bar dataKey="secure" fill="#233554" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

// --- MAIN APP LAYOUT ---

const MainLayout: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [view, setView] = useState('dashboard');
  
  // Initialize mock user
  const handleLogin = () => {
    setUser({
      id: 'usr_123',
      email: 'admin@demo.com',
      name: 'Demo Admin',
      hasPaid: false // Set to false to trigger lock screen demo
    });
  };

  const handleLogout = () => setUser(null);

  const handlePaymentSuccess = () => {
    if (user) {
      setUser({ ...user, hasPaid: true });
    }
  };

  if (!user) return <AuthPage onLogin={handleLogin} />;

  if (!user.hasPaid) {
    return <PaymentLock onSuccess={handlePaymentSuccess} userEmail={user.email} />;
  }

  return (
    <div className="min-h-screen bg-cyber-900 text-cyber-300 font-sans flex">
      <Sidebar 
        currentView={view} 
        setView={setView} 
        onLogout={handleLogout} 
      />
      
      <main className="ml-64 flex-1 p-8 h-screen overflow-y-auto">
        <header className="flex justify-between items-center mb-8">
          <div>
            <h2 className="text-2xl font-bold text-white capitalize">{view.replace('-', ' ')}</h2>
            <p className="text-sm text-cyber-400">Welcome back, {user.name}</p>
          </div>
          <div className="flex items-center gap-4">
             <div className="bg-cyber-800 px-4 py-2 rounded-full border border-cyber-700 text-sm flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                System Operational
             </div>
             <div className="w-10 h-10 bg-gradient-to-tr from-cyber-500 to-purple-500 rounded-full flex items-center justify-center text-cyber-900 font-bold">
               {user.name.charAt(0)}
             </div>
          </div>
        </header>

        <div className="max-w-6xl mx-auto">
          {view === 'dashboard' && <Dashboard />}
          {view === 'scanner' && <VulnerabilityScanner />}
          {view === 'phishing' && <PhishingDetector />}
          {view === 'api-sec' && <ApiSecurityMonitor />}
        </div>
      </main>
    </div>
  );
};

export default MainLayout;
