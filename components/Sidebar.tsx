import React from 'react';
import { ShieldAlert, Globe, Activity, Lock, LayoutDashboard, LogOut } from 'lucide-react';

interface SidebarProps {
  currentView: string;
  setView: (view: string) => void;
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ currentView, setView, onLogout }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scanner', label: 'Vuln. Scanner', icon: Globe },
    { id: 'phishing', label: 'Phishing Detector', icon: ShieldAlert },
    { id: 'api-sec', label: 'API Security', icon: Lock },
  ];

  return (
    <div className="w-64 bg-cyber-800 h-screen flex flex-col border-r border-cyber-700 fixed left-0 top-0">
      <div className="p-6 flex items-center gap-3">
        <Activity className="text-cyber-500 w-8 h-8" />
        <h1 className="text-xl font-bold tracking-wider text-white">SecurBot<span className="text-cyber-500">.ai</span></h1>
      </div>

      <div className="px-6 mb-6">
        <div className="bg-cyber-700/50 rounded-lg p-3 border border-cyber-600 flex items-center justify-between">
          <div>
            <p className="text-xs text-cyber-400 uppercase tracking-wider mb-1">Status</p>
            <span className="font-bold text-emerald-400">UNLOCKED</span>
          </div>
          <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_10px_#10b981]"></div>
        </div>
      </div>

      <nav className="flex-1 px-4 space-y-2">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setView(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                isActive 
                  ? 'bg-cyber-600/50 text-cyber-500 border-l-2 border-cyber-500' 
                  : 'text-cyber-400 hover:bg-cyber-700 hover:text-white'
              }`}
            >
              <Icon size={20} />
              <span className="font-medium">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-cyber-700">
        <button 
          onClick={onLogout}
          className="w-full flex items-center gap-3 px-4 py-3 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
        >
          <LogOut size={20} />
          <span>Sign Out</span>
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
