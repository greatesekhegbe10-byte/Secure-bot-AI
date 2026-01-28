export interface User {
  id: string;
  email: string;
  name: string;
  hasPaid: boolean;
}

export enum SecurityRisk {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  risk: SecurityRisk;
  remediation: string;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  score: number;
  vulnerabilities: Vulnerability[];
  summary: string;
}
