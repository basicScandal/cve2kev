export interface CVE {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  published: string;
  lastModified: string;
  exploited: boolean;
}

export interface CVEStats {
  total: number;
  exploited: number;
  bySeverity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
}