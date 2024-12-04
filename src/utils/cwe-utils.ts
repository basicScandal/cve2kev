import { Vulnerability } from '../types/vulnerability';
import { getVulnerabilityColor } from './colors';

export interface CWEData {
  [key: string]: number;
}

function extractCWEDescription(cwe: string): string {
  const parts = cwe.split(' ');
  return parts.slice(1).join(' ').replace(/['"()]/g, '');
}

export function analyzeCWEDistribution(vulnerabilities: Vulnerability[]): CWEData {
  const cweDistribution: CWEData = {};
  
  vulnerabilities.forEach(vuln => {
    if (vuln.cwe) {
      const description = extractCWEDescription(vuln.cwe);
      cweDistribution[description] = (cweDistribution[description] || 0) + 1;
    }
  });

  return cweDistribution;
}

export const cweColors = new Proxy({}, {
  get: (target, prop) => {
    if (typeof prop === 'string') {
      return getVulnerabilityColor(prop);
    }
    return vulnerabilityColors.default;
  }
});