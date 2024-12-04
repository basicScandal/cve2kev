import { NVDVulnerability, CISAVulnerability } from './api-types';
import { CVE } from '../types/cve';

export function transformNVDResponse(vuln: NVDVulnerability): CVE {
  return {
    id: vuln.cve.id,
    severity: (vuln.cve.metrics?.cvssMetrics?.[0]?.severity || 'MEDIUM') as CVE['severity'],
    description: vuln.cve.descriptions?.[0]?.value || '',
    published: vuln.cve.published,
    lastModified: vuln.cve.lastModified,
    exploited: false,
  };
}

export function filterPaloAltoCVEs(vulns: CISAVulnerability[]): string[] {
  return vulns
    .filter(vuln => 
      typeof vuln.vendorProject === 'string' && 
      vuln.vendorProject.toLowerCase().includes('palo alto')
    )
    .map(vuln => vuln.cveID);
}