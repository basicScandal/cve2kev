import axios from 'axios';
import { CVE } from '../types/cve';
import { NVDVulnerability, CISAVulnerability } from './api-types';
import { transformNVDResponse, filterPaloAltoCVEs } from './transformers';
import { mockPaloAltoCVEs, mockExploitedCVEs } from './mock-data';

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const USE_MOCK_DATA = true; // Toggle this for development

export async function fetchPaloAltoCVEs(): Promise<CVE[]> {
  if (USE_MOCK_DATA) {
    return mockPaloAltoCVEs;
  }

  try {
    const response = await axios.get(NVD_API_BASE, {
      params: {
        keywordSearch: 'palo alto',
        keywordExactMatch: true,
      },
    });

    if (!response.data?.vulnerabilities) {
      console.error('Invalid NVD API response format');
      return mockPaloAltoCVEs; // Fallback to mock data
    }

    return response.data.vulnerabilities
      .map((vuln: NVDVulnerability) => transformNVDResponse(vuln))
      .filter((cve: CVE) => cve.id && cve.severity);
  } catch (error) {
    console.error('NVD API Error:', error instanceof Error ? error.message : 'Unknown error');
    return mockPaloAltoCVEs; // Fallback to mock data
  }
}

export async function fetchExploitedCVEs(): Promise<string[]> {
  if (USE_MOCK_DATA) {
    return mockExploitedCVEs;
  }

  try {
    const response = await axios.get<{ vulnerabilities: CISAVulnerability[] }>(CISA_KEV_URL);

    if (!response.data?.vulnerabilities) {
      console.error('Invalid CISA KEV response format');
      return mockExploitedCVEs; // Fallback to mock data
    }

    return filterPaloAltoCVEs(response.data.vulnerabilities);
  } catch (error) {
    console.error('CISA KEV API Error:', error instanceof Error ? error.message : 'Unknown error');
    return mockExploitedCVEs; // Fallback to mock data
  }
}