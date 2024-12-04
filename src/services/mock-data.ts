import { CVE } from '../types/cve';

export const mockExploitedCVEs: string[] = [
  'CVE-2024-1234',
  'CVE-2024-5678',
  'CVE-2024-9012'
];

export const mockPaloAltoCVEs: CVE[] = [
  {
    id: 'CVE-2024-1234',
    severity: 'CRITICAL',
    description: 'Remote code execution vulnerability in PAN-OS',
    published: '2024-01-15T00:00:00.000Z',
    lastModified: '2024-01-20T00:00:00.000Z',
    exploited: true
  },
  {
    id: 'CVE-2024-5678',
    severity: 'HIGH',
    description: 'Authentication bypass in Prisma Cloud',
    published: '2024-02-01T00:00:00.000Z',
    lastModified: '2024-02-05T00:00:00.000Z',
    exploited: true
  },
  {
    id: 'CVE-2023-9876',
    severity: 'MEDIUM',
    description: 'Information disclosure in Cortex XDR',
    published: '2023-12-10T00:00:00.000Z',
    lastModified: '2023-12-15T00:00:00.000Z',
    exploited: false
  },
  {
    id: 'CVE-2023-5432',
    severity: 'LOW',
    description: 'Cross-site scripting in XSOAR',
    published: '2023-11-20T00:00:00.000Z',
    lastModified: '2023-11-25T00:00:00.000Z',
    exploited: false
  }
];