export interface NVDVulnerability {
  cve: {
    id: string;
    metrics?: {
      cvssMetrics?: Array<{
        severity: string;
      }>;
    };
    descriptions?: Array<{
      value: string;
    }>;
    published: string;
    lastModified: string;
  };
}

export interface CISAVulnerability {
  cveID: string;
  vendorProject: string;
  dateAdded: string;
}