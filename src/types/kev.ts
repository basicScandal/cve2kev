export interface KEVCWEData {
  [cweId: string]: {
    count: number;
    description: string;
  };
}

export interface KEVStats {
  total: number;
  byCWE: KEVCWEData;
}