// Color palette organized by vulnerability categories
export const vulnerabilityColors = {
  // Command Injection & Code Execution
  commandInjection: '#FF4B4B',
  osCommandInjection: '#FF6B6B',
  codeExecution: '#FF8B8B',
  
  // Authentication & Authorization
  authBypass: '#4ECDC4',
  privilegeEscalation: '#45B7D1',
  missingAuth: '#2D9CDB',
  improperAuth: '#56CCF2',
  
  // Input Validation & Sanitization
  inputValidation: '#F2C94C',
  pathTraversal: '#F2994A',
  formatString: '#FFB347',
  syntaxValidation: '#FFD93D',
  
  // Information Disclosure
  infoExposure: '#6772E5',
  sensitiveData: '#5851DB',
  credentialExposure: '#9B51E0',
  cleartext: '#8B5CF6',
  
  // Access Control
  improperAccess: '#EB5757',
  accessControl: '#EF4444',
  incorrectPerms: '#DC2626',
  accessBypass: '#B91C1C',
  
  // Cryptographic Issues
  weakCrypto: '#805AD5',
  certValidation: '#6B46C1',
  cryptoVerification: '#553C9A',
  encryptionStrength: '#9F7AEA',
  
  // Resource Management
  resourceLeak: '#10B981',
  memoryCorruption: '#059669',
  nullPointer: '#047857',
  bufferOverflow: '#065F46',
  
  // Configuration & Setup
  configError: '#F59E0B',
  defaultConfig: '#D97706',
  misconfiguration: '#B45309',
  improperSetup: '#92400E',
  
  // Request Handling
  ssrf: '#EC4899',
  requestForgery: '#DB2777',
  requestValidation: '#BE185D',
  requestHandling: '#9D174D',
  
  // Cross-Site Scripting
  xss: '#8B5CF6',
  storedXss: '#7C3AED',
  reflectedXss: '#6D28D9',
  domXss: '#5B21B6',
  
  // SQL Injection
  sqlInjection: '#14B8A6',
  blindSqlInjection: '#0D9488',
  timeSqlInjection: '#0F766E',
  
  // Default
  default: '#64748B'
};

// Function to get color by vulnerability type
export function getVulnerabilityColor(type: string): string {
  const colorMap: { [key: string]: string } = {
    // Command Injection
    'Command Injection': vulnerabilityColors.commandInjection,
    'OS Command Injection': vulnerabilityColors.osCommandInjection,
    
    // SQL Injection
    'SQL Injection': vulnerabilityColors.sqlInjection,
    
    // XSS
    'Cross-site Scripting': vulnerabilityColors.xss,
    'Stored XSS': vulnerabilityColors.storedXss,
    'Reflected XSS': vulnerabilityColors.reflectedXss,
    
    // Authentication
    'Missing Authentication': vulnerabilityColors.missingAuth,
    'Authentication Bypass': vulnerabilityColors.authBypass,
    'Improper Authentication': vulnerabilityColors.improperAuth,
    
    // Authorization
    'Improper Authorization': vulnerabilityColors.improperAccess,
    'Incorrect Authorization': vulnerabilityColors.accessControl,
    'Authorization Bypass': vulnerabilityColors.accessBypass,
    
    // Privilege
    'Improper Privilege Management': vulnerabilityColors.privilegeEscalation,
    'Privilege Escalation': vulnerabilityColors.privilegeEscalation,
    
    // Input Validation
    'Input Validation': vulnerabilityColors.inputValidation,
    'Improper Input Validation': vulnerabilityColors.inputValidation,
    
    // Path Traversal
    'Path Traversal': vulnerabilityColors.pathTraversal,
    
    // Information Disclosure
    'Information Exposure': vulnerabilityColors.infoExposure,
    'Information Disclosure': vulnerabilityColors.infoExposure,
    'Sensitive Data': vulnerabilityColors.sensitiveData,
    
    // Cleartext
    'Cleartext Storage': vulnerabilityColors.cleartext,
    'Cleartext Transmission': vulnerabilityColors.cleartext,
    
    // Cryptographic
    'Inadequate Encryption': vulnerabilityColors.weakCrypto,
    'Weak Cryptography': vulnerabilityColors.weakCrypto,
    'Improper Certificate Validation': vulnerabilityColors.certValidation,
    
    // Resource Management
    'Resource Management': vulnerabilityColors.resourceLeak,
    'Memory Management': vulnerabilityColors.memoryCorruption,
    'NULL Pointer Dereference': vulnerabilityColors.nullPointer,
    
    // Request Handling
    'Server-Side Request Forgery': vulnerabilityColors.ssrf,
    'SSRF': vulnerabilityColors.ssrf,
    
    // Default
    'Default': vulnerabilityColors.default
  };

  // Try to find a close match if exact match not found
  const key = Object.keys(colorMap).find(k => 
    type.toLowerCase().includes(k.toLowerCase())
  );
  
  return key ? colorMap[key] : vulnerabilityColors.default;
}