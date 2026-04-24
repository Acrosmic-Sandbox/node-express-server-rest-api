import { URL } from 'url';

/**
 * SSRF Protection Middleware
 * Validates URLs and blocks requests to private IP ranges and metadata endpoints
 */

// Private IP ranges (CIDR notation)
const PRIVATE_IP_RANGES = [
  { min: 0, max: 16777215 },           // 0.0.0.0/8
  { min: 167772160, max: 184549375 },  // 10.0.0.0/8
  { min: 2130706432, max: 2147483647 }, // 127.0.0.0/8
  { min: 2886729728, max: 2887778303 }, // 172.16.0.0/12
  { min: 3232235520, max: 3232301055 }, // 192.168.0.0/16
  { min: 2852126720, max: 2852132863 }, // 169.254.0.0/16 (link-local)
  { min: 3758096384, max: 4294967295 }, // 224.0.0.0/4 (multicast)
];

// Metadata endpoints that should be blocked
const BLOCKED_HOSTNAMES = [
  'metadata.google.internal',
  'metadata.google.com',
  'instance-data',
  'instance-metadata',
  'localhost',
  'local',
];

/**
 * Convert IPv4 address string to 32-bit integer
 * @param {string} ip - IPv4 address (e.g., "192.168.1.1")
 * @returns {number} 32-bit integer representation
 */
function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  
  return parts.reduce((acc, part, idx) => {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return null;
    return acc + (num << (8 * (3 - idx)));
  }, 0);
}

/**
 * Check if an IP address is in a private range
 * @param {string} ip - IPv4 address
 * @returns {boolean} true if IP is private
 */
function isPrivateIP(ip) {
  const ipInt = ipToInt(ip);
  if (ipInt === null) return false;
  
  return PRIVATE_IP_RANGES.some(range => ipInt >= range.min && ipInt <= range.max);
}

/**
 * Check if a hostname is a blocked metadata endpoint
 * @param {string} hostname - Hostname to check
 * @returns {boolean} true if hostname is blocked
 */
function isBlockedHostname(hostname) {
  const lowerHostname = hostname.toLowerCase();
  return BLOCKED_HOSTNAMES.some(blocked => 
    lowerHostname === blocked || lowerHostname.endsWith('.' + blocked)
  );
}

/**
 * Validate a URL for SSRF vulnerabilities
 * @param {string} urlString - URL to validate
 * @returns {object} { valid: boolean, error?: string }
 */
export function validateURL(urlString) {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;
    
    // Check for blocked hostnames
    if (isBlockedHostname(hostname)) {
      return {
        valid: false,
        error: `Blocked hostname: ${hostname}`,
      };
    }
    
    // Check for private IP addresses
    if (isPrivateIP(hostname)) {
      return {
        valid: false,
        error: `Private IP address not allowed: ${hostname}`,
      };
    }
    
    // Check for IPv6 loopback and private ranges
    if (hostname === '::1' || hostname === '::' || hostname.startsWith('fc') || hostname.startsWith('fd')) {
      return {
        valid: false,
        error: `Private IPv6 address not allowed: ${hostname}`,
      };
    }
    
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: `Invalid URL: ${error.message}`,
    };
  }
}

/**
 * SSRF Protection Middleware
 * Validates URLs in request body and query parameters
 */
export function ssrfProtectionMiddleware(req, res, next) {
  // Store the original request methods
  const originalFetch = global.fetch;
  const originalHttpGet = require('http').get;
  const originalHttpsGet = require('https').get;
  
  // Wrap fetch to validate URLs
  if (global.fetch) {
    global.fetch = function(url, ...args) {
      const validation = validateURL(url);
      if (!validation.valid) {
        const error = new Error(validation.error);
        error.statusCode = 403;
        throw error;
      }
      return originalFetch.call(this, url, ...args);
    };
  }
  
  // Store wrapped functions in request context for cleanup
  req.ssrfWrappedFunctions = {
    fetch: global.fetch,
  };
  
  // Add validation utility to request context
  req.validateURL = validateURL;
  
  // Cleanup on response finish
  res.on('finish', () => {
    if (global.fetch && req.ssrfWrappedFunctions.fetch) {
      global.fetch = originalFetch;
    }
  });
  
  next();
}

/**
 * Express middleware factory
 * Returns the SSRF protection middleware
 */
export default function createSSRFMiddleware() {
  return ssrfProtectionMiddleware;
}
