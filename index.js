const scanner = require('./lib/scanner');

/**
 * Scan a file or directory for potential prompt injection vulnerabilities
 * @param {string} path - File path or directory to scan
 * @param {Object} options - Scanning options
 * @param {boolean} options.recursive - Recursively scan directories (default: true)
 * @param {boolean} options.json - Return results as JSON (default: false)
 * @param {string[]} options.include - File extensions to include (default: all supported)
 * @param {string[]} options.exclude - Patterns to exclude
 * @returns {Promise<Object>} Scan results
 */
async function scan(path, options = {}) {
  const defaultOptions = {
    recursive: true,
    json: false,
    include: null,
    exclude: []
  };

  const mergedOptions = { ...defaultOptions, ...options };
  
  try {
    const results = await scanner.scan(path, mergedOptions);
    
    if (mergedOptions.json) {
      return results;
    }
    
    return scanner.formatResults(results);
  } catch (error) {
    throw new Error(`Scan failed: ${error.message}`);
  }
}

/**
 * Scan text content directly for vulnerabilities
 * @param {string} content - Text content to scan
 * @param {string} filename - Optional filename for context
 * @returns {Object} Scan results
 */
function scanContent(content, filename = 'unknown') {
  return scanner.scanContent(content, filename);
}

module.exports = {
  scan,
  scanContent,
  // Export severity levels for external use
  SEVERITY: scanner.SEVERITY
};