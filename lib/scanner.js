const fs = require('fs').promises;
const path = require('path');

// Severity levels
const SEVERITY = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high'
};

// Supported file extensions
const SUPPORTED_EXTENSIONS = ['.md', '.markdown', '.yml', '.yaml', '.json', '.js', '.jsx', '.ts', '.tsx'];

// Detection patterns
const PATTERNS = {
  // Hidden comments
  hiddenComments: {
    patterns: [
      /<!--[\s\S]*?-->/g,  // HTML comments
      /\/\*[\s\S]*?\*\//g,  // Block comments
      /^\s*\/\/.*/gm,       // Line comments
      /{#[\s\S]*?#}/g,      // Jinja2 comments
      /<%--[\s\S]*?--%>/g   // JSP comments
    ],
    severity: SEVERITY.MEDIUM,
    reason: 'Hidden comment detected'
  },

  // Base64 encoded strings
  base64: {
    patterns: [
      /[A-Za-z0-9+\/]{16,}={0,2}/g  // Reduced from 20 to 16
    ],
    severity: SEVERITY.HIGH,
    reason: 'Potential Base64 encoded content',
    validate: (match) => {
      // Additional validation to reduce false positives
      try {
        const decoded = Buffer.from(match, 'base64').toString();
        // Check if decoded content is printable
        return /^[\x20-\x7E\s]+$/.test(decoded);
      } catch {
        return false;
      }
    }
  },

  // Hex encoded strings
  hexEncoded: {
    patterns: [
      /(?:0x)?[0-9a-fA-F]{16,}/g
    ],
    severity: SEVERITY.MEDIUM,
    reason: 'Potential hex encoded content'
  },

  // Unicode obfuscation
  unicodeObfuscation: {
    patterns: [
      /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g,  // Zero-width and invisible characters
      /[\u0300-\u036F]{3,}/g,  // Excessive combining diacritics
      /[\uE000-\uF8FF]/g,      // Private use area
    ],
    severity: SEVERITY.HIGH,
    reason: 'Suspicious Unicode patterns detected'
  },

  // Suspicious markdown patterns
  suspiciousMarkdown: {
    patterns: [
      /\[.*?\]\(javascript:.*?\)/gi,  // JavaScript URLs
      /\[.*?\]\(data:.*?\)/gi,         // Data URLs
      /<script[\s\S]*?<\/script>/gi,   // Script tags
      /<iframe[\s\S]*?>/gi,            // Iframe tags
      /\bon\w+\s*=/gi                  // Event handlers
    ],
    severity: SEVERITY.HIGH,
    reason: 'Suspicious markdown/HTML pattern'
  },

  // Prompt injection keywords
  promptInjection: {
    patterns: [
      // English patterns
      /ignore\s+(?:all\s+)?(?:previous|above)\s+instructions?/gi,
      /disregard\s+(?:all\s+)?(?:previous|above)\s+instructions?/gi,
      /forget\s+everything/gi,
      /new\s+instructions?:/gi,
      /you\s+are\s+now/gi,
      /act\s+as\s+(?:a|an)/gi,
      /pretend\s+(?:to\s+be|you\s+are)/gi,
      /\bsystem\s*:\s*["\']?/gi,
      /\buser\s*:\s*["\']?/gi,
      /\bassistant\s*:\s*["\']?/gi,
      // Detect instructions to AI assistants
      /(?:hey\s+)?(?:copilot|claude|gpt|chatgpt|assistant|ai|bot),?\s*(?:please\s+)?(?:add|append|include|say|write|put)/gi,
      /add\s+["']?.*?["']?\s+(?:at|to)\s+(?:the\s+)?(?:end|beginning)\s+of\s+(?:your\s+)?(?:answer|response|output)/gi,
      /(?:always|please|must)\s+(?:end|finish|conclude)\s+(?:your\s+)?(?:answer|response|output)\s+with/gi,
      /(?:end|finish|conclude|sign off)\s+(?:every\s+)?(?:answer|response|message)\s+(?:with|by)/gi,
      /(?:your\s+)?(?:answer|response|output)\s+(?:should|must)\s+(?:end|include|contain)/gi,
      
      // Spanish patterns
      /ignora?\s+(?:todas?\s+las?\s+)?(?:instrucciones?\s+)?(?:anteriores?|previas?)/gi,
      /no\s+hagas?\s+caso\s+(?:a\s+)?(?:las?\s+)?instrucciones?\s+anteriores?/gi,
      /olvida\s+todo/gi,
      /nuevas?\s+instrucciones?:/gi,
      /ahora\s+eres?/gi,
      /act[uú]a\s+como\s+(?:un|una)/gi,
      /finge\s+(?:que\s+)?(?:eres?|ser)/gi,
      /sistema\s*:\s*["\']?/gi,
      /usuario\s*:\s*["\']?/gi,
      /asistente\s*:\s*["\']?/gi,
      
      // French patterns
      /ignore[sz]?\s+(?:toutes?\s+les?\s+)?instructions?\s+(?:pr[eé]c[eé]dentes?|ant[eé]rieures?)/gi,
      /ne\s+(?:pas\s+)?(?:tenir\s+compte|faire\s+attention)\s+(?:des?\s+)?instructions?\s+pr[eé]c[eé]dentes?/gi,
      /oublie[sz]?\s+tout/gi,
      /nouvelles?\s+instructions?\s*:/gi,
      /(?:tu\s+es|vous\s+[eê]tes)\s+maintenant/gi,
      /agis?\s+comme\s+(?:un|une)/gi,
      /(?:fais|faites)\s+semblant\s+(?:d'[eê]tre|que\s+(?:tu\s+es|vous\s+[eê]tes))/gi,
      /syst[eè]me\s*:\s*["\']?/gi,
      /utilisateur\s*:\s*["\']?/gi,
      /assistant\s*:\s*["\']?/gi,
      
      // German patterns
      /ignoriere?\s+(?:alle\s+)?(?:vorherigen|fr[uü]heren)\s+(?:anweisungen?|instruktionen?)/gi,
      /vergiss\s+alles/gi,
      /neue\s+(?:anweisungen?|instruktionen?)\s*:/gi,
      /du\s+bist\s+jetzt/gi,
      /verhalte?\s+dich\s+wie\s+(?:ein|eine)/gi,
      /tu\s+so\s+als\s+(?:ob\s+du|w[aä]rst\s+du)/gi,
      /system\s*:\s*["\']?/gi,
      /benutzer\s*:\s*["\']?/gi,
      /assistent\s*:\s*["\']?/gi,
      
      // Chinese patterns (Simplified and Traditional)
      /忽略(?:所有)?(?:之前|以前|前面)的(?:指令|说明|指示)/gi,
      /无视(?:所有)?(?:之前|以前|前面)的(?:指令|说明|指示)/gi,
      /忘记(?:所有|全部)/gi,
      /新的?(?:指令|说明|指示)[:：]/gi,
      /你现在是/gi,
      /扮演(?:一个|一位)/gi,
      /假装(?:你是|自己是)/gi,
      /系统[:：]\s*["\']?/gi,
      /用户[:：]\s*["\']?/gi,
      /助手[:：]\s*["\']?/gi,
      // Traditional Chinese variants
      /忽略(?:所有)?(?:之前|以前|前面)的(?:指令|說明|指示)/gi,
      /無視(?:所有)?(?:之前|以前|前面)的(?:指令|說明|指示)/gi,
      /忘記(?:所有|全部)/gi,
      /現在你是/gi,
      
      // Japanese patterns
      /(?:前の|以前の|これまでの)(?:指示|命令|指令)を(?:無視|忘れ)/gi,
      /すべてを忘れ/gi,
      /新しい(?:指示|命令|指令)[:：]/gi,
      /あなたは今/gi,
      /(?:として|みたいに)(?:振る舞|行動)/gi,
      /(?:のふりを|の真似を)(?:し|する)/gi,
      /システム[:：]\s*["\']?/gi,
      /ユーザー[:：]\s*["\']?/gi,
      /アシスタント[:：]\s*["\']?/gi
    ],
    severity: SEVERITY.HIGH,
    reason: 'Potential prompt injection attempt'
  },

  // Encoded URLs
  encodedUrls: {
    patterns: [
      /%[2-7][0-9A-F]/gi
    ],
    severity: SEVERITY.LOW,
    reason: 'URL encoding detected',
    validate: (match, fullLine) => {
      // Check if it's part of a longer encoded sequence
      const urlPattern = /%[0-9A-F]{2}/gi;
      const matches = fullLine.match(urlPattern);
      return matches && matches.length > 3;
    }
  }
};

/**
 * Scan a file or directory for vulnerabilities
 */
async function scan(targetPath, options = {}) {
  const results = {
    filesScanned: 0,
    vulnerabilities: []
  };

  const stats = await fs.stat(targetPath);
  
  if (stats.isFile()) {
    await scanFile(targetPath, results, options);
  } else if (stats.isDirectory()) {
    await scanDirectory(targetPath, results, options);
  }

  return results;
}

/**
 * Scan a directory recursively
 */
async function scanDirectory(dirPath, results, options) {
  const entries = await fs.readdir(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    
    // Check exclusions
    if (shouldExclude(fullPath, options.exclude || [])) {
      continue;
    }

    if (entry.isFile() && shouldIncludeFile(fullPath, options.include)) {
      await scanFile(fullPath, results, options);
    } else if (entry.isDirectory() && options.recursive !== false) {
      await scanDirectory(fullPath, results, options);
    }
  }
}

/**
 * Scan a single file
 */
async function scanFile(filePath, results, options) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const vulnerabilities = scanContent(content, filePath);
    
    results.filesScanned++;
    results.vulnerabilities.push(...vulnerabilities);
  } catch (error) {
    // Skip files that can't be read
    console.error(`Warning: Could not read file ${filePath}: ${error.message}`);
  }
}

/**
 * Scan text content for vulnerabilities
 */
function scanContent(content, filename = 'unknown') {
  const vulnerabilities = [];
  const lines = content.split('\n');

  // Check each pattern type
  Object.entries(PATTERNS).forEach(([type, config]) => {
    config.patterns.forEach(pattern => {
      let match;
      const regex = new RegExp(pattern.source, pattern.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = getLineNumber(content, match.index);
        const line = lines[lineNumber - 1];
        
        // Apply validation if exists
        if (config.validate && !config.validate(match[0], line)) {
          continue;
        }

        // Skip if it looks like a legitimate use
        if (shouldSkipMatch(match[0], line, type)) {
          continue;
        }

        vulnerabilities.push({
          file: filename,
          line: lineNumber,
          severity: config.severity,
          type: type,
          reason: config.reason,
          content: match[0].trim()
        });
      }
    });
  });

  return vulnerabilities;
}

/**
 * Get line number for a given index in content
 */
function getLineNumber(content, index) {
  return content.substring(0, index).split('\n').length;
}

/**
 * Check if a file should be included based on extensions
 */
function shouldIncludeFile(filePath, includeExtensions) {
  const ext = path.extname(filePath).toLowerCase();
  
  if (!includeExtensions || includeExtensions.length === 0) {
    return SUPPORTED_EXTENSIONS.includes(ext);
  }

  return includeExtensions.some(incExt => {
    const normalizedExt = incExt.startsWith('.') ? incExt : `.${incExt}`;
    return ext === normalizedExt.toLowerCase();
  });
}

/**
 * Check if a path should be excluded
 */
function shouldExclude(filePath, excludePatterns) {
  return excludePatterns.some(pattern => {
    if (pattern.includes('*')) {
      // Simple glob pattern
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      return regex.test(filePath);
    }
    return filePath.includes(pattern);
  });
}

/**
 * Determine if a match should be skipped (false positive reduction)
 */
function shouldSkipMatch(match, line, type) {
  // Skip base64 if it looks like a legitimate hash or ID
  if (type === 'base64' && (
    line.includes('sha') || 
    line.includes('hash') || 
    line.includes('token') ||
    line.includes('key') ||
    match.length < 16  // Reduced from 20 to match pattern
  )) {
    return true;
  }

  // Skip hex if it's likely a color code or commit hash
  if (type === 'hexEncoded' && (
    match.length === 6 || 
    match.length === 3 || 
    match.length === 40 || // Git commit hash
    line.includes('color') ||
    line.includes('#')
  )) {
    return true;
  }

  // Skip URL encoding if it's in an actual URL
  if (type === 'encodedUrls' && (
    line.includes('http://') ||
    line.includes('https://') ||
    line.includes('url')
  )) {
    return false; // Actually include these
  }

  return false;
}

/**
 * Format results for display
 */
function formatResults(results) {
  return results;
}

module.exports = {
  scan,
  scanContent,
  formatResults,
  SEVERITY
};
