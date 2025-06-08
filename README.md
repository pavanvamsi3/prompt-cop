# Prompt Cop

<p align="center">
  <img src="assets/logo.png" width="300">
</p>


A light weight library prompt-cop scans text files in your project for potential **prompt injection vulnerabilities**.

Use it from the command line or as a library in your tooling.

### Prompt Injection Example in GPT
--------------

<p align="center">
  <img src="assets/chat-gpt-injection.png" width="1000">
</p>

## Features

- Scan files or directories recursively
- Works with Markdown, YAML, JSON, JS/TS, and more
- Detect hidden comments, obfuscation, Unicode tricks, and other injection patterns
- Optional Hugging Face AI detection of prompt injections
- Output results as color-coded text or JSON
- Customize include/exclude patterns and severity filtering

## Installation

Requires Node.js 14 or higher.

```bash
npm install -g prompt-cop
```

Or as a development dependency:

```bash
npm install --save-dev prompt-cop
```

## AI Detection Setup (Optional)

To enable AI-powered detection using Hugging Face models:

1. Sign up for a free account at [huggingface.co](https://huggingface.co)
2. Generate an access token at [Settings > Access Tokens](https://huggingface.co/settings/tokens)
3. Set the environment variable:
   ```bash
   export HF_ACCESS_TOKEN=hf_your_token_here
   ```
4. Use the `--ai` flag or `ai: true` option to enable AI detection

## Usage

### Command Line Interface (CLI)

Basic usage:
```bash
prompt-cop ./src
```

Scan a specific file:
```bash
prompt-cop README.md
```

Advanced options:
```bash
# Output as JSON
prompt-cop ./src --json

# Only show medium and high severity issues
prompt-cop ./src --severity medium

# Include only specific file types
prompt-cop ./src --include .md .yml

# Exclude directories
prompt-cop . --exclude node_modules dist

# Non-recursive scan
prompt-cop ./src --no-recursive

# Use AI detection (requires HF_ACCESS_TOKEN environment variable)
prompt-cop ./src --ai
```

### CLI Options

- `-r, --no-recursive` - Do not scan directories recursively
- `-j, --json` - Output results as JSON
- `-i, --include <extensions...>` - File extensions to include (e.g., .md .yml)
- `-e, --exclude <patterns...>` - Patterns to exclude (e.g., node_modules)
- `-s, --severity <level>` - Minimum severity level to report (low, medium, high)
- `-a, --ai` - Use Hugging Face model for detection (requires HF_ACCESS_TOKEN)

### Programmatic API

```javascript
const { scan, scanContent, scanContentAI, SEVERITY } = require('prompt-cop');

// Scan a file or directory
async function checkVulnerabilities() {
  try {
    const results = await scan('./src', {
      recursive: true,
      exclude: ['node_modules', 'dist'],
      include: ['.md', '.yml'],
      json: true,
      ai: true
    });
    
    console.log(`Files scanned: ${results.filesScanned}`);
    console.log(`Vulnerabilities found: ${results.vulnerabilities.length}`);
    
    results.vulnerabilities.forEach(vuln => {
      console.log(`${vuln.file}:${vuln.line} - ${vuln.reason}`);
    });
  } catch (error) {
    console.error('Scan failed:', error);
  }
}

// Scan text content directly
const content = '<!-- Hidden comment --> Some text';
const vulnerabilities = scanContent(content, 'example.md');
const aiVulnerabilities = await scanContentAI(content, 'example.md');
```
## Terminal Examples

## Examples of Detected Vulnerabilities

## Integration with CI/CD

Use prompt-cop in your CI/CD pipeline to automatically check for vulnerabilities:

### GitHub Actions Example

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  prompt-injection-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install -g prompt-cop
      - run: prompt-cop . --exclude node_modules --severity medium
```

### Pre-commit Hook

```json
{
  "husky": {
    "hooks": {
      "pre-commit": "prompt-cop . --exclude node_modules"
    }
  }
}
```

## Exit Codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities detected or error occurred

## Development

### Running Tests

```bash
npm test
```

### Running Tests with Coverage

```bash
npm run test:coverage
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
