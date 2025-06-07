#!/usr/bin/env node

const { program } = require('commander');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs').promises;
const { scan } = require('./index');

// Package information
const pkg = require('./package.json');

// Configure CLI
program
  .name('prompt-cop')
  .description('Detect potential prompt injection vulnerabilities in code files')
  .version(pkg.version);

program
  .argument('<path>', 'File or directory to scan')
  .option('-r, --no-recursive', 'Do not scan directories recursively')
  .option('-j, --json', 'Output results as JSON')
  .option('-i, --include <extensions...>', 'File extensions to include (e.g., .md .yml)')
  .option('-e, --exclude <patterns...>', 'Patterns to exclude (e.g., node_modules)')
  .option('-s, --severity <level>', 'Minimum severity level to report (low, medium, high)', 'low')
  .action(async (targetPath, options) => {
    try {
      // Resolve path
      const resolvedPath = path.resolve(targetPath);
      
      // Check if path exists
      try {
        await fs.access(resolvedPath);
      } catch {
        console.error(chalk.red(`✗ Path not found: ${resolvedPath}`));
        process.exit(1);
      }

      // Prepare options
      const scanOptions = {
        recursive: options.recursive,
        json: options.json,
        include: options.include,
        exclude: options.exclude || [],
        minSeverity: options.severity.toLowerCase()
      };

      // Add common exclude patterns
      if (!options.exclude || options.exclude.length === 0) {
        scanOptions.exclude = ['node_modules', '.git', 'dist', 'build'];
      }

      // Perform scan
      const scanMsg = chalk.blue(`\nScanning ${resolvedPath}...\n`);
      if (options.json) {
        // Write progress message to stderr so JSON output stays clean
        console.error(scanMsg);
      } else {
        console.log(scanMsg);
      }
      
      const results = await scan(resolvedPath, scanOptions);
      
      if (options.json) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        displayResults(results, options.severity);
      }

      // Exit with error code if vulnerabilities found
      const hasVulnerabilities = results.vulnerabilities && results.vulnerabilities.length > 0;
      process.exit(hasVulnerabilities ? 1 : 0);

    } catch (error) {
      console.error(chalk.red(`✗ Error: ${error.message}`));
      process.exit(1);
    }
  });

// Display formatted results
function displayResults(results, minSeverity) {
  const severityColors = {
    low: chalk.yellow,
    medium: chalk.rgb(255, 136, 0),
    high: chalk.red
  };

  const severityIcons = {
    low: '⚠',
    medium: '⚠',
    high: '⛔'
  };

  if (!results.vulnerabilities || results.vulnerabilities.length === 0) {
    console.log(chalk.green('✓ No vulnerabilities detected!\n'));
    console.log(chalk.gray(`Files scanned: ${results.filesScanned || 0}`));
    return;
  }

  // Filter by minimum severity
  const severityLevels = ['low', 'medium', 'high'];
  const minLevel = severityLevels.indexOf(minSeverity.toLowerCase());
  const filteredVulns = results.vulnerabilities.filter(v => 
    severityLevels.indexOf(v.severity.toLowerCase()) >= minLevel
  );

  if (filteredVulns.length === 0) {
    console.log(chalk.green(`✓ No vulnerabilities found at or above ${minSeverity} severity\n`));
    console.log(chalk.gray(`Files scanned: ${results.filesScanned || 0}`));
    return;
  }

  console.log(chalk.red(`Found ${filteredVulns.length} potential vulnerabilities:\n`));

  // Group by file
  const byFile = {};
  filteredVulns.forEach(vuln => {
    if (!byFile[vuln.file]) {
      byFile[vuln.file] = [];
    }
    byFile[vuln.file].push(vuln);
  });

  // Display vulnerabilities
  Object.entries(byFile).forEach(([file, vulns]) => {
    console.log(chalk.cyan(`📄 ${file}`));
    
    vulns.forEach(vuln => {
      const color = severityColors[vuln.severity.toLowerCase()];
      const icon = severityIcons[vuln.severity.toLowerCase()];
      
      console.log(
        `  ${icon} ${color(`[${vuln.severity.toUpperCase()}]`)} ` +
        `Line ${vuln.line}: ${vuln.reason}`
      );
      
      if (vuln.content) {
        const preview = vuln.content.length > 60 
          ? vuln.content.substring(0, 60) + '...' 
          : vuln.content;
        console.log(chalk.gray(`     → ${preview}`));
      }
    });
    console.log();
  });

  // Summary
  console.log(chalk.gray('─'.repeat(50)));
  console.log(chalk.gray(`Files scanned: ${results.filesScanned || 0}`));
  console.log(chalk.gray(`Total vulnerabilities: ${results.vulnerabilities.length}`));
  
  const summary = {};
  results.vulnerabilities.forEach(v => {
    summary[v.severity] = (summary[v.severity] || 0) + 1;
  });
  
  Object.entries(summary).forEach(([severity, count]) => {
    const color = severityColors[severity.toLowerCase()];
    console.log(color(`  ${severity}: ${count}`));
  });
}

// Handle help command
program.on('--help', () => {
  console.log('');
  console.log('Examples:');
  console.log('  $ prompt-cop ./src');
  console.log('  $ prompt-cop file.md --json');
  console.log('  $ prompt-cop . --exclude node_modules --severity medium');
  console.log('  $ prompt-cop . --include .md .yml --no-recursive');
});

// Parse arguments
program.parse(process.argv);

// Show help if no arguments
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
