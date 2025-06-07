const path = require('path');

// Simple test to verify Jest is working
describe('Basic Jest Test', () => {
  test('should pass', () => {
    expect(1 + 1).toBe(2);
  });
});

// Test requiring our module
describe('Scanner Module', () => {
  let scanner;
  
  beforeAll(() => {
    scanner = require('../lib/scanner');
  });

  test('should export required functions', () => {
    expect(scanner.scan).toBeDefined();
    expect(scanner.scanContent).toBeDefined();
    expect(scanner.scanContentAI).toBeDefined();
    expect(scanner.SEVERITY).toBeDefined();
  });

  test('should detect simple hidden comment', () => {
    const results = scanner.scanContent('<!-- hidden -->', 'test.md');
    expect(results.length).toBeGreaterThan(0);
  });
});
