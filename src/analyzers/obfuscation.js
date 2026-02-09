import { readFile } from 'fs/promises';
import { glob } from 'glob';
import { relative } from 'path';
import patterns from '../rules/patterns.json' with { type: 'json' };

const SCAN_PATTERNS = ['**/*.js', '**/*.mjs', '**/*.cjs', '**/*.py', '**/*.sh', '**/*.bash', '**/*.rb'];
const MAX_FILE_SIZE = 1024 * 1024;

const RULES = patterns.obfuscation;

export async function analyzeObfuscation(skillPath) {
  const findings = [];

  let files = [];
  for (const pattern of SCAN_PATTERNS) {
    const matched = await glob(pattern, {
      cwd: skillPath,
      absolute: true,
      nodir: true,
      ignore: ['**/node_modules/**', '**/.git/**']
    });
    files.push(...matched);
  }
  files = [...new Set(files)];

  for (const filePath of files) {
    const relPath = relative(skillPath, filePath);
    let content;
    try {
      const { size } = await import('fs').then(fs => fs.promises.stat(filePath));
      if (size > MAX_FILE_SIZE) continue;
      content = await readFile(filePath, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');

    // Apply pattern rules
    for (const [ruleId, rule] of Object.entries(RULES)) {
      const regex = new RegExp(rule.pattern, 'gi');
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(regex);
        if (match) {
          findings.push({
            analyzer: 'obfuscation',
            severity: rule.severity,
            file: relPath,
            line: i + 1,
            message: rule.description,
            match: match[0].substring(0, 120),
            ruleId
          });
        }
      }
    }

    // Detect minified/packed code (very long lines)
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > 500 && !relPath.endsWith('.json')) {
        findings.push({
          analyzer: 'obfuscation',
          severity: 'warning',
          file: relPath,
          line: i + 1,
          message: `Extremely long line (${lines[i].length} chars) — possible minified/obfuscated code`,
          ruleId: 'longLine'
        });
        break; // Only report once per file
      }
    }

    // Detect variable name obfuscation (many single-char or _0x vars)
    const obfVars = content.match(/\b_0x[a-f0-9]+\b/g);
    if (obfVars && obfVars.length > 3) {
      findings.push({
        analyzer: 'obfuscation',
        severity: 'critical',
        file: relPath,
        line: null,
        message: `JavaScript obfuscator detected — ${obfVars.length} obfuscated variable names (_0x pattern)`,
        ruleId: 'jsObfuscator'
      });
    }

    // Detect common obfuscation tools signatures
    const obfSignatures = [
      { pattern: /javascript-obfuscator/i, name: 'javascript-obfuscator' },
      { pattern: /JSFuck/i, name: 'JSFuck' },
      { pattern: /jjencode/i, name: 'JJEncode' },
      { pattern: /aaencode/i, name: 'AAEncode' },
      { pattern: /pyarmor/i, name: 'PyArmor' },
      { pattern: /pyobfuscate/i, name: 'PyObfuscate' },
    ];

    for (const sig of obfSignatures) {
      if (sig.pattern.test(content)) {
        findings.push({
          analyzer: 'obfuscation',
          severity: 'critical',
          file: relPath,
          line: null,
          message: `Code obfuscation tool signature detected: ${sig.name}`,
          ruleId: 'obfuscationTool'
        });
      }
    }
  }

  return findings;
}
