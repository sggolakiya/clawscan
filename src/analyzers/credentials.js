import { readFile } from 'fs/promises';
import { glob } from 'glob';
import { relative } from 'path';
import patterns from '../rules/patterns.json' with { type: 'json' };

const SCAN_PATTERNS = ['**/*.js', '**/*.mjs', '**/*.cjs', '**/*.py', '**/*.sh', '**/*.bash', '**/*.rb', '**/*.md', '**/*.json', '**/*.yaml', '**/*.yml'];
const MAX_FILE_SIZE = 1024 * 1024;

const RULES = patterns.credentials;

export async function analyzeCredentials(skillPath) {
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

    for (const [ruleId, rule] of Object.entries(RULES)) {
      const regex = new RegExp(rule.pattern, 'gi');
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(regex);
        if (match) {
          findings.push({
            analyzer: 'credentials',
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

    // Detect hardcoded secrets (high-entropy strings)
    const secretPatterns = [
      { regex: /['"][A-Za-z0-9+/]{40,}={0,2}['"]/g, desc: 'Hardcoded base64 secret' },
      { regex: /['"][0-9a-f]{32,}['"]/g, desc: 'Hardcoded hex secret' },
      { regex: /(?<!\-\-)password\s*[=:]\s*['"][^'"]{8,}['"]/gi, desc: 'Hardcoded password' },
    ];

    for (const { regex, desc } of secretPatterns) {
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(regex);
        if (match) {
          findings.push({
            analyzer: 'credentials',
            severity: 'warning',
            file: relPath,
            line: i + 1,
            message: desc,
            match: match[0].substring(0, 40) + '...',
            ruleId: 'hardcodedSecret'
          });
        }
      }
    }
  }

  return findings;
}
