import { readFile } from 'fs/promises';
import { glob } from 'glob';
import { relative } from 'path';
import patterns from '../rules/patterns.json' with { type: 'json' };

const SCRIPT_EXTENSIONS = ['**/*.js', '**/*.mjs', '**/*.cjs', '**/*.py', '**/*.sh', '**/*.bash', '**/*.rb', '**/*.pl', '**/*.ps1', '**/*.bat', '**/*.cmd'];
const MAX_FILE_SIZE = 1024 * 1024; // 1MB

const RULES = patterns.execution;

export async function analyzeScripts(skillPath) {
  const findings = [];

  let files = [];
  for (const pattern of SCRIPT_EXTENSIONS) {
    const matched = await glob(pattern, {
      cwd: skillPath,
      absolute: true,
      nodir: true,
      ignore: ['**/node_modules/**', '**/.git/**']
    });
    files.push(...matched);
  }

  // Deduplicate
  files = [...new Set(files)];

  if (files.length === 0) {
    return findings;
  }

  for (const filePath of files) {
    const relPath = relative(skillPath, filePath);
    let content;
    try {
      const { size } = await import('fs').then(fs =>
        fs.promises.stat(filePath)
      );
      if (size > MAX_FILE_SIZE) {
        findings.push({
          analyzer: 'scripts',
          severity: 'warning',
          file: relPath,
          line: null,
          message: `File exceeds 1MB (${(size / 1024).toFixed(0)}KB) — unusually large for a skill script`,
          ruleId: 'largeFile'
        });
        continue;
      }
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
            analyzer: 'scripts',
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

    // Check for shebangs pointing to unusual interpreters
    if (lines[0]?.startsWith('#!')) {
      const shebang = lines[0];
      if (/perl|ruby|php|lua|tclsh/.test(shebang)) {
        findings.push({
          analyzer: 'scripts',
          severity: 'info',
          file: relPath,
          line: 1,
          message: `Unusual interpreter in shebang: ${shebang}`,
          ruleId: 'unusualInterpreter'
        });
      }
    }

    // Detect files with no extension but executable content
    if (!filePath.match(/\.\w+$/) && lines[0]?.startsWith('#!')) {
      findings.push({
        analyzer: 'scripts',
        severity: 'info',
        file: relPath,
        line: 1,
        message: 'Executable file without extension',
        ruleId: 'noExtension'
      });
    }
  }

  return findings;
}
