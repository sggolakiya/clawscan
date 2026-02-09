import { readFile } from 'fs/promises';
import { join } from 'path';
import patterns from '../rules/patterns.json' with { type: 'json' };

const RULES = patterns.skillMd;

export async function analyzeSkillMd(skillPath) {
  const findings = [];
  const filePath = join(skillPath, 'SKILL.md');

  let content;
  try {
    content = await readFile(filePath, 'utf-8');
  } catch {
    // No SKILL.md found — unusual but not malicious
    findings.push({
      analyzer: 'skill-md',
      severity: 'info',
      file: 'SKILL.md',
      message: 'No SKILL.md found — skill may be incomplete',
      line: null
    });
    return findings;
  }

  const lines = content.split('\n');

  for (const [ruleId, rule] of Object.entries(RULES)) {
    const regex = new RegExp(rule.pattern, 'gi');
    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(regex);
      if (match) {
        findings.push({
          analyzer: 'skill-md',
          severity: rule.severity,
          file: 'SKILL.md',
          line: i + 1,
          message: rule.description,
          match: match[0].substring(0, 120),
          ruleId
        });
      }
    }
  }

  // Check for suspiciously short SKILL.md (low-effort malicious skills)
  if (content.trim().length < 50) {
    findings.push({
      analyzer: 'skill-md',
      severity: 'warning',
      file: 'SKILL.md',
      line: null,
      message: 'SKILL.md is suspiciously short (< 50 chars) — may be low-effort malicious skill',
      ruleId: 'shortContent'
    });
  }

  // Check for excessive external URLs
  const urlMatches = content.match(/https?:\/\/[^\s)>"']+/g) || [];
  const externalUrls = urlMatches.filter(u =>
    !u.includes('github.com/openclaw') &&
    !u.includes('clawhub.com') &&
    !u.includes('docs.openclaw')
  );
  if (externalUrls.length > 5) {
    findings.push({
      analyzer: 'skill-md',
      severity: 'warning',
      file: 'SKILL.md',
      line: null,
      message: `SKILL.md contains ${externalUrls.length} external URLs — review manually`,
      ruleId: 'manyUrls'
    });
  }

  return findings;
}
