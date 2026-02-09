import { readFile, writeFile, mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import patterns from '../rules/patterns.json' with { type: 'json' };
import { analyzeScripts } from './scripts.js';
import { analyzeNetwork } from './network.js';
import { analyzeCredentials } from './credentials.js';
import { analyzeObfuscation } from './obfuscation.js';

const RULES = patterns.skillMd;

/**
 * Extract fenced code blocks from markdown and analyze them as scripts
 */
async function analyzeCodeBlocks(content, findings) {
  const codeBlockRegex = /```[^\n]*\n([\s\S]*?)```/g;
  let match;
  const blocks = [];
  
  while ((match = codeBlockRegex.exec(content)) !== null) {
    const fencedBlock = match[0];
    const code = match[1];
    const openingFenceOffset = fencedBlock.indexOf('\n') + 1;
    const codeStartOffset = match.index + openingFenceOffset;
    const startLine = content.slice(0, codeStartOffset).split('\n').length;
    blocks.push({ code, startLine });
  }
  
  if (blocks.length === 0) return;

  // Write code blocks to temp files and scan them
  const tmpDir = await mkdtemp(join(tmpdir(), 'clawscan-codeblocks-'));
  
  try {
    for (let i = 0; i < blocks.length; i++) {
      const blockPath = join(tmpDir, `block_${i}.sh`);
      await writeFile(blockPath, blocks[i].code);
    }
    
    // Run all analyzers on the extracted code blocks
    const analyzers = [
      { fn: analyzeScripts, label: 'scripts' },
      { fn: analyzeNetwork, label: 'network' },
      { fn: analyzeCredentials, label: 'credentials' },
      { fn: analyzeObfuscation, label: 'obfuscation' },
    ];
    
    for (const { fn, label } of analyzers) {
      try {
        const blockFindings = await fn(tmpDir);
        for (const f of blockFindings) {
          const blockIndexMatch = f.file?.match(/^block_(\d+)\.sh$/);
          const blockIndex = blockIndexMatch ? Number(blockIndexMatch[1]) : null;
          const blockMeta = blockIndex !== null ? blocks[blockIndex] : null;
          // Map back to SKILL.md context
          f.file = 'SKILL.md';
          if (blockMeta && typeof f.line === 'number') {
            f.line = blockMeta.startLine + f.line - 1;
          } else {
            f.line = null;
          }
          f.message = `[In code block] ${f.message}`;
          findings.push(f);
        }
      } catch {}
    }
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

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

  // Extract and analyze code blocks inside SKILL.md
  await analyzeCodeBlocks(content, findings);

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
