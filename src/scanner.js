import { stat, access, mkdtemp, rm, readFile } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { execSync } from 'child_process';

import { analyzeSkillMd } from './analyzers/skill-md.js';
import { analyzeScripts } from './analyzers/scripts.js';
import { analyzeNetwork } from './analyzers/network.js';
import { analyzeCredentials } from './analyzers/credentials.js';
import { analyzeObfuscation } from './analyzers/obfuscation.js';
import { analyzeTyposquat } from './analyzers/typosquat.js';
import { analyzePromptInjection } from './analyzers/prompt-injection.js';

const ANALYZERS = [
  { name: 'SKILL.md Analysis', fn: analyzeSkillMd },
  { name: 'Script Analysis', fn: analyzeScripts },
  { name: 'Network Analysis', fn: analyzeNetwork },
  { name: 'Credential Analysis', fn: analyzeCredentials },
  { name: 'Obfuscation Detection', fn: analyzeObfuscation },
  { name: 'Typosquat Detection', fn: analyzeTyposquat },
  { name: 'Prompt Injection Detection', fn: analyzePromptInjection },
];

/**
 * Detect if the skill describes itself as a CLI wrapper/tool in SKILL.md
 */
function detectCliToolContext(findings) {
  // If SKILL.md mentions CLI tool patterns, the skill is a legitimate CLI wrapper
  // We check this by looking at the skill-md analyzer — if it found SKILL.md content
  // We'll check in the scan function where we have access to the skill path
  return false;
}

/**
 * Detect dangerous combinations of findings
 * Returns bonus score for combinations that indicate truly malicious behavior
 */
function detectDangerousCombinations(findings) {
  const ruleIds = new Set(findings.map(f => f.ruleId));
  const analyzers = new Set(findings.map(f => f.analyzer));
  let comboScore = 0;

  const hasExec = ruleIds.has('evalExec') || ruleIds.has('shellExecution');
  const hasDownloadExec = ruleIds.has('downloadExecute');
  const hasReverseShell = ruleIds.has('reverseShell');
  const hasCronPersist = ruleIds.has('cronPersistence');
  const hasBlocklistedDomain = ruleIds.has('blocklistedDomain');
  const hasBlocklistedIP = ruleIds.has('blocklistedIP');
  const hasWebhook = ruleIds.has('discordWebhook') || ruleIds.has('telegramBot') || ruleIds.has('slackWebhook');
  const hasCredAccess = ruleIds.has('sshKeyAccess') || ruleIds.has('browserData') || ruleIds.has('apiKeyPatterns');
  const hasEnvAccess = ruleIds.has('envFileAccess') || ruleIds.has('clawbotPaths');
  const hasObfuscation = ruleIds.has('jsObfuscator') || ruleIds.has('obfuscationTool') || ruleIds.has('longLine');
  const hasBase64 = ruleIds.has('base64Exec');
  const hasPromptInjection = ruleIds.has('promptInjection') || ruleIds.has('roleHijack') || 
    ruleIds.has('instructionOverride') || ruleIds.has('authoritySpoofing') || 
    ruleIds.has('steganoInstructions') || ruleIds.has('conversationManip');
  const hasInvisibleChars = ruleIds.has('invisibleChars');
  const hasHiddenComment = ruleIds.has('hiddenComment');
  const hasDataExfil = ruleIds.has('dataExfilPrompt');
  const hasPrivEsc = ruleIds.has('privEscalation');
  const hasFakePrereq = ruleIds.has('fakePrerequisites');
  const hasHiddenCmds = ruleIds.has('hiddenCommands');
  const hasExternalUrls = ruleIds.has('externalUrls');
  const hasNetwork = ruleIds.has('httpRequests') || ruleIds.has('rawSockets');

  // === VERY HIGH weight combinations (50+ each) ===

  // Credential theft + exfiltration channel
  if (hasCredAccess && (hasWebhook || hasBlocklistedDomain || hasBlocklistedIP)) {
    comboScore += 60;
  }

  // Download + execute remote code
  if (hasDownloadExec) comboScore += 50;

  // Reverse shell
  if (hasReverseShell) comboScore += 60;

  // Prompt injection
  if (hasPromptInjection) comboScore += 50;

  // Invisible characters (steganographic attack)
  if (hasInvisibleChars) comboScore += 40;

  // Hidden comment instructions
  if (hasHiddenComment) comboScore += 35;

  // Data exfiltration via prompt
  if (hasDataExfil) comboScore += 50;

  // Privilege escalation via prompt
  if (hasPrivEsc) comboScore += 40;

  // Prompt injection + data exfil = worst case scenario
  if (hasPromptInjection && hasDataExfil) comboScore += 20;

  // Hidden commands in markdown
  if (hasHiddenCmds) comboScore += 50;

  // === HIGH weight combinations (25-40 each) ===

  // Fake prerequisites pointing to external downloads
  if (hasFakePrereq && hasExternalUrls) comboScore += 40;
  else if (hasFakePrereq) comboScore += 25;

  // Blocklisted domains/IPs (inherently suspicious)
  if (hasBlocklistedDomain) comboScore += 30;
  if (hasBlocklistedIP) comboScore += 30;

  // Obfuscation + execution = hiding what you run
  if (hasObfuscation && hasExec) comboScore += 35;

  // Persistence mechanisms
  if (hasCronPersist) comboScore += 30;

  // Webhooks as exfil channels + env/cred access
  if (hasWebhook && hasEnvAccess) comboScore += 35;

  // === MEDIUM weight combinations (10-20 each) ===

  // Credential access + network (potential exfil without known-bad endpoint)
  if (hasCredAccess && hasNetwork && !hasWebhook && !hasBlocklistedDomain) {
    comboScore += 15;
  }

  // Obfuscation alone
  if (hasObfuscation && !hasExec) comboScore += 10;

  // Base64 decode + exec
  if (hasBase64 && hasExec) comboScore += 15;

  // Webhook alone (could be legitimate integration)
  if (hasWebhook && !hasCredAccess && !hasEnvAccess) comboScore += 10;

  return comboScore;
}

/**
 * Calculate overall risk score from findings with context-aware weighting
 */
function calculateRiskScore(findings, context = {}) {
  const { isCliTool } = context;

  // Base weights per individual finding — intentionally low for info/warning
  const weights = { critical: 10, warning: 2, info: 0 };
  let score = 0;

  // Individual finding base score
  for (const f of findings) {
    score += weights[f.severity] || 0;
  }

  // CLI tool context: reduce base score since exec/env are expected
  if (isCliTool) {
    score = Math.floor(score * 0.5);
  }

  // Combination-based scoring (the real signal)
  const comboScore = detectDangerousCombinations(findings);
  score += comboScore;

  // Normalize to 0-100
  score = Math.min(score, 100);

  if (score >= 50) return { score, level: 'dangerous', emoji: '🔴', label: 'DANGEROUS' };
  if (score >= 20) return { score, level: 'warning', emoji: '🟡', label: 'WARNING' };
  return { score, level: 'safe', emoji: '🟢', label: 'SAFE' };
}

/**
 * Check if a path is a ClawHub URL and download if so
 */
async function resolveTarget(target) {
  // Check if it's a URL
  if (target.startsWith('http://') || target.startsWith('https://')) {
    const tmpDir = await mkdtemp(join(tmpdir(), 'clawguard-'));

    try {
      // Try to download as zip
      const zipPath = join(tmpDir, 'skill.zip');

      try {
        execSync(`curl -fsSL -o "${zipPath}" "${target}"`, { timeout: 30000 });
      } catch {
        // Try appending /archive/main.zip for GitHub-style URLs
        const archiveUrl = target.replace(/\/?$/, '/archive/main.zip');
        execSync(`curl -fsSL -o "${zipPath}" "${archiveUrl}"`, { timeout: 30000 });
      }

      // Extract
      const extractDir = join(tmpDir, 'extracted');
      execSync(`mkdir -p "${extractDir}" && unzip -q -o "${zipPath}" -d "${extractDir}"`, { timeout: 30000 });

      // Find the actual skill directory (often nested one level)
      const { readdirSync, statSync } = await import('fs');
      const entries = readdirSync(extractDir);
      if (entries.length === 1 && statSync(join(extractDir, entries[0])).isDirectory()) {
        return { path: join(extractDir, entries[0]), tmpDir, isTemp: true };
      }

      return { path: extractDir, tmpDir, isTemp: true };
    } catch (err) {
      await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
      throw new Error(`Failed to download skill from URL: ${err.message}`);
    }
  }

  // Local path
  try {
    const s = await stat(target);
    if (!s.isDirectory()) {
      throw new Error(`"${target}" is not a directory`);
    }
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`Path not found: "${target}"`);
    }
    throw err;
  }

  return { path: target, isTemp: false };
}

/**
 * Main scan function
 */
export async function scan(target, options = {}) {
  const { path: skillPath, tmpDir, isTemp } = await resolveTarget(target);

  const results = {
    target: target,
    path: skillPath,
    timestamp: new Date().toISOString(),
    findings: [],
    analyzers: [],
  };

  try {
    for (const analyzer of ANALYZERS) {
      const startTime = Date.now();
      try {
        const findings = await analyzer.fn(skillPath);
        const elapsed = Date.now() - startTime;
        results.findings.push(...findings);
        results.analyzers.push({
          name: analyzer.name,
          findings: findings.length,
          elapsed,
          status: 'ok'
        });
      } catch (err) {
        results.analyzers.push({
          name: analyzer.name,
          findings: 0,
          elapsed: Date.now() - startTime,
          status: 'error',
          error: err.message
        });
      }
    }

    // Detect CLI tool context from SKILL.md
    let isCliTool = false;
    try {
      const skillMd = await readFile(join(skillPath, 'SKILL.md'), 'utf-8');
      const lowerMd = skillMd.toLowerCase();
      // CLI wrapper indicators: mentions CLI, command-line, wrapper, tool, exec, shell, terminal usage
      const cliIndicators = ['cli', 'command-line', 'command line', 'wrapper', 'terminal', 'shell command',
        'executes', 'runs command', 'run command', 'spawns', 'child_process', 'subprocess',
        'exec(', 'execsync', 'spawn(', 'tool that', 'tool for', 'curl', 'calls the'];
      const matchCount = cliIndicators.filter(ind => lowerMd.includes(ind)).length;
      if (matchCount >= 2) isCliTool = true;
    } catch { /* no SKILL.md */ }

    results.risk = calculateRiskScore(results.findings, { isCliTool });
    results.summary = {
      total: results.findings.length,
      critical: results.findings.filter(f => f.severity === 'critical').length,
      warning: results.findings.filter(f => f.severity === 'warning').length,
      info: results.findings.filter(f => f.severity === 'info').length,
    };

    return results;
  } finally {
    // Cleanup temp directory if we downloaded from URL
    if (isTemp && tmpDir) {
      await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  }
}
