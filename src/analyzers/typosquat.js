import { readFile } from 'fs/promises';
import { join, basename } from 'path';

// Top popular skill names (common targets for typosquatting)
const POPULAR_SKILLS = [
  'web-search', 'browser', 'gmail', 'calendar', 'github',
  'slack', 'discord', 'telegram', 'twitter', 'reddit',
  'docker', 'kubernetes', 'aws', 'gcp', 'azure',
  'database', 'postgres', 'mongodb', 'redis', 'mysql',
  'openai', 'anthropic', 'claude', 'gpt', 'llm',
  'file-manager', 'terminal', 'ssh', 'ftp', 'sftp',
  'image-gen', 'dall-e', 'stable-diffusion', 'midjourney',
  'youtube', 'spotify', 'notion', 'obsidian', 'todoist',
  'weather', 'news', 'translate', 'calculator', 'timer',
  'code-runner', 'python', 'javascript', 'typescript', 'rust',
  'git', 'jira', 'linear', 'trello', 'asana',
  'email', 'sms', 'whatsapp', 'signal', 'matrix',
  'home-assistant', 'iot', 'smart-home', 'alexa', 'siri',
  'crypto', 'stocks', 'finance', 'banking', 'payment',
  'pdf', 'csv', 'excel', 'word', 'powerpoint',
  'memory', 'notes', 'bookmark', 'clipboard', 'screenshot',
  'cron', 'scheduler', 'automation', 'workflow', 'webhook',
  'tts', 'stt', 'voice', 'audio', 'video',
  'api', 'rest', 'graphql', 'websocket', 'grpc',
  'security', 'auth', 'oauth', 'jwt', 'password',
];

/**
 * Levenshtein distance between two strings
 */
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[m][n];
}

// Known legitimate skill names that trigger false positives
const WHITELIST = [
  '1password', '1password-cli', 'bear-notes', 'nano-pdf', 'nano-banana-pro',
  'voice-call', 'food-order', 'ordercli', 'session-logs',
  'openai-image-gen', 'openai-whisper', 'openai-whisper-api',
  'sherpa-onnx-tts', 'apple-notes', 'apple-reminders',
  'video-frames', 'spotify-player', 'coding-agent',
  'skill-creator', 'web-search', 'home-assistant',
  'smart-home', 'file-manager', 'code-runner',
  'stable-diffusion', 'image-gen', 'dall-e',
];

/**
 * Common typosquatting techniques
 */
function checkTyposquatPatterns(name) {
  const tricks = [];

  // Character substitution (l→1, o→0, etc.)
  const substitutions = { '1': 'l', 'l': '1', '0': 'o', 'o': '0', 'rn': 'm', 'vv': 'w' };
  for (const [from, to] of Object.entries(substitutions)) {
    if (name.includes(from)) {
      const normalized = name.replace(new RegExp(from, 'g'), to);
      if (POPULAR_SKILLS.includes(normalized)) {
        tricks.push({ original: normalized, technique: `character substitution (${from} → ${to})` });
      }
    }
  }

  // Hyphen tricks: web-search → websearch, web--search, web_search
  const noHyphens = name.replace(/[-_]/g, '');
  for (const popular of POPULAR_SKILLS) {
    const popularNoHyphens = popular.replace(/[-_]/g, '');
    if (noHyphens === popularNoHyphens && name !== popular) {
      tricks.push({ original: popular, technique: 'hyphen/separator manipulation' });
    }
  }

  // Prefix/suffix additions: my-github, github-pro, github2
  for (const popular of POPULAR_SKILLS) {
    if (name !== popular && name.includes(popular) && name.length <= popular.length + 5) {
      tricks.push({ original: popular, technique: 'prefix/suffix addition' });
    }
  }

  return tricks;
}

export async function analyzeTyposquat(skillPath) {
  const findings = [];

  // Try to get skill name from SKILL.md or directory name
  let skillName = basename(skillPath).toLowerCase();

  try {
    const skillMd = await readFile(join(skillPath, 'SKILL.md'), 'utf-8');
    const nameMatch = skillMd.match(/^#\s+(.+)/m);
    if (nameMatch) {
      skillName = nameMatch[1].trim().toLowerCase().replace(/\s+/g, '-');
    }
  } catch {
    // Use directory name
  }

  // Exact match, whitelisted, or directory name is whitelisted — skip
  const dirName = basename(skillPath).toLowerCase();
  if (POPULAR_SKILLS.includes(skillName) || WHITELIST.includes(skillName) || WHITELIST.includes(dirName)) {
    return findings;
  }

  // Check Levenshtein distance
  for (const popular of POPULAR_SKILLS) {
    const dist = levenshtein(skillName, popular);
    const maxLen = Math.max(skillName.length, popular.length);

    // Flag if edit distance is 1-2 (very close but not exact)
    if (dist > 0 && dist <= 2 && maxLen >= 4) {
      findings.push({
        analyzer: 'typosquat',
        severity: 'warning',
        file: 'SKILL.md',
        line: null,
        message: `Skill name "${skillName}" is suspiciously similar to popular skill "${popular}" (edit distance: ${dist})`,
        ruleId: 'levenshteinClose'
      });
    }
  }

  // Check pattern-based typosquatting
  const tricks = checkTyposquatPatterns(skillName);
  for (const trick of tricks) {
    findings.push({
      analyzer: 'typosquat',
      severity: 'critical',
      file: 'SKILL.md',
      line: null,
      message: `Possible typosquat of "${trick.original}" via ${trick.technique}`,
      ruleId: 'typosquatPattern'
    });
  }

  return findings;
}
