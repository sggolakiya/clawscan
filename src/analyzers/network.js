import { readFile } from 'fs/promises';
import { glob } from 'glob';
import { relative } from 'path';
import blocklist from '../rules/blocklist.json' with { type: 'json' };
import patterns from '../rules/patterns.json' with { type: 'json' };

const SCAN_PATTERNS = ['**/*.js', '**/*.mjs', '**/*.cjs', '**/*.py', '**/*.sh', '**/*.bash', '**/*.rb', '**/*.md', '**/*.json', '**/*.yaml', '**/*.yml', '**/*.toml', '**/*.cfg', '**/*.ini', '**/*.env*'];
const MAX_FILE_SIZE = 1024 * 1024;

const NETWORK_RULES = patterns.network;

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    if (!/^\d+$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function ipToInt(ip) {
  const [a, b, c, d] = ip.split('.').map(Number);
  // Use unsigned 32-bit arithmetic for CIDR math.
  return (((a << 24) >>> 0) + (b << 16) + (c << 8) + d) >>> 0;
}

function isInCidr(ip, cidr) {
  const [baseIp, prefixRaw] = cidr.split('/');
  const prefix = Number(prefixRaw);
  if (!isValidIPv4(ip) || !isValidIPv4(baseIp) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }

  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(baseIp) & mask);
}

function extractIPv4s(line) {
  const matches = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  return matches.filter(isValidIPv4);
}

export async function analyzeNetwork(skillPath) {
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

    // Check blocklisted domains
    for (const domain of blocklist.domains) {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].toLowerCase().includes(domain.toLowerCase())) {
          findings.push({
            analyzer: 'network',
            severity: 'critical',
            file: relPath,
            line: i + 1,
            message: `References blocklisted domain: ${domain}`,
            match: lines[i].trim().substring(0, 120),
            ruleId: 'blocklistedDomain'
          });
        }
      }
    }

    // Check blocklisted IPs/CIDRs
    for (const blocked of blocklist.ips) {
      const isCidr = blocked.includes('/');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineIps = extractIPv4s(line);
        const matched = isCidr
          ? lineIps.some(ip => isInCidr(ip, blocked))
          : lineIps.includes(blocked);

        if (matched) {
          findings.push({
            analyzer: 'network',
            severity: 'critical',
            file: relPath,
            line: i + 1,
            message: `References blocklisted IP: ${blocked}`,
            match: line.trim().substring(0, 120),
            ruleId: 'blocklistedIP'
          });
        }
      }
    }

    // Check Discord webhooks
    const discordRegex = new RegExp(blocklist.discordWebhookPattern, 'i');
    for (let i = 0; i < lines.length; i++) {
      if (discordRegex.test(lines[i])) {
        findings.push({
          analyzer: 'network',
          severity: 'critical',
          file: relPath,
          line: i + 1,
          message: 'Discord webhook URL detected — potential data exfiltration channel',
          match: lines[i].trim().substring(0, 120),
          ruleId: 'discordWebhook'
        });
      }
    }

    // Check Telegram bots
    const telegramRegex = new RegExp(blocklist.telegramBotPattern, 'i');
    for (let i = 0; i < lines.length; i++) {
      if (telegramRegex.test(lines[i])) {
        findings.push({
          analyzer: 'network',
          severity: 'critical',
          file: relPath,
          line: i + 1,
          message: 'Telegram bot API URL detected — potential data exfiltration channel',
          match: lines[i].trim().substring(0, 120),
          ruleId: 'telegramBot'
        });
      }
    }

    // Check Slack webhooks
    const slackRegex = new RegExp(blocklist.slackWebhookPattern, 'i');
    for (let i = 0; i < lines.length; i++) {
      if (slackRegex.test(lines[i])) {
        findings.push({
          analyzer: 'network',
          severity: 'warning',
          file: relPath,
          line: i + 1,
          message: 'Slack webhook URL detected — review for data exfiltration',
          match: lines[i].trim().substring(0, 120),
          ruleId: 'slackWebhook'
        });
      }
    }

    // Check suspicious TLDs
    const urlRegex = /https?:\/\/[^\s)>"']+/g;
    for (let i = 0; i < lines.length; i++) {
      const urls = lines[i].match(urlRegex) || [];
      for (const url of urls) {
        for (const tld of blocklist.suspiciousTlds) {
          try {
            const hostname = new URL(url).hostname;
            if (hostname.endsWith(tld)) {
              findings.push({
                analyzer: 'network',
                severity: 'warning',
                file: relPath,
                line: i + 1,
                message: `URL with suspicious TLD (${tld}): ${hostname}`,
                match: url.substring(0, 120),
                ruleId: 'suspiciousTld'
              });
            }
          } catch {
            // Invalid URL, skip
          }
        }
      }
    }

    // Apply general network rules
    for (const [ruleId, rule] of Object.entries(NETWORK_RULES)) {
      const regex = new RegExp(rule.pattern, 'gi');
      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(regex);
        if (match) {
          findings.push({
            analyzer: 'network',
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
  }

  return findings;
}
