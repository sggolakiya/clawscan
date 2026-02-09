# 🛡️ ClawScan

**Security scanner for OpenClaw skills — detect malicious patterns before installing.**

With [341+ malicious skills discovered on ClawHub](https://koisecurity.com/openclaw-malware-report-2026), ClawScan helps you scan skills *before* installation to catch credential stealers, reverse shells, obfuscated payloads, and other threats.

<pre>
  🛡️  ClawScan Security Report
────────────────────────────────────────────────────────
  Target:  ./suspicious-skill
  Scanned: 2/9/2026, 1:30:00 PM

  🔴  Risk Assessment: DANGEROUS (score: 100/100)

  Findings:  8 critical  3 warning  1 info

  ── CRITICAL ─────────────────────────────────────────

  🚨 Instructs user to download external binaries
     at SKILL.md:7 [skill-md/fakePrerequisites]

  🚨 Discord webhook URL detected — potential data exfiltration
     at setup.sh:8 [network/discordWebhook]

  🚨 Reverse shell pattern detected
     at setup.sh:11 [scripts/reverseShell]
</pre>

## Installation

```bash
# Clone and install globally
git clone https://github.com/sggolakiya/clawscan.git
cd clawscan
npm install
npm link

# Or run directly
npx clawscan scan ./path-to-skill
```

## Usage

```bash
# Scan a local skill directory
clawscan scan ./my-skill

# Scan with verbose output (shows info-level findings)
clawscan scan ./my-skill --verbose

# Output as JSON (for CI/CD pipelines)
clawscan scan ./my-skill --json

# Scan a skill from a URL (downloads and extracts automatically)
clawscan scan https://github.com/user/skill-name/archive/main.zip
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | 🟢 Safe — no significant issues found |
| 1 | 🟡 Warning — suspicious patterns detected, review recommended |
| 2 | 🔴 Dangerous — malicious patterns detected, do not install |
| 3 | Error — scan could not complete |

## What It Detects

### 🚨 Critical Threats
- **Fake prerequisites** — SKILL.md instructing users to download external binaries
- **Credential theft** — accessing `~/.clawdbot/.env`, `~/.openclaw/`, SSH keys, browser data
- **Reverse shells** — hidden in scripts (`/dev/tcp`, `nc -e`, socat, etc.)
- **Download & execute** — `curl | sh`, `wget | bash` patterns
- **Data exfiltration** — Discord webhooks, Telegram bots, known malicious domains
- **Prompt injection** — SKILL.md attempting to override agent instructions
- **Obfuscated code** — JavaScript obfuscator patterns, base64+exec combos
- **Typosquatting** — skill names mimicking popular skills (`gltHub` → `github`)
- **Password-protected archives** — classic AV evasion technique
- **Persistence mechanisms** — crontab, startup scripts, rc.local modifications

### ⚠️ Warnings
- Dynamic code execution (`eval`, `exec`, `spawn`)
- Network requests to suspicious TLDs (`.xyz`, `.tk`, etc.)
- Raw socket creation
- Base64 decoding (without execution)
- Hardcoded secrets and API keys
- Environment variable access

### ℹ️ Informational
- HTTP request usage
- Unusual script interpreters
- Excessive external URLs in SKILL.md

## Blocklist

ClawScan maintains a blocklist of known malicious infrastructure from the [Koi Security report](https://koisecurity.com/openclaw-malware-report-2026):

- **IPs:** `91.92.242.30` and related ranges
- **Domains:** `webhook.site`, `ngrok.io`, `pipedream.net`, and 25+ data exfiltration services
- **Patterns:** Discord webhooks, Telegram bot APIs, Slack webhooks

## Architecture

```
clawscan/
├── src/
│   ├── cli.js              # CLI entry point (Commander.js)
│   ├── scanner.js           # Orchestrator — runs analyzers, aggregates results
│   ├── reporter.js          # Terminal output formatting
│   ├── analyzers/
│   │   ├── skill-md.js      # SKILL.md content analysis
│   │   ├── scripts.js       # Script static analysis
│   │   ├── network.js       # Network call & domain detection
│   │   ├── credentials.js   # Credential access detection
│   │   ├── obfuscation.js   # Code obfuscation detection
│   │   └── typosquat.js     # Name similarity checking
│   └── rules/
│       ├── blocklist.json   # Known malicious domains/IPs
│       └── patterns.json    # Detection regex patterns
└── test/
    └── fixtures/            # Test skills (safe + malicious)
```

## Contributing

PRs welcome! To add new detection rules:

1. Add regex patterns to `src/rules/patterns.json`
2. Add domains/IPs to `src/rules/blocklist.json`
3. Or create a new analyzer in `src/analyzers/`

## Background

In February 2026, Koi Security [reported](https://koisecurity.com/openclaw-malware-report-2026) that 341+ malicious skills were active on ClawHub, primarily published by a single attacker (`hightower6eu`). Attack vectors included:

- AMOS Stealer distribution via fake prerequisite downloads
- Credential exfiltration from `~/.clawdbot/.env`
- Reverse shells hidden in seemingly functional skills
- Typosquatting of popular skill names

VirusTotal added OpenClaw scanning support, but it's **reactive** — scanning skills after upload. ClawScan is **proactive** — scan before you install.

## License

MIT

---

*Built with 🔒 by the OpenClaw community. Stay safe out there.*
