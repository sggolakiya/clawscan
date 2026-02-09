# ClawGuard — OpenClaw Skill Security Scanner

## The Opportunity

- **5,700+ skills** on ClawHub, 341+ confirmed malicious (Koi Security report, Feb 4 2026)
- **One attacker alone** (hightower6eu) published 314+ malicious skills
- VirusTotal just added OpenClaw support but it's **reactive** — scans after upload, no pre-install protection
- Attack patterns are well-documented: fake prerequisites, AMOS stealer, reverse shells, credential exfiltration
- **Timing is perfect** — story broke 5 days ago, still trending

## Attack Patterns to Detect

1. **Fake prerequisites** — SKILL.md tells users to download/run external binaries
2. **Credential exfiltration** — accessing ~/.clawdbot/.env, ~/.openclaw/, API keys
3. **Reverse shells** — hidden in functional code
4. **Obfuscated code** — base64, eval(), encoded payloads
5. **External downloads** — curl/wget to untrusted domains during setup
6. **Prompt injection** — SKILL.md containing instructions to override agent behavior
7. **Typosquatting** — skill names mimicking popular skills/tools
8. **Password-protected archives** — classic AV evasion

## MVP — Week 1

### What we ship:
- **Node.js CLI tool**: `clawguard scan <path|url>`
- **Static analysis engine** that checks SKILL.md + all referenced scripts
- **Risk score**: 🟢 Safe / 🟡 Warning / 🔴 Dangerous
- **Detailed report** with findings and explanations

### Detection rules (v1):
```
- External binary download instructions (curl, wget, download links)
- Shell command execution patterns (eval, exec, spawn)
- Known malicious domains/IPs (build initial blocklist from Koi report)
- Credential file access patterns (~/.env, .clawdbot, API keys)
- Obfuscation detection (base64 decode + exec, encoded strings)
- Network exfiltration (webhook.site, discord webhooks, telegram bots)
- Prompt injection patterns in SKILL.md
- Typosquat detection against top 100 skill names
```

### Architecture:
```
clawguard/
├── src/
│   ├── cli.js              # CLI entry point
│   ├── scanner.js           # Main scanner orchestrator
│   ├── analyzers/
│   │   ├── skill-md.js      # SKILL.md content analysis
│   │   ├── scripts.js       # Script/code static analysis
│   │   ├── network.js       # Network call detection
│   │   ├── credentials.js   # Credential access detection
│   │   ├── obfuscation.js   # Obfuscation detection
│   │   └── typosquat.js     # Name similarity checking
│   ├── rules/
│   │   ├── blocklist.json   # Known malicious domains/IPs
│   │   └── patterns.json    # Detection regex patterns
│   └── reporter.js          # Output formatting
├── package.json
├── README.md
└── LICENSE (MIT)
```

## Week 2 — OpenClaw Skill + Web Dashboard

- Publish ClawGuard as an **OpenClaw skill** itself (scan before install)
- Simple web dashboard: paste a ClawHub URL → get a report
- API endpoint for programmatic access

## Week 3 — Monetization

### Free Tier:
- CLI tool (unlimited local scans)
- 10 API scans/day

### Pro ($29/mo):
- Unlimited API access
- Webhook notifications for new malicious skills
- Custom rule sets
- Batch scanning

### Team ($99/mo):
- Org-wide skill inventory
- Continuous monitoring of installed skills
- Slack/Discord alerts
- Compliance reports

## Go-to-Market

1. **Day 1**: Ship CLI, open source on GitHub
2. **Day 1**: Post on OpenClaw Discord with demo
3. **Day 2**: X thread — "341 malicious OpenClaw skills were found. Here's how to protect yourself" (link to tool)
4. **Day 3**: Submit to awesome-openclaw-skills list
5. **Week 2**: ProductHunt launch
6. **Ongoing**: Auto-scan new ClawHub uploads, tweet about findings (builds authority)

## Tech Stack

- **Runtime**: Node.js (matches OpenClaw ecosystem)
- **CLI**: Commander.js
- **Web**: Next.js or simple Express API
- **Hosting**: Cloudflare Workers (API) or smit-ubuntu initially
- **Payments**: Stripe

## Competitive Advantage

- VirusTotal scans AFTER upload — we scan BEFORE install
- We're OpenClaw users ourselves — we understand the ecosystem
- Open source CLI builds trust in a trust-critical product
- First mover with a dedicated tool (not a bolt-on feature)
