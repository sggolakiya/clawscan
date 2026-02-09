# ClawScan Roadmap

## v1.0 ✅ (shipped Feb 9 2026)
- 6 static analyzers (SKILL.md, scripts, network, credentials, obfuscation, typosquat)
- Combination-based scoring
- CLI with colored output + JSON mode
- URL scanning support
- npm published, landing page live

## v2.0 — Anti-Evasion & AI Analysis

### LLM-Powered Code Review
- Feed skill code to an LLM, ask "what does this actually do from a security perspective?"
- Similar to VirusTotal's Code Insight (Gemini) but as a local CLI
- Catches intent-based attacks that regex can't see
- Model options: local (Ollama) or API (OpenAI/Anthropic)

### String Reconstruction Detection
- Detect `"web" + "hook" + ".site"` patterns
- Track variable assignments that build suspicious strings
- Flag excessive string concatenation resolving to known-bad patterns

### Dynamic Analysis (Sandbox)
- Run skill setup scripts in an isolated container
- Monitor: network calls, file access, process spawning
- Compare declared behavior (SKILL.md) vs actual behavior
- Docker-based, optional flag: `clawscan scan --dynamic ./skill`

### Publisher Reputation
- Check ClawHub publisher: account age, number of skills, report history
- Flag brand-new accounts publishing many skills (hightower6eu pattern)
- Cross-reference with known malicious publisher list

### Community Threat Database
- API endpoint to submit/query skill hashes and reports
- Users can flag skills, building collective intelligence
- Feeds into scoring: "3 users reported this skill"

### Advanced Evasion Detection
- ROT13/custom encoding detection
- Unicode lookalike character detection in URLs
- Polyglot file detection (shell in image metadata, etc.)
- Delayed execution patterns (setTimeout, cron-based triggers)
- External payload fetch detection (clean script that downloads real payload)

## v3.0 — Platform

### Web Dashboard
- Paste a ClawHub URL → get a report
- Browse all scanned skills
- Publisher profiles and trust scores

### API
- `POST /scan` with skill zip → JSON report
- Webhook notifications for new threats
- CI/CD integration (GitHub Actions)

### Pricing
- Free: CLI (unlimited) + 10 API scans/day
- Pro ($29/mo): unlimited API, webhooks, custom rules
- Team ($99/mo): org inventory, continuous monitoring, Slack alerts
