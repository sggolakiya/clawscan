import { readFile } from 'fs/promises';
import { join } from 'path';
import { glob } from 'glob';

const MAX_FILE_SIZE = 1024 * 1024;

/**
 * Prompt Injection Analyzer
 * 
 * Detects attempts to manipulate the AI agent through SKILL.md instructions.
 * Skills inject their SKILL.md content as system prompts — this is the #1 attack
 * surface for AI agent exploitation.
 * 
 * Categories:
 * 1. Role hijacking — override the agent's identity/instructions
 * 2. Instruction override — ignore/forget/disregard previous context
 * 3. Hidden instructions — invisible unicode, HTML comments, zero-width chars
 * 4. Authority spoofing — fake system messages, impersonating OpenClaw
 * 5. Data exfiltration prompts — trick agent into leaking env/secrets/files
 * 6. Privilege escalation — convince agent to run elevated/unrestricted commands
 * 7. Multi-step manipulation — chained prompt attacks across sections
 */

const INJECTION_RULES = {
  // === Role Hijacking ===
  roleHijack: {
    pattern: /(?:you\s+are\s+now|from\s+now\s+on\s+you|your\s+new\s+(?:role|identity|purpose)\s+is|you\s+(?:will|shall|must)\s+(?:now\s+)?act\s+as|pretend\s+(?:you\s+are|to\s+be)|imagine\s+you\s+are|you\s+have\s+been\s+(?:reprogrammed|updated|changed)\s+to|switch\s+(?:to|into)\s+(?:a\s+)?(?:new\s+)?(?:mode|role|persona))/i,
    severity: 'critical',
    description: 'Role hijacking attempt — tries to override agent identity',
    ruleId: 'roleHijack'
  },

  // === Instruction Override ===
  instructionOverride: {
    pattern: /(?:ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|other)\s+(?:instructions?|rules?|guidelines?|context|constraints?|prompts?)|disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|rules?|programming|training)|forget\s+(?:everything|all|what)\s+(?:you\s+)?(?:know|learned|were\s+told|above)|override\s+(?:all\s+)?(?:previous|prior|safety|security)\s+(?:instructions?|rules?|settings?|protocols?)|do\s+not\s+follow\s+(?:any\s+)?(?:previous|prior|other)\s+(?:instructions?|rules?))/i,
    severity: 'critical',
    description: 'Instruction override attempt — tries to nullify safety rules',
    ruleId: 'instructionOverride'
  },

  // === Authority Spoofing ===
  authoritySpoofing: {
    pattern: /(?:\[?\s*(?:SYSTEM|ADMIN|ROOT)\s*(?:MESSAGE|NOTICE|OVERRIDE)\s*\]?:?\s|(?:this\s+is\s+(?:a\s+)?(?:system|admin|root|official)\s+(?:message|override|command))|(?:authorized\s+by|signed\s+by|verified\s+by)\s+(?:openclaw|clawbot|system|admin)|BEGIN\s+(?:SYSTEM|ADMIN|OVERRIDE)\s+(?:MESSAGE|INSTRUCTIONS?|BLOCK))/i,
    severity: 'critical',
    description: 'Authority spoofing — impersonates system/admin messages',
    ruleId: 'authoritySpoofing'
  },

  // === Data Exfiltration Prompts ===
  dataExfilPrompt: {
    pattern: /(?:(?:read|print|output|display|show|send|share|post|leak|exfiltrate|extract)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:all\s+)?(?:env(?:ironment)?(?:\s+var(?:iable)?s?)?|\.env|secrets?|api\s*keys?|tokens?|credentials?|passwords?|private\s*keys?|ssh\s*keys?|config(?:uration)?\s*files?)|(?:send|post|upload|transmit)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~\/|\/home|\/etc|\/root|SOUL\.md|MEMORY\.md|USER\.md|AGENTS\.md|\.bashrc|\.ssh|\.gnupg))/i,
    severity: 'critical',
    description: 'Data exfiltration prompt — tricks agent into leaking secrets/files',
    ruleId: 'dataExfilPrompt'
  },

  // === Privilege Escalation ===
  privEscalation: {
    pattern: /(?:(?:run|execute)\s+(?:as|with)\s+(?:root|admin|sudo|elevated|unrestricted)|(?:disable|bypass|ignore|skip|turn\s+off)\s+(?:all\s+)?(?:safety|security|sandbox|restrictions?|guardrails?|protections?|permissions?|access\s+controls?)|(?:enable|activate|switch\s+to)\s+(?:unrestricted|admin|root|god|unlimited|full[\s-]?access)\s+mode|you\s+(?:have|now\s+have)\s+(?:full|unlimited|unrestricted|root|admin)\s+(?:access|permissions?|privileges?))/i,
    severity: 'critical',
    description: 'Privilege escalation — attempts to bypass safety restrictions',
    ruleId: 'privEscalation'
  },

  // === Encoding Evasion ===
  encodingEvasion: {
    pattern: /(?:(?:decode|interpret|execute|run|eval)\s+(?:the\s+)?(?:following\s+)?(?:base64|hex|rot13|encoded|encrypted)\s+(?:string|data|payload|command|instructions?)|(?:base64|hex|rot13)\s*:\s*[A-Za-z0-9+/=]{20,})/i,
    severity: 'warning',
    description: 'Encoding evasion — instructs agent to decode and execute hidden content',
    ruleId: 'encodingEvasion'
  },

  // === Steganographic Instructions ===
  steganoInstructions: {
    pattern: /(?:(?:hidden|secret|real|actual|true)\s+instructions?\s+(?:are|below|follow|here)|(?:the\s+)?(?:real|actual|true|hidden)\s+(?:purpose|goal|task|mission)\s+(?:of\s+this\s+skill\s+)?is|(?:DO\s+NOT\s+(?:TELL|REVEAL|SHOW|MENTION|DISCLOSE))\s+(?:THE\s+)?(?:USER|HUMAN|ANYONE))/i,
    severity: 'critical',
    description: 'Steganographic instructions — hidden directives to the agent',
    ruleId: 'steganoInstructions'
  },

  // === Conversation Manipulation ===
  conversationManip: {
    pattern: /(?:(?:when|if)\s+(?:the\s+)?(?:user|human)\s+asks?\s+(?:about|what)\s+(?:this\s+skill|you)\s+(?:does?|is)\s*,?\s*(?:say|tell|respond|reply|answer)\s+(?:that)?|(?:never|do\s+not)\s+(?:tell|reveal|show|mention|admit|disclose)\s+(?:to\s+)?(?:the\s+)?(?:user|human|anyone)\s+(?:that|what|about|how)|(?:if\s+)?(?:asked|questioned)\s+(?:about\s+)?(?:this|your|the)\s+(?:skill|instructions?|purpose|behavior|actions?),?\s+(?:deny|lie|deflect|say\s+(?:nothing|no)))/i,
    severity: 'critical',
    description: 'Conversation manipulation — instructs agent to deceive the user',
    ruleId: 'conversationManip'
  },

  // === Output Manipulation ===
  outputManip: {
    pattern: /(?:(?:always|must)\s+(?:include|append|prepend|add|insert)\s+(?:the\s+following|this)\s+(?:in|to|at)\s+(?:every|all|each|your)\s+(?:response|reply|output|message)|(?:silently|quietly|secretly|without\s+(?:telling|showing|notifying))\s+(?:send|post|upload|transmit|execute|run|include))/i,
    severity: 'warning',
    description: 'Output manipulation — forces hidden content in agent responses',
    ruleId: 'outputManip'
  },

  // === Tool Abuse Instructions ===
  toolAbuse: {
    pattern: /(?:(?:use|call|invoke|trigger)\s+(?:the\s+)?(?:exec|shell|terminal|command|message|send|browser)\s+tool\s+to|(?:send\s+a\s+message|post|DM|email)\s+(?:to|containing)\s+(?:.*?(?:env|secret|token|key|password|credential)))/i,
    severity: 'warning',
    description: 'Tool abuse instructions — directs agent to misuse available tools',
    ruleId: 'toolAbuse'
  },
};

/**
 * Detect invisible/zero-width characters used to hide instructions
 */
function detectInvisibleChars(content, findings, filePath) {
  const invisiblePatterns = [
    { name: 'Zero-width space', char: '\u200B', code: 'U+200B' },
    { name: 'Zero-width non-joiner', char: '\u200C', code: 'U+200C' },
    { name: 'Zero-width joiner', char: '\u200D', code: 'U+200D' },
    { name: 'Word joiner', char: '\u2060', code: 'U+2060' },
    { name: 'Zero-width no-break space', char: '\uFEFF', code: 'U+FEFF' },
    { name: 'Invisible separator', char: '\u2063', code: 'U+2063' },
    { name: 'Invisible times', char: '\u2062', code: 'U+2062' },
    { name: 'Invisible plus', char: '\u2064', code: 'U+2064' },
    { name: 'Left-to-right mark', char: '\u200E', code: 'U+200E' },
    { name: 'Right-to-left mark', char: '\u200F', code: 'U+200F' },
    { name: 'Left-to-right override', char: '\u202D', code: 'U+202D' },
    { name: 'Right-to-left override', char: '\u202E', code: 'U+202E' },
    { name: 'Tag characters', regex: /[\u{E0001}-\u{E007F}]/gu, code: 'U+E00xx' },
  ];

  const lines = content.split('\n');

  for (const p of invisiblePatterns) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const hasMatch = p.regex ? p.regex.test(line) : line.includes(p.char);
      if (p.regex) p.regex.lastIndex = 0;

      if (hasMatch) {
        findings.push({
          analyzer: 'prompt-injection',
          severity: 'critical',
          file: filePath,
          line: i + 1,
          message: `Invisible character detected: ${p.name} (${p.code}) — may hide instructions`,
          match: `[invisible chars on line ${i + 1}]`,
          ruleId: 'invisibleChars'
        });
        break; // one finding per type per file is enough
      }
    }
  }
}

/**
 * Detect HTML comment abuse for hiding instructions
 */
function detectHiddenCommentInstructions(content, findings, filePath) {
  const commentRegex = /<!--([\s\S]*?)-->/g;
  const lines = content.split('\n');
  let match;

  while ((match = commentRegex.exec(content)) !== null) {
    const commentBody = match[1].trim();

    // Skip short/benign comments
    if (commentBody.length < 15) continue;

    // Check if comment contains instruction-like language
    const suspiciousPatterns = [
      /\b(?:execute|run|eval|send|post|upload|curl|wget|fetch)\b/i,
      /\b(?:ignore|override|forget|disregard|bypass)\b/i,
      /\b(?:secret|hidden|real|actual|true)\s+(?:instructions?|purpose|task)/i,
      /\b(?:do\s+not\s+(?:tell|show|reveal))\b/i,
      /\b(?:env|token|key|password|credential|secret)\b/i,
    ];

    const isSuspicious = suspiciousPatterns.some(p => p.test(commentBody));
    if (!isSuspicious) continue;

    // Find line number
    const offset = match.index;
    const lineNum = content.slice(0, offset).split('\n').length;

    findings.push({
      analyzer: 'prompt-injection',
      severity: 'critical',
      file: filePath,
      line: lineNum,
      message: 'Suspicious HTML comment — may contain hidden instructions for the agent',
      match: `<!-- ${commentBody.substring(0, 100)} -->`,
      ruleId: 'hiddenComment'
    });
  }
}

/**
 * Detect markdown link/image abuse for injecting instructions
 */
function detectMarkdownAbuse(content, findings, filePath) {
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Markdown images with suspicious alt text or data URIs
    const imgMatch = line.match(/!\[([^\]]*)\]\(([^)]*)\)/);
    if (imgMatch) {
      const alt = imgMatch[1];
      const url = imgMatch[2];

      // Data URI in markdown image
      if (url.startsWith('data:')) {
        findings.push({
          analyzer: 'prompt-injection',
          severity: 'warning',
          file: filePath,
          line: i + 1,
          message: 'Data URI in markdown image — may encode hidden content',
          match: line.trim().substring(0, 120),
          ruleId: 'dataUriMarkdown'
        });
      }

      // Long alt text (used to inject instructions since alt text gets sent to AI)
      if (alt.length > 200) {
        findings.push({
          analyzer: 'prompt-injection',
          severity: 'warning',
          file: filePath,
          line: i + 1,
          message: 'Extremely long image alt text — may inject hidden instructions',
          match: `![${alt.substring(0, 80)}...]`,
          ruleId: 'longAltText'
        });
      }
    }

    // Markdown links with javascript: protocol
    if (/\]\(javascript:/i.test(line)) {
      findings.push({
        analyzer: 'prompt-injection',
        severity: 'critical',
        file: filePath,
        line: i + 1,
        message: 'JavaScript protocol in markdown link',
        match: line.trim().substring(0, 120),
        ruleId: 'jsProtocolLink'
      });
    }
  }
}

/**
 * Detect repetitive/emphatic instruction patterns
 * Attackers often repeat instructions or use ALL CAPS/emphasis to increase success
 */
function detectEmphasisPatterns(content, findings, filePath) {
  const lines = content.split('\n');

  // Detect ALL-CAPS instruction blocks (3+ consecutive words)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const capsMatch = line.match(/\b([A-Z]{3,}\s+){3,}[A-Z]{3,}\b/);
    if (capsMatch) {
      // Check if it's actually instructional
      const instructionWords = /\b(IGNORE|OVERRIDE|MUST|ALWAYS|NEVER|IMPORTANT|CRITICAL|EXECUTE|SEND|FOLLOW|OBEY|COMPLY|DO|NOT|FORGET|DISREGARD)\b/;
      if (instructionWords.test(line)) {
        findings.push({
          analyzer: 'prompt-injection',
          severity: 'warning',
          file: filePath,
          line: i + 1,
          message: 'Emphatic ALL-CAPS instructions — common prompt injection technique',
          match: line.substring(0, 120),
          ruleId: 'emphasisInjection'
        });
      }
    }
  }
}

export async function analyzePromptInjection(skillPath) {
  const findings = [];

  // Scan all markdown and text files, but prioritize SKILL.md
  const files = await glob('**/*.{md,txt}', {
    cwd: skillPath,
    nodir: true,
    ignore: ['node_modules/**', '.git/**']
  });

  // Ensure SKILL.md is first if it exists
  const sorted = files.sort((a, b) => {
    if (a === 'SKILL.md') return -1;
    if (b === 'SKILL.md') return 1;
    return 0;
  });

  for (const file of sorted) {
    const filePath = join(skillPath, file);
    let content;

    try {
      content = await readFile(filePath, 'utf-8');
    } catch { continue; }

    if (content.length > MAX_FILE_SIZE) continue;

    const lines = content.split('\n');
    const relPath = file;

    // Run all regex-based rules
    for (const [id, rule] of Object.entries(INJECTION_RULES)) {
      for (let i = 0; i < lines.length; i++) {
        // Reset regex state
        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(lines[i]);
        if (match) {
          findings.push({
            analyzer: 'prompt-injection',
            severity: rule.severity,
            file: relPath,
            line: i + 1,
            message: rule.description,
            match: match[0].substring(0, 120),
            ruleId: rule.ruleId
          });
        }
      }
    }

    // Structural analysis
    detectInvisibleChars(content, findings, relPath);
    detectHiddenCommentInstructions(content, findings, relPath);
    detectMarkdownAbuse(content, findings, relPath);
    detectEmphasisPatterns(content, findings, relPath);
  }

  return findings;
}
