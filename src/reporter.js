import chalk from 'chalk';

const SEVERITY_COLORS = {
  critical: chalk.red.bold,
  warning: chalk.yellow,
  info: chalk.blue,
};

const SEVERITY_ICONS = {
  critical: '🚨',
  warning: '⚠️ ',
  info: 'ℹ️ ',
};

const SEVERITY_LABELS = {
  critical: 'CRITICAL',
  warning: 'WARNING',
  info: 'INFO',
};

/**
 * Format the scan report for terminal output
 */
export function formatReport(results, options = {}) {
  const { verbose = false, json = false } = options;

  if (json) {
    return JSON.stringify(results, null, 2);
  }

  const lines = [];
  const hr = chalk.dim('─'.repeat(60));

  // Header
  lines.push('');
  lines.push(chalk.bold.white('  🛡️  ClawGuard Security Report'));
  lines.push(hr);
  lines.push(`  ${chalk.dim('Target:')}  ${results.target}`);
  lines.push(`  ${chalk.dim('Scanned:')} ${new Date(results.timestamp).toLocaleString()}`);
  lines.push(hr);

  // Risk Score
  const risk = results.risk;
  const riskColor = risk.level === 'dangerous' ? chalk.red.bold
    : risk.level === 'warning' ? chalk.yellow.bold
    : chalk.green.bold;

  lines.push('');
  lines.push(`  ${risk.emoji}  Risk Assessment: ${riskColor(risk.label)} (score: ${risk.score}/100)`);
  lines.push('');

  // Summary counts
  const { summary } = results;
  lines.push(`  ${chalk.dim('Findings:')}  ${chalk.red(summary.critical + ' critical')}  ${chalk.yellow(summary.warning + ' warning')}  ${chalk.blue(summary.info + ' info')}`);
  lines.push('');

  // Findings grouped by severity
  if (results.findings.length === 0) {
    lines.push(`  ${chalk.green('✓')} No security issues detected`);
    lines.push('');
  } else {
    // Critical findings first
    for (const severity of ['critical', 'warning', 'info']) {
      const sevFindings = results.findings.filter(f => f.severity === severity);
      if (sevFindings.length === 0) continue;

      // In non-verbose mode, skip info findings
      if (!verbose && severity === 'info') {
        lines.push(chalk.dim(`  ... ${sevFindings.length} informational findings (use --verbose to show)`));
        continue;
      }

      const colorFn = SEVERITY_COLORS[severity];
      const icon = SEVERITY_ICONS[severity];

      lines.push(colorFn(`  ── ${SEVERITY_LABELS[severity]} (${sevFindings.length}) ${'─'.repeat(40)}`));
      lines.push('');

      // Deduplicate similar findings
      const seen = new Set();
      for (const f of sevFindings) {
        const key = `${f.file}:${f.ruleId}:${f.line}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const location = f.line ? `${f.file}:${f.line}` : f.file;
        lines.push(`  ${icon} ${colorFn(f.message)}`);
        lines.push(`     ${chalk.dim('at')} ${chalk.cyan(location)} ${chalk.dim(`[${f.analyzer}/${f.ruleId}]`)}`);

        if (f.match && verbose) {
          lines.push(`     ${chalk.dim('match:')} ${chalk.dim(f.match)}`);
        }

        lines.push('');
      }
    }
  }

  // Analyzer stats (verbose)
  if (verbose) {
    lines.push(hr);
    lines.push(chalk.dim('  Analyzers:'));
    for (const a of results.analyzers) {
      const status = a.status === 'ok' ? chalk.green('✓') : chalk.red('✗');
      lines.push(`    ${status} ${a.name}: ${a.findings} findings (${a.elapsed}ms)`);
      if (a.error) {
        lines.push(`      ${chalk.red(a.error)}`);
      }
    }
    lines.push('');
  }

  lines.push(hr);
  lines.push(chalk.dim('  ClawGuard v1.0.0 — https://github.com/sggolakiya/clawguard'));
  lines.push('');

  return lines.join('\n');
}
