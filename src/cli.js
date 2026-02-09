#!/usr/bin/env node

import { Command } from 'commander';
import ora from 'ora';
import chalk from 'chalk';
import { scan } from './scanner.js';
import { formatReport } from './reporter.js';

const program = new Command();

program
  .name('clawguard')
  .description('🛡️  Security scanner for OpenClaw skills — detect malicious patterns before installing')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan an OpenClaw skill for security issues')
  .argument('<target>', 'Path to skill directory or ClawHub URL')
  .option('-v, --verbose', 'Show detailed output including info-level findings')
  .option('-j, --json', 'Output results as JSON')
  .option('--no-color', 'Disable colored output')
  .action(async (target, options) => {
    if (!options.json) {
      console.log('');
      console.log(chalk.bold.white('  🛡️  ClawGuard — OpenClaw Skill Security Scanner'));
      console.log('');
    }

    const spinner = options.json ? null : ora({
      text: 'Scanning skill...',
      indent: 2
    }).start();

    try {
      const results = await scan(target, options);

      if (spinner) spinner.stop();

      const report = formatReport(results, {
        verbose: options.verbose,
        json: options.json,
      });

      console.log(report);

      // Exit with non-zero if dangerous
      if (results.risk.level === 'dangerous') {
        process.exit(2);
      } else if (results.risk.level === 'warning') {
        process.exit(1);
      }
      process.exit(0);

    } catch (err) {
      if (spinner) spinner.fail(chalk.red(err.message));
      else console.error(JSON.stringify({ error: err.message }));
      process.exit(3);
    }
  });

program
  .command('version')
  .description('Show version')
  .action(() => {
    console.log('clawguard v1.0.0');
  });

// Default to help if no command
if (process.argv.length <= 2) {
  program.outputHelp();
  process.exit(0);
}

program.parse();
