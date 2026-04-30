// ============================================================
// dashboard.js — Interactive terminal dashboard
// Run: node scripts/dashboard.js
// ============================================================

const chalk = require('chalk');
const Table = require('cli-table3');
const readline = require('readline');
const { FINDINGS, MASVS_COVERAGE } = require('../data/findings');

// ── Colour helpers ──────────────────────────────────────────
const SEV_COLOR = {
  CRITICAL: (t) => chalk.bgRed.white.bold(` ${t} `),
  HIGH:     (t) => chalk.bgYellow.black.bold(` ${t} `),
  MEDIUM:   (t) => chalk.bgBlue.white.bold(` ${t} `),
  LOW:      (t) => chalk.bgGreen.white.bold(` ${t} `),
  INFO:     (t) => chalk.bgMagenta.white.bold(` ${t} `),
};
const sev = (s) => (SEV_COLOR[s] ? SEV_COLOR[s](s) : s);
const dim = chalk.gray;
const bold = chalk.bold;
const cyan = chalk.cyan;
const green = chalk.green;
const red = chalk.red;
const yellow = chalk.yellow;
const magenta = chalk.magenta;

// ── Banner ──────────────────────────────────────────────────
function printBanner() {
  console.clear();
  console.log(chalk.red.bold(''));
  console.log(chalk.red.bold('  ███╗   ███╗ █████╗ ██╗   ██╗███████╗██████╗ '));
  console.log(chalk.red.bold('  ████╗ ████║██╔══██╗██║   ██║██╔════╝██╔══██╗'));
  console.log(chalk.red.bold('  ██╔████╔██║███████║██║   ██║███████╗██████╔╝'));
  console.log(chalk.red.bold('  ██║╚██╔╝██║██╔══██║╚██╗ ██╔╝╚════██║██╔═══╝ '));
  console.log(chalk.red.bold('  ██║ ╚═╝ ██║██║  ██║ ╚████╔╝ ███████║██║     '));
  console.log(chalk.red.bold('  ╚═╝     ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝     '));
  console.log('');
  console.log(chalk.white.bold('  Mobile App Security Verification — Red Team Dashboard'));
  console.log(dim('  OWASP MASVS v2.1  |  iOS & Android  |  DemoBank Mobile v3.2.1'));
  console.log(dim('  ─────────────────────────────────────────────────────────────'));
  console.log('');
}

// ── Summary metrics ─────────────────────────────────────────
function printSummary() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  FINDINGS.forEach((f) => counts[f.severity]++);
  const total = FINDINGS.length;
  const covered = MASVS_COVERAGE.length;
  const passed = MASVS_COVERAGE.filter((c) => c.status === 'PASS').length;

  console.log(bold('  ┌─ FINDINGS SUMMARY ──────────────────────────────────────┐'));
  console.log(
    `  │  ${SEV_COLOR.CRITICAL('CRITICAL')} ${red.bold(counts.CRITICAL)}   ` +
    `${SEV_COLOR.HIGH('HIGH')} ${yellow.bold(counts.HIGH)}   ` +
    `${SEV_COLOR.MEDIUM('MEDIUM')} ${chalk.blue.bold(counts.MEDIUM)}   ` +
    `${SEV_COLOR.LOW('LOW')} ${green.bold(counts.LOW)}   ` +
    `${SEV_COLOR.INFO('INFO')} ${magenta.bold(counts.INFO)}        │`
  );
  console.log(`  │  Total Findings: ${bold(total)}  |  MASVS Controls: ${bold(covered)} tested  |  Pass Rate: ${green.bold(passed + '/' + covered)}  │`);
  console.log(bold('  └────────────────────────────────────────────────────────────┘'));
  console.log('');
}

// ── Main findings table ─────────────────────────────────────
function printFindingsTable(filter = null) {
  let data = filter
    ? FINDINGS.filter((f) => f.severity === filter.toUpperCase())
    : FINDINGS;

  const table = new Table({
    head: [
      chalk.white.bold('ID'),
      chalk.white.bold('Severity'),
      chalk.white.bold('Title'),
      chalk.white.bold('Category'),
      chalk.white.bold('Platform'),
      chalk.white.bold('CVSS'),
    ],
    colWidths: [8, 12, 48, 10, 10, 7],
    style: { head: [], border: ['gray'] },
  });

  data.forEach((f) => {
    const cvssColor =
      f.cvss >= 9 ? red.bold : f.cvss >= 7 ? yellow.bold : f.cvss >= 4 ? chalk.blue.bold : green.bold;
    table.push([
      cyan(f.id),
      sev(f.severity),
      f.title.length > 45 ? f.title.substring(0, 44) + '…' : f.title,
      dim(f.category),
      f.platform === 'Both' ? chalk.magenta('Both') : f.platform === 'iOS' ? chalk.blue('iOS') : chalk.green('Android'),
      cvssColor(String(f.cvss)),
    ]);
  });

  console.log(table.toString());
  console.log('');
}

// ── Single finding detail ───────────────────────────────────
function printFindingDetail(id) {
  const f = FINDINGS.find((x) => x.id.toUpperCase() === id.toUpperCase());
  if (!f) {
    console.log(red(`  Finding ${id} not found.`));
    return;
  }

  const line = dim('  ' + '─'.repeat(70));
  console.log('');
  console.log(line);
  console.log(`  ${cyan.bold(f.id)}  ${sev(f.severity)}  ${bold(f.title)}`);
  console.log(line);
  console.log(`  ${dim('MASVS:')} ${f.masvs}   ${dim('CVSS:')} ${red.bold(String(f.cvss))}   ${dim('Platform:')} ${f.platform}   ${dim('Tools:')} ${f.tools.join(', ')}`);
  console.log('');
  console.log(`  ${bold('Description')}`);
  console.log(`  ${f.description}`);
  console.log('');
  console.log(`  ${bold('Impact')}`);
  console.log(`  ${f.impact}`);
  console.log('');
  console.log(`  ${bold('Exploit Steps')}`);
  f.exploitSteps.forEach((s, i) => {
    console.log(`  ${yellow(String(i + 1) + '.')} ${s}`);
  });
  console.log('');
  console.log(`  ${bold('Remediation')}`);
  console.log(`  ${green(f.remediation)}`);
  if (f.fridaScript) {
    console.log('');
    console.log(`  ${dim('Frida script:')} ${cyan(f.fridaScript)}`);
  }
  console.log(line);
  console.log('');
}

// ── MASVS coverage table ────────────────────────────────────
function printCoverage() {
  const table = new Table({
    head: [
      chalk.white.bold('MASVS ID'),
      chalk.white.bold('Control'),
      chalk.white.bold('Level'),
      chalk.white.bold('Status'),
      chalk.white.bold('Platform'),
      chalk.white.bold('Finding'),
    ],
    colWidths: [18, 42, 8, 8, 10, 12],
    style: { head: [], border: ['gray'] },
  });

  MASVS_COVERAGE.forEach((c) => {
    table.push([
      cyan(c.id),
      c.control.length > 40 ? c.control.substring(0, 39) + '…' : c.control,
      chalk.magenta(c.level),
      c.status === 'PASS' ? green.bold('PASS') : red.bold('FAIL'),
      dim(c.platform),
      c.findingId ? yellow(c.findingId) : dim('—'),
    ]);
  });

  console.log(table.toString());
  console.log('');
}

// ── Stats breakdown ─────────────────────────────────────────
function printStats() {
  const byCat = {};
  FINDINGS.forEach((f) => {
    if (!byCat[f.category]) byCat[f.category] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    byCat[f.category][f.severity]++;
  });

  console.log(bold('  Findings by Category'));
  console.log('');
  Object.entries(byCat).forEach(([cat, counts]) => {
    const bar = [
      counts.CRITICAL ? red.bold('█'.repeat(counts.CRITICAL * 2)) : '',
      counts.HIGH     ? yellow.bold('█'.repeat(counts.HIGH * 2)) : '',
      counts.MEDIUM   ? chalk.blue.bold('█'.repeat(counts.MEDIUM * 2)) : '',
      counts.LOW      ? green.bold('█'.repeat(counts.LOW * 2)) : '',
    ].join('');
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    console.log(`  ${cyan(cat.padEnd(6))}  ${bar}  ${dim(total + ' finding' + (total > 1 ? 's' : ''))}`);
  });
  console.log('');

  const byPlatform = { iOS: 0, Android: 0, Both: 0 };
  FINDINGS.forEach((f) => byPlatform[f.platform]++);
  console.log(bold('  Findings by Platform'));
  console.log('');
  console.log(`  ${chalk.blue('iOS')}     ${chalk.blue.bold('█'.repeat(byPlatform.iOS * 2))}  ${dim(byPlatform.iOS)}`);
  console.log(`  ${green('Android')} ${green.bold('█'.repeat(byPlatform.Android * 2))}  ${dim(byPlatform.Android)}`);
  console.log(`  ${magenta('Both')}    ${magenta.bold('█'.repeat(byPlatform.Both * 2))}  ${dim(byPlatform.Both)}`);
  console.log('');
}

// ── Help ────────────────────────────────────────────────────
function printHelp() {
  console.log(bold('  Commands'));
  console.log('');
  console.log(`  ${cyan('list')}              Show all findings table`);
  console.log(`  ${cyan('list critical')}     Filter by severity (critical/high/medium/low/info)`);
  console.log(`  ${cyan('detail F-001')}      Show full detail for a finding`);
  console.log(`  ${cyan('coverage')}          Show MASVS control coverage`);
  console.log(`  ${cyan('stats')}             Show breakdown charts`);
  console.log(`  ${cyan('report')}            Generate Word document report`);
  console.log(`  ${cyan('clear')}             Clear screen`);
  console.log(`  ${cyan('exit')}              Exit dashboard`);
  console.log('');
}

// ── REPL ────────────────────────────────────────────────────
async function main() {
  printBanner();
  printSummary();
  printHelp();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: chalk.red.bold('  masvs> ') + chalk.white(''),
  });

  rl.prompt();

  rl.on('line', async (line) => {
    const parts = line.trim().split(' ');
    const cmd = parts[0].toLowerCase();
    const arg = parts.slice(1).join(' ');

    console.log('');

    switch (cmd) {
      case 'list':
        printFindingsTable(arg || null);
        break;
      case 'detail':
        if (!arg) {
          console.log(red('  Usage: detail <finding-id>  e.g. detail F-001'));
        } else {
          printFindingDetail(arg.toUpperCase());
        }
        break;
      case 'coverage':
        printCoverage();
        break;
      case 'stats':
        printStats();
        break;
      case 'report':
        console.log(cyan('  Generating report...'));
        const { execSync } = require('child_process');
        try {
          execSync('node report/generate-report.js', { stdio: 'inherit', cwd: require('path').join(__dirname, '..') });
          console.log(green.bold('  Report generated: output/mobile_pentest_report.docx'));
        } catch (e) {
          console.log(red('  Error generating report. Run: node report/generate-report.js'));
        }
        break;
      case 'clear':
        printBanner();
        printSummary();
        printHelp();
        break;
      case 'help':
        printHelp();
        break;
      case 'exit':
      case 'quit':
        console.log(dim('  Exiting. Stay curious, stay ethical.\n'));
        process.exit(0);
        break;
      case '':
        break;
      default:
        console.log(red(`  Unknown command: "${cmd}"`) + dim('  Type help for commands.'));
        console.log('');
    }

    rl.prompt();
  });

  rl.on('close', () => {
    console.log('');
    process.exit(0);
  });
}

main();
