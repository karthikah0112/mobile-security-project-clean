// ============================================================
// generate-report.js — Generates full Word document report
// Run: node report/generate-report.js
// ============================================================

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  LevelFormat, PageBreak, Header, Footer,
} = require('docx');
const fs   = require('fs');
const path = require('path');
const { FINDINGS, MASVS_COVERAGE } = require('../data/findings');

const outDir = path.join(__dirname, '..', 'output');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

// ── Colours ─────────────────────────────────────────────────
const C = {
  darkBlue: '1B2A4A', midBlue: '2E5090', lightBlue: 'D6E4F0',
  critical: 'C0392B', high: 'D35400', medium: '2471A3', low: '1E8449', info: '7D3C98',
  red50: 'FADBD8', amber50: 'FDEBD0', blue50: 'D6EAF8', green50: 'D5F5E3', purple50: 'EDE7F6',
  lightGray: 'F2F3F4', white: 'FFFFFF', midGray: 'AAAAAA',
};
const SEV_FILL = { CRITICAL: 'FADBD8', HIGH: 'FDEBD0', MEDIUM: 'D6EAF8', LOW: 'D5F5E3', INFO: 'EDE7F6' };
const SEV_TEXT = { CRITICAL: 'C0392B', HIGH: 'D35400', MEDIUM: '2471A3', LOW: '1E8449', INFO: '7D3C98' };

// ── Helpers ──────────────────────────────────────────────────
const bdr  = (color, size) => ({ style: BorderStyle.SINGLE, size, color });
const allB = (color, size) => ({ top: bdr(color,size), bottom: bdr(color,size), left: bdr(color,size), right: bdr(color,size) });
const cm   = { top: 80, bottom: 80, left: 150, right: 150 };

const gap  = (n=120) => new Paragraph({ spacing: { before: n, after: 0 }, children: [] });
const pb   = ()      => new Paragraph({ children: [new PageBreak()] });
const para = (t, o={}) => new Paragraph({ spacing: { before: 60, after: 100 }, children: [new TextRun({ text: t, size: 22, font: 'Arial', ...o })] });
const mono = (t)     => new Paragraph({ spacing: { before: 30, after: 30 }, indent: { left: 360 }, shading: { fill: '1E1E1E', type: ShadingType.CLEAR }, children: [new TextRun({ text: t, size: 18, font: 'Courier New', color: '00FF41' })] });
const blt  = (t, lv=0) => new Paragraph({ numbering: { reference: 'bullets', level: lv }, spacing: { before: 40, after: 40 }, children: [new TextRun({ text: t, size: 22, font: 'Arial' })] });

const h1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 120 }, children: [new TextRun({ text: t, bold: true, size: 36, color: C.darkBlue, font: 'Arial' })] });
const h2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 80 }, border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: C.midBlue, space: 1 } }, children: [new TextRun({ text: t, bold: true, size: 28, color: C.midBlue, font: 'Arial' })] });
const h3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 160, after: 60 }, children: [new TextRun({ text: t, bold: true, size: 24, color: C.darkBlue, font: 'Arial' })] });

function hdrCell(text, width) {
  return new TableCell({ borders: allB(C.midBlue,6), shading: { fill: C.darkBlue, type: ShadingType.CLEAR }, margins: cm, width: { size: width, type: WidthType.DXA },
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, size: 18, color: 'FFFFFF', font: 'Arial' })] })] });
}
function valCell(text, width, fill) {
  return new TableCell({ borders: allB('CCCCCC',4), shading: { fill: fill||C.white, type: ShadingType.CLEAR }, margins: cm, width: { size: width, type: WidthType.DXA },
    children: [new Paragraph({ children: [new TextRun({ text: String(text), size: 20, font: 'Arial' })] })] });
}
function sevCell(sev, width) {
  return new TableCell({ borders: allB('CCCCCC',4), shading: { fill: SEV_FILL[sev], type: ShadingType.CLEAR }, margins: cm, width: { size: width, type: WidthType.DXA },
    children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: sev, bold: true, size: 18, color: SEV_TEXT[sev], font: 'Arial' })] })] });
}

// ── Finding block ─────────────────────────────────────────────
function findingBlock(f) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [1800, 2160, 1800, 3600],
    rows: [
      new TableRow({ children: [
        new TableCell({ columnSpan: 4, borders: allB(C.midBlue,8), shading: { fill: C.darkBlue, type: ShadingType.CLEAR }, margins: cm, width: { size: 9360, type: WidthType.DXA },
          children: [new Paragraph({ children: [
            new TextRun({ text: f.id + '  ', bold: true, size: 22, color: 'AABBCC', font: 'Courier New' }),
            new TextRun({ text: f.title, bold: true, size: 22, color: 'FFFFFF', font: 'Arial' }),
          ]})] })
      ] }),
      new TableRow({ children: [hdrCell('Severity',1800), sevCell(f.severity,2160), hdrCell('CVSS',1800), valCell(f.cvss,3600)] }),
      new TableRow({ children: [hdrCell('MASVS',1800), valCell(f.masvs,2160), hdrCell('Platform',1800), valCell(f.platform,3600)] }),
      new TableRow({ children: [
        hdrCell('Tools',1800),
        new TableCell({ columnSpan: 3, borders: allB('CCCCCC',4), shading: { fill: C.white, type: ShadingType.CLEAR }, margins: cm, width: { size: 7560, type: WidthType.DXA },
          children: [new Paragraph({ children: [new TextRun({ text: f.tools.join(' · '), size: 18, font: 'Courier New' })] })] }),
      ] }),
      new TableRow({ children: [
        hdrCell('Description',1800),
        new TableCell({ columnSpan: 3, borders: allB('CCCCCC',4), shading: { fill: C.lightGray, type: ShadingType.CLEAR }, margins: cm, width: { size: 7560, type: WidthType.DXA },
          children: [new Paragraph({ children: [new TextRun({ text: f.description, size: 20, font: 'Arial' })] })] }),
      ] }),
      new TableRow({ children: [
        hdrCell('Impact',1800),
        new TableCell({ columnSpan: 3, borders: allB('CCCCCC',4), shading: { fill: C.white, type: ShadingType.CLEAR }, margins: cm, width: { size: 7560, type: WidthType.DXA },
          children: [new Paragraph({ children: [new TextRun({ text: f.impact, size: 20, font: 'Arial' })] })] }),
      ] }),
      new TableRow({ children: [
        hdrCell('Exploit Steps',1800),
        new TableCell({ columnSpan: 3, borders: allB('CCCCCC',4), shading: { fill: C.lightGray, type: ShadingType.CLEAR }, margins: cm, width: { size: 7560, type: WidthType.DXA },
          children: f.exploitSteps.map((s,i) => new Paragraph({ spacing: { before: 20, after: 20 }, children: [new TextRun({ text: `${i+1}. ${s}`, size: 20, font: 'Arial' })] })) }),
      ] }),
      new TableRow({ children: [
        hdrCell('Remediation',1800),
        new TableCell({ columnSpan: 3, borders: allB(C.low,6), shading: { fill: C.green50, type: ShadingType.CLEAR }, margins: cm, width: { size: 7560, type: WidthType.DXA },
          children: [new Paragraph({ children: [new TextRun({ text: f.remediation, size: 20, font: 'Arial', color: '145A32' })] })] }),
      ] }),
    ],
  });
}

// ── Summary table ─────────────────────────────────────────────
function summaryTable() {
  const widths = [900,1200,3860,900,1100,1400];
  const hdrs   = ['ID','Severity','Title','Cat','Platform','CVSS'];
  return new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: widths,
    rows: [
      new TableRow({ children: hdrs.map((h,i) => hdrCell(h, widths[i])) }),
      ...FINDINGS.map(f => new TableRow({ children: [
        new TableCell({ borders: allB('CCCCCC',4), margins: cm, width:{size:900,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:f.id,size:16,font:'Courier New'})]})] }),
        sevCell(f.severity, 1200),
        new TableCell({ borders: allB('CCCCCC',4), margins: cm, width:{size:3860,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:f.title,size:18,font:'Arial'})]})] }),
        new TableCell({ borders: allB('CCCCCC',4), margins: cm, width:{size:900,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:f.category,size:16,font:'Courier New'})]})] }),
        new TableCell({ borders: allB('CCCCCC',4), margins: cm, width:{size:1100,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:f.platform,size:16,font:'Arial'})]})] }),
        new TableCell({ borders: allB('CCCCCC',4), margins: cm, width:{size:1400,type:WidthType.DXA}, children:[new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:String(f.cvss),bold:true,size:18,font:'Arial',color:f.cvss>=9?C.critical:f.cvss>=7?C.high:f.cvss>=4?C.medium:C.low})]})] }),
      ]})),
    ],
  });
}

// ── MASVS coverage table ──────────────────────────────────────
function coverageTable() {
  const widths = [2000,3760,700,700,900,1300];
  const hdrs   = ['MASVS ID','Control','Level','Status','Platform','Finding'];
  return new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: widths,
    rows: [
      new TableRow({ children: hdrs.map((h,i) => hdrCell(h,widths[i])) }),
      ...MASVS_COVERAGE.map((c,idx) => new TableRow({ children: [
        new TableCell({ borders:allB('CCCCCC',4), shading:{fill:idx%2===0?C.lightGray:C.white,type:ShadingType.CLEAR}, margins:cm, width:{size:2000,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:c.id,size:17,font:'Courier New'})]})] }),
        new TableCell({ borders:allB('CCCCCC',4), shading:{fill:idx%2===0?C.lightGray:C.white,type:ShadingType.CLEAR}, margins:cm, width:{size:3760,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:c.control,size:18,font:'Arial'})]})] }),
        new TableCell({ borders:allB('CCCCCC',4), shading:{fill:C.purple50,type:ShadingType.CLEAR}, margins:cm, width:{size:700,type:WidthType.DXA}, children:[new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:c.level,bold:true,size:16,color:C.info,font:'Arial'})]})] }),
        new TableCell({ borders:allB('CCCCCC',4), shading:{fill:c.status==='PASS'?C.green50:C.red50,type:ShadingType.CLEAR}, margins:cm, width:{size:700,type:WidthType.DXA}, children:[new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:c.status,bold:true,size:16,color:c.status==='PASS'?C.low:C.critical,font:'Arial'})]})] }),
        new TableCell({ borders:allB('CCCCCC',4), margins:cm, width:{size:900,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:c.platform,size:16,font:'Arial'})]})] }),
        new TableCell({ borders:allB('CCCCCC',4), margins:cm, width:{size:1300,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:c.findingId||'—',size:16,font:'Courier New',color:c.findingId?C.high:'AAAAAA'})]})] }),
      ]})),
    ],
  });
}

// ── Cover severity pills ──────────────────────────────────────
function coverPills() {
  const pills = [
    ['5','CRITICAL',C.red50,C.critical],
    ['8','HIGH',C.amber50,C.high],
    ['1','MEDIUM',C.blue50,C.medium],
    ['2','LOW/INFO',C.green50,C.low],
  ];
  return new Table({
    width: { size: 7200, type: WidthType.DXA }, columnWidths: [1800,1800,1800,1800],
    rows: [
      new TableRow({
        children: pills.map(([n,lbl,fill,txt]) =>
          new TableCell({ borders: allB(C.midBlue,6), shading: { fill, type: ShadingType.CLEAR },
            margins: { top:160, bottom:160, left:0, right:0 }, width: { size:1800, type:WidthType.DXA },
            children: [
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text:n, bold:true, size:64, color:txt, font:'Arial' })] }),
              new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text:lbl, bold:true, size:18, color:txt, font:'Arial' })] }),
            ],
          })
        ),
      }),
    ],
  });
}

// ── Tool stack table ──────────────────────────────────────────
function toolTable() {
  const tools = [
    ['Frida + objection','Dynamic instrumentation','Runtime hooking, SSL bypass, PIN brute-force, Keychain dump'],
    ['jadx / jadx-gui','Android decompiler','Java/Kotlin source recovery, secret extraction, manifest review'],
    ['apktool','APK unpacking','Resource extraction, smali review, manifest analysis'],
    ['Burp Suite Pro','HTTP proxy','Full traffic interception, API mapping, session analysis'],
    ['mitmproxy','HTTP proxy','Scripted traffic manipulation and replay attacks'],
    ['class-dump / dsdump','iOS binary analysis','Objective-C class and method header extraction'],
    ['keychain-dumper','iOS Keychain','Dump all Keychain items on jailbroken device'],
    ['drozer','Android attack framework','IPC testing, exported component enumeration'],
    ['adb','Android debug bridge','File system access, intent injection, logcat capture'],
    ['trufflehog','Secret scanning','Automated search for hardcoded credentials in source'],
    ['jwt_tool','JWT manipulation','Token forging, algorithm confusion, brute-force'],
    ['Ghidra','Binary analysis','Low-level crypto and logic reverse engineering'],
  ];
  const widths = [2200,2400,4760];
  return new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: widths,
    rows: [
      new TableRow({ children: ['Tool','Category','Usage in this assessment'].map((h,i)=>hdrCell(h,widths[i])) }),
      ...tools.map(([t,c,u],i) => new TableRow({ children: [
        new TableCell({ borders:allB('CCCCCC',4), shading:{fill:i%2===0?C.lightGray:C.white,type:ShadingType.CLEAR}, margins:cm, width:{size:2200,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:t,bold:true,size:18,font:'Courier New',color:C.darkBlue})]})] }),
        new TableCell({ borders:allB('CCCCCC',4), shading:{fill:i%2===0?C.lightGray:C.white,type:ShadingType.CLEAR}, margins:cm, width:{size:2400,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:c,size:18,font:'Arial'})]})] }),
        new TableCell({ borders:allB('CCCCCC',4), shading:{fill:i%2===0?C.lightGray:C.white,type:ShadingType.CLEAR}, margins:cm, width:{size:4760,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:u,size:18,font:'Arial'})]})] }),
      ]})),
    ],
  });
}

// ── Build document ────────────────────────────────────────────
const criticals = FINDINGS.filter(f => f.severity === 'CRITICAL');
const highs     = FINDINGS.filter(f => f.severity === 'HIGH');
const others    = FINDINGS.filter(f => !['CRITICAL','HIGH'].includes(f.severity));

const children = [
  // ── COVER ──────────────────────────────────────────────────
  gap(1440),
  new Paragraph({ alignment:AlignmentType.CENTER, children:[new TextRun({text:'MOBILE APPLICATION',bold:true,size:64,color:C.darkBlue,font:'Arial'})] }),
  new Paragraph({ alignment:AlignmentType.CENTER, children:[new TextRun({text:'SECURITY VERIFICATION REPORT',bold:true,size:64,color:C.darkBlue,font:'Arial'})] }),
  gap(80),
  new Paragraph({ alignment:AlignmentType.CENTER, border:{ bottom:{style:BorderStyle.SINGLE,size:12,color:C.midBlue} }, children:[new TextRun({text:'Red Team  ·  OWASP MASVS v2.1  ·  iOS & Android',size:26,color:C.midBlue,font:'Arial'})] }),
  gap(240),
  new Table({
    width:{size:7200,type:WidthType.DXA}, columnWidths:[3600,3600],
    rows:[
      new TableRow({ children:[
        new TableCell({ borders:allB(C.midBlue,8), shading:{fill:C.lightBlue,type:ShadingType.CLEAR}, margins:{top:120,bottom:120,left:200,right:200}, width:{size:3600,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:'Target Application',bold:true,size:20,color:C.darkBlue,font:'Arial'})]}), new Paragraph({children:[new TextRun({text:'DemoBank Mobile v3.2.1 (Fictional)',size:22,font:'Arial'})]})] }),
        new TableCell({ borders:allB(C.midBlue,8), shading:{fill:C.lightBlue,type:ShadingType.CLEAR}, margins:{top:120,bottom:120,left:200,right:200}, width:{size:3600,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:'Assessment Type',bold:true,size:20,color:C.darkBlue,font:'Arial'})]}), new Paragraph({children:[new TextRun({text:'Black-box + Static Analysis',size:22,font:'Arial'})]})] }),
      ] }),
      new TableRow({ children:[
        new TableCell({ borders:allB(C.midBlue,8), shading:{fill:C.white,type:ShadingType.CLEAR}, margins:{top:120,bottom:120,left:200,right:200}, width:{size:3600,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:'Platforms',bold:true,size:20,color:C.darkBlue,font:'Arial'})]}), new Paragraph({children:[new TextRun({text:'iOS 17 + Android 14',size:22,font:'Arial'})]})] }),
        new TableCell({ borders:allB(C.midBlue,8), shading:{fill:C.white,type:ShadingType.CLEAR}, margins:{top:120,bottom:120,left:200,right:200}, width:{size:3600,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:'Standard',bold:true,size:20,color:C.darkBlue,font:'Arial'})]}), new Paragraph({children:[new TextRun({text:'OWASP MASVS 2.1 — L1 + L2',size:22,font:'Arial'})]})] }),
      ] }),
      new TableRow({ children:[
        new TableCell({ borders:allB(C.midBlue,8), shading:{fill:C.lightBlue,type:ShadingType.CLEAR}, margins:{top:120,bottom:120,left:200,right:200}, width:{size:3600,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:'Author',bold:true,size:20,color:C.darkBlue,font:'Arial'})]}), new Paragraph({children:[new TextRun({text:'[Your Name] — Junior Security Researcher',size:22,font:'Arial'})]})] }),
        new TableCell({ borders:allB(C.midBlue,8), shading:{fill:C.lightBlue,type:ShadingType.CLEAR}, margins:{top:120,bottom:120,left:200,right:200}, width:{size:3600,type:WidthType.DXA}, children:[new Paragraph({children:[new TextRun({text:'Date',bold:true,size:20,color:C.darkBlue,font:'Arial'})]}), new Paragraph({children:[new TextRun({text:'April 2026',size:22,font:'Arial'})]})] }),
      ] }),
    ],
  }),
  gap(200),
  coverPills(),
  pb(),

  // ── SECTION 1 ───────────────────────────────────────────────
  h1('1. Executive Summary'),
  para('This report presents the findings of a personal security research project assessing a fictional mobile banking application — DemoBank Mobile v3.2.1 — against the OWASP Mobile Application Security Verification Standard (MASVS) v2.1. Conducted as a portfolio project to develop practical mobile pentesting skills across iOS and Android.'),
  gap(80),
  para('14 findings were identified across 6 MASVS categories. Five Critical and eight High findings represent significant attack surface that would compromise user accounts and expose financial data if left unaddressed.'),
  gap(80),
  h2('1.1 Risk Summary'),
  summaryTable(),
  gap(160),
  h2('1.2 Key Observations'),
  blt('Authentication is critically weak — secrets hardcoded, brute-force protections absent.'),
  blt('Network layer is the most exposed surface — no certificate pinning on either platform.'),
  blt('Platform-specific issues on both iOS and Android show OS-level security was not considered.'),
  blt('Crypto primitives present but misconfigured — AES used in ECB mode.'),
  blt('Data storage issues span both platforms, exposing PII without encryption.'),
  pb(),

  // ── SECTION 2 ───────────────────────────────────────────────
  h1('2. Scope & Methodology'),
  h2('2.1 Scope'),
  para('Personal research project in a local lab environment. DemoBank Mobile is a fictional app built for this assessment. No real users, real data, or production systems were involved. Published for portfolio and educational purposes only.'),
  gap(80),
  h2('2.2 Testing Phases'),
  h3('Phase 1 — Reconnaissance & Setup'),
  blt('Jailbreak iOS via Dopamine 2.x · Root Android emulator via Magisk'),
  blt('Deploy frida-server on both platforms for runtime instrumentation'),
  blt('Configure Burp Suite CA + system proxy for full traffic capture'),
  blt('Extract IPA via frida-ios-dump · Decompile APK with apktool + jadx'),
  gap(60),
  h3('Phase 2 — Static Analysis'),
  blt('Decompile APK: jadx-gui — review Java/Kotlin source, AndroidManifest.xml, strings.xml'),
  blt('iOS class header dump: class-dump and dsdump on extracted binary'),
  blt('Secret scanning: trufflehog + manual grep for keys, JWTs, hardcoded credentials'),
  blt('Permissions audit: Android manifest + iOS entitlements review'),
  gap(60),
  h3('Phase 3 — Dynamic Analysis'),
  blt('Runtime hooking with Frida — traced auth, crypto, storage method calls'),
  blt('SSL pinning bypass via objection (objection --gadget <app> explore)'),
  blt('Full API traffic map via Burp Suite — endpoint enumeration, token analysis'),
  blt('Deeplink and IPC fuzzing with ADB intent injection and custom Frida scripts'),
  gap(60),
  h3('Phase 4 — Data Storage'),
  blt('SharedPreferences dump via ADB backup on Android'),
  blt('iOS Keychain enumeration with keychain-dumper on jailbroken device'),
  blt('SQLite database extraction via ADB and review'),
  blt('Logcat capture (adb logcat) + iOS syslog (idevicesyslog)'),
  gap(60),
  h3('Phase 5 — Network Security'),
  blt('TLS version sweep — test for TLS 1.0/1.1 fallback'),
  blt('Certificate validation bypass and custom CA injection testing'),
  blt('API key and bearer token harvest from intercepted traffic'),
  pb(),

  // ── SECTION 3 ───────────────────────────────────────────────
  h1('3. Findings'),
  h2('3.1 Critical Findings'),
  gap(80),
  ...criticals.flatMap(f => [findingBlock(f), gap(160)]),
  pb(),
  h2('3.2 High Findings'),
  gap(80),
  ...highs.flatMap(f => [findingBlock(f), gap(160)]),
  pb(),
  h2('3.3 Medium / Low / Informational'),
  gap(80),
  ...others.flatMap(f => [findingBlock(f), gap(160)]),
  pb(),

  // ── SECTION 4 ───────────────────────────────────────────────
  h1('4. MASVS Coverage'),
  para('Testing was conducted against OWASP MASVS v2.1 L1 and L2 controls. Of 74 applicable controls, 47 were verified during this assessment (63% coverage).'),
  gap(80),
  coverageTable(),
  pb(),

  // ── SECTION 5 ───────────────────────────────────────────────
  h1('5. Tools & Techniques'),
  h2('5.1 Tool Stack'),
  toolTable(),
  gap(120),
  h2('5.2 Frida Script — SSL Pinning Bypass (Android)'),
  para('The following script replaces the TrustManager with one that accepts all certificates, then overrides SSLContext.getDefault() so all HTTPS connections use the permissive context:'),
  gap(60),
  mono('Java.perform(function () {'),
  mono('  var TrustManager = Java.use("javax.net.ssl.X509TrustManager");'),
  mono('  var SSLContext    = Java.use("javax.net.ssl.SSLContext");'),
  mono('  var TrustManagerImpl = Java.registerClass({'),
  mono('    name: "com.bypass.UniversalTrustManager",'),
  mono('    implements: [TrustManager],'),
  mono('    methods: {'),
  mono('      checkClientTrusted: function(chain, authType) {},'),
  mono('      checkServerTrusted: function(chain, authType) {},'),
  mono('      getAcceptedIssuers: function() { return []; }'),
  mono('    }'),
  mono('  });'),
  mono('  var ctx = SSLContext.getInstance("TLS");'),
  mono('  ctx.init(null, [TrustManagerImpl.$new()], null);'),
  mono('  SSLContext.getDefault.implementation = function() { return ctx; };'),
  mono('  console.log("[*] SSL pinning bypassed");'),
  mono('});'),
  pb(),

  // ── SECTION 6 ───────────────────────────────────────────────
  h1('6. Recommendations'),
  h2('6.1 Immediate — Before Next Release (Critical)'),
  blt('Rotate all hardcoded JWT secrets. Move to asymmetric signing (RS256/ES256).'),
  blt('Implement EncryptedSharedPreferences for all Android storage. Remove plaintext PII.'),
  blt('Implement certificate pinning on both platforms. Pin SPKI hash, not the certificate.'),
  blt('Validate all deeplink parameters. Reject path traversal sequences canonically.'),
  blt('Remove auth token from iOS pasteboard writes. Use localOnly + immediate expiry.'),
  gap(80),
  h2('6.2 Short-Term — Within 30 Days (High)'),
  blt('Replace all AES-ECB usage with AES-GCM (authenticated encryption).'),
  blt('Add PIN attempt counter to Keystore/Keychain. Lockout after 5 failures.'),
  blt('Update all Keychain items to kSecAttrAccessibleWhenUnlockedThisDeviceOnly.'),
  blt('Implement API key rotation. Use short-lived bearer tokens with refresh.'),
  blt('Add permission checks to all exported Android activities.'),
  gap(80),
  h2('6.3 Medium-Term — 30–90 Days'),
  blt('Enable FLAG_SECURE on all screens displaying account numbers, balances, or credentials.'),
  blt('Replace java.util.Random with SecureRandom. Replace NSRandom with SecRandomCopyBytes.'),
  blt('Strip debug symbols from all release builds. Enforce in CI/CD pipeline.'),
  blt('Disable verbose logging in release builds via ProGuard rules or Timber.'),
  pb(),

  // ── SECTION 7 ───────────────────────────────────────────────
  h1('7. Disclaimer'),
  para('This report was produced as a personal portfolio project. DemoBank Mobile is a fictional application created for this assessment in a controlled lab environment. No real users, real financial data, or real infrastructure were involved.'),
  gap(80),
  para('All techniques were performed against an app I own and control, in an isolated network. Published for educational purposes to demonstrate understanding of mobile security principles, OWASP MASVS controls, and common vulnerability classes found in real-world applications.'),
  gap(80),
  h2('References'),
  blt('OWASP MASVS v2.1 — https://mas.owasp.org/MASVS/'),
  blt('OWASP MASTG — https://mas.owasp.org/MASTG/'),
  blt('CVSS v3.1 — https://www.first.org/cvss/calculator/3.1'),
  blt('Frida — https://frida.re'),
  blt('jadx — https://github.com/skylot/jadx'),
  blt('objection — https://github.com/sensepost/objection'),
  gap(160),
  new Paragraph({ alignment:AlignmentType.CENTER, border:{ top:{style:BorderStyle.SINGLE,size:4,color:'AAAAAA',space:1} }, children:[new TextRun({text:'End of Report  ·  Mobile App Security Verification  ·  April 2026',size:18,color:'AAAAAA',font:'Arial'})] }),
];

const doc = new Document({
  numbering: { config: [{ reference:'bullets', levels:[
    { level:0, format:LevelFormat.BULLET, text:'•', alignment:AlignmentType.LEFT, style:{ paragraph:{ indent:{ left:720, hanging:360 } } } },
    { level:1, format:LevelFormat.BULLET, text:'◦', alignment:AlignmentType.LEFT, style:{ paragraph:{ indent:{ left:1080, hanging:360 } } } },
  ]}] },
  styles: {
    default: { document: { run: { font:'Arial', size:22 } } },
    paragraphStyles: [
      { id:'Heading1', name:'Heading 1', basedOn:'Normal', next:'Normal', quickFormat:true, run:{ size:36, bold:true, font:'Arial', color:C.darkBlue }, paragraph:{ spacing:{ before:360, after:120 }, outlineLevel:0 } },
      { id:'Heading2', name:'Heading 2', basedOn:'Normal', next:'Normal', quickFormat:true, run:{ size:28, bold:true, font:'Arial', color:C.midBlue }, paragraph:{ spacing:{ before:240, after:80 }, outlineLevel:1 } },
      { id:'Heading3', name:'Heading 3', basedOn:'Normal', next:'Normal', quickFormat:true, run:{ size:24, bold:true, font:'Arial', color:C.darkBlue }, paragraph:{ spacing:{ before:160, after:60 }, outlineLevel:2 } },
    ],
  },
  sections: [{
    properties: { page: { size:{ width:12240, height:15840 }, margin:{ top:1080, right:1080, bottom:1080, left:1080 } } },
    headers: { default: new Header({ children:[
      new Paragraph({ border:{ bottom:{ style:BorderStyle.SINGLE, size:6, color:C.midBlue, space:1 } }, children:[
        new TextRun({ text:'Mobile App Security Verification Report  |  ', size:18, color:C.midBlue, font:'Arial' }),
        new TextRun({ text:'PORTFOLIO PROJECT — EDUCATIONAL', bold:true, size:18, color:C.critical, font:'Arial' }),
      ]}),
    ]}) },
    footers: { default: new Footer({ children:[
      new Paragraph({ border:{ top:{ style:BorderStyle.SINGLE, size:4, color:'AAAAAA', space:1 } }, children:[
        new TextRun({ text:'Red Team Security Research  |  OWASP MASVS v2.1  |  iOS & Android', size:16, color:'AAAAAA', font:'Arial' }),
      ]}),
    ]}) },
    children,
  }],
});

Packer.toBuffer(doc).then(buf => {
  const p = path.join(outDir, 'mobile_pentest_report.docx');
  fs.writeFileSync(p, buf);
  console.log('✅  Report saved → output/mobile_pentest_report.docx');
}).catch(err => {
  console.error('❌  Error:', err.message);
});
