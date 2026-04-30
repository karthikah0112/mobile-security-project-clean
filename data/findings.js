// ============================================================
// findings.js — Central data store for all pentest findings
// Mobile App Security Verification Project
// ============================================================

const FINDINGS = [
  {
    id: 'F-001',
    severity: 'CRITICAL',
    cvss: 9.8,
    category: 'AUTH',
    masvs: 'MASVS-AUTH-2',
    platform: 'Both',
    title: 'JWT Secret Hardcoded in Application Binary',
    tools: ['jadx', 'strings', 'frida', 'jwt_tool'],
    description:
      'The JWT signing secret was found in plaintext within the compiled APK. ' +
      'On Android it was located in decompiled Java source via jadx. ' +
      'On iOS it was recoverable via the strings utility on the extracted binary.',
    impact:
      'An attacker who extracts the binary can forge valid JWT tokens for any user ID, ' +
      'enabling complete account takeover without knowing credentials.',
    exploitSteps: [
      'Extract APK: adb shell pm path com.demobank.app + adb pull <path>',
      'Decompile: jadx-gui app.apk — search strings.xml and source for "jwt", "secret"',
      'Located: private static final String JWT_SECRET = "sk-jwt-demobank-secret-2024"',
      'Forge token: python3 jwt_tool.py -I -pc user_id -pv 9999 -S hs256 -p "sk-jwt-demobank-secret-2024"',
      'Send forged Bearer token in Authorization header — confirmed full account access',
    ],
    fridaScript: 'frida-scripts/F001-jwt-hook.js',
    remediation:
      'Store JWT secrets exclusively in server-side environment variables. ' +
      'Switch to asymmetric signing (RS256/ES256) so the mobile app only holds the public key. ' +
      'Rotate all current secrets immediately and invalidate existing tokens.',
    status: 'OPEN',
  },
  {
    id: 'F-002',
    severity: 'CRITICAL',
    cvss: 9.1,
    category: 'STOR',
    masvs: 'MASVS-STOR-1',
    platform: 'Android',
    title: 'Cleartext PII in SharedPreferences',
    tools: ['adb', 'drozer'],
    description:
      'User email, phone number, and session tokens are stored unencrypted in ' +
      'com.demobank.app_preferences.xml — world-readable on rooted devices and accessible ' +
      'via ADB backup on Android 13 and below without root.',
    impact:
      'Any app with READ_EXTERNAL_STORAGE or an attacker with ADB access can extract all PII ' +
      'and session tokens, enabling immediate account takeover.',
    exploitSteps: [
      'Enable ADB backup: adb backup -noapk com.demobank.app',
      'Unpack: dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys; sys.stdout.write(zlib.decompress(sys.stdin.read()))" > backup.tar',
      'Extract: tar xf backup.tar',
      'Read: cat apps/com.demobank.app/sp/com.demobank.app_preferences.xml',
      'Found plaintext: email, phone, session_token, device_id',
    ],
    fridaScript: 'frida-scripts/F002-storage-monitor.js',
    remediation:
      'Use EncryptedSharedPreferences (Jetpack Security library) for all sensitive data. ' +
      'Store session tokens only in memory, re-requested on app resume. ' +
      'Never persist raw tokens to disk.',
    status: 'OPEN',
  },
  {
    id: 'F-003',
    severity: 'CRITICAL',
    cvss: 8.8,
    category: 'NET',
    masvs: 'MASVS-NETWORK-2',
    platform: 'Both',
    title: 'SSL Certificate Pinning Not Implemented',
    tools: ['Burp Suite', 'objection', 'frida-ssl-pinning-bypass'],
    description:
      'The application accepts any certificate from a system-trusted CA. ' +
      'No certificate pinning is implemented on either platform. ' +
      'All HTTPS traffic is fully visible in Burp Suite with zero bypass effort.',
    impact:
      'All API traffic including auth tokens, PII, and financial data is exposed to any ' +
      'network-positioned attacker. Session tokens captured enable full account hijacking.',
    exploitSteps: [
      'Install Burp Suite CA cert as system certificate on device',
      'Set device Wi-Fi proxy to Burp listener (192.168.x.x:8080)',
      'Launch app — all HTTPS traffic appears in Burp Proxy in plaintext immediately',
      'No SSL bypass script needed — app trusts Burp CA without further action',
      'Captured: Authorization: Bearer <token>, full JSON response bodies with balances and PII',
    ],
    fridaScript: 'frida-scripts/F003-ssl-bypass.js',
    remediation:
      'Implement certificate pinning using OkHttp CertificatePinner (Android) or ' +
      'URLSession pinning delegate (iOS). Pin to the SPKI hash of the leaf or intermediate cert, ' +
      'not the certificate itself. Include backup pins to handle cert rotation.',
    status: 'OPEN',
  },
  {
    id: 'F-004',
    severity: 'CRITICAL',
    cvss: 9.3,
    category: 'CODE',
    masvs: 'MASVS-CODE-4',
    platform: 'Android',
    title: 'Deeplink Path Traversal — Arbitrary File Write',
    tools: ['adb', 'jadx', 'custom PoC'],
    description:
      'The deeplink handler demobank://open?file= passes the file parameter directly to a ' +
      'file write operation without sanitisation. A malicious deeplink can traverse directory ' +
      'boundaries using ../ sequences to write to any app-accessible file.',
    impact:
      'An attacker can craft a malicious deeplink in a phishing URL or QR code that overwrites ' +
      'the app SQLite database, SharedPreferences, or cached auth tokens. ' +
      'Could lead to account lockout, data destruction, or code execution via shared lib overwrite.',
    exploitSteps: [
      'Identify deeplink handler in AndroidManifest.xml: <data android:scheme="demobank" android:host="open"/>',
      'Trace handler in jadx: FileUtils.writeFile(getIntent().getStringExtra("file"), data)',
      'Craft malicious intent: adb shell am start -a android.intent.action.VIEW -d "demobank://open?file=../../databases/userdata.db&content=OVERWRITTEN"',
      'Verify: adb shell run-as com.demobank.app cat databases/userdata.db',
      'Confirmed: file successfully overwritten via path traversal',
    ],
    fridaScript: 'frida-scripts/F004-deeplink-monitor.js',
    remediation:
      'Resolve the canonical path of any file parameter and verify it falls within the ' +
      'application sandbox directory before performing any file operation. ' +
      'Apply allowlist validation to all deeplink and IPC input parameters.',
    status: 'OPEN',
  },
  {
    id: 'F-005',
    severity: 'CRITICAL',
    cvss: 8.5,
    category: 'PLAT',
    masvs: 'MASVS-PLATFORM-4',
    platform: 'iOS',
    title: 'Auth Token Written to iOS System Pasteboard',
    tools: ['frida', 'xcode-instruments', 'custom pasteboard monitor'],
    description:
      'When a user copies their account number, the full Bearer auth token is written to ' +
      'UIPasteboard.general — the system-wide pasteboard accessible to all installed applications. ' +
      'Apps in the background can poll pasteboard changes and silently receive the token.',
    impact:
      'Any malicious app can register for UIPasteboard change notifications and capture auth tokens ' +
      'the moment they are copied. The captured token grants full API access for the 24-hour session ' +
      'duration with no revocation mechanism.',
    exploitSteps: [
      'Hook UIPasteboard in Frida: Interceptor.attach(ObjC.classes.UIPasteboard["- setString:"].implementation, ...)',
      'Trigger copy action in app UI (copy account number)',
      'Frida log: [Pasteboard Write] Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      'Background monitor app registered for pasteboard notifications receives token within 200ms',
      'Token used directly in API call — confirmed full account access without credentials',
    ],
    fridaScript: 'frida-scripts/F005-pasteboard-hook.js',
    remediation:
      'Never write authentication tokens to UIPasteboard.general. ' +
      'If copy functionality is needed, write only the user-facing account number. ' +
      'Set localOnly: true and expirationDate: Date() for any sensitive pasteboard writes.',
    status: 'OPEN',
  },
  {
    id: 'F-006',
    severity: 'HIGH',
    cvss: 7.4,
    category: 'CRYP',
    masvs: 'MASVS-CRYPTO-1',
    platform: 'Both',
    title: 'AES-ECB Mode Used for Local Data Encryption',
    tools: ['jadx', 'Ghidra', 'custom Python script'],
    description:
      'The application uses AES in ECB (Electronic Codebook) mode to encrypt locally cached API ' +
      'responses. ECB is deterministic — identical plaintext blocks produce identical ciphertext blocks — ' +
      'causing pattern leakage that allows partial plaintext recovery without the key.',
    impact:
      'Block frequency analysis of the encrypted cache revealed account number prefixes and ' +
      'repeating field structure. An attacker with access to the cache file can infer data structure ' +
      'and recover partial values without brute-forcing the key.',
    exploitSteps: [
      'Locate in jadx: Cipher.getInstance("AES/ECB/PKCS5Padding")',
      'Extract encrypted cache: adb pull /data/data/com.demobank.app/cache/api_cache.bin',
      'Run block analysis: python3 scripts/ecb-detector.py api_cache.bin',
      'Output: Repeated 16-byte blocks detected at offsets 32, 64, 96',
      'Partial recovery: Account number prefix pattern reconstructed from repeating blocks',
    ],
    fridaScript: 'frida-scripts/F006-crypto-monitor.js',
    remediation:
      'Replace all AES-ECB usage with AES-GCM (authenticated encryption). ' +
      'Generate a fresh random nonce (12 bytes) for every encryption operation. ' +
      'Store the nonce alongside the ciphertext. AES-GCM also provides integrity checking.',
    status: 'OPEN',
  },
  {
    id: 'F-007',
    severity: 'HIGH',
    cvss: 7.1,
    category: 'AUTH',
    masvs: 'MASVS-AUTH-7',
    platform: 'Both',
    title: 'No Brute-Force Protection on Local PIN Entry',
    tools: ['frida', 'objection'],
    description:
      'The 4-digit local PIN has no failed attempt counter, lockout, or delay between attempts. ' +
      'PIN verification runs entirely in-process and can be automated via Frida hooks. ' +
      'Full keyspace (10,000 PINs) exhausted in under 3 minutes.',
    impact:
      'Physical access to a device with the app running is sufficient for an attacker to brute-force ' +
      'the PIN. No jailbreak required. A simple Frida script iterates all possible values with ' +
      'no rate limiting or lockout triggered.',
    exploitSteps: [
      'Identify PIN check via Frida trace: -[PINViewController validatePIN:]',
      'Attach brute-force script: frida -U -f com.demobank.app -l frida-scripts/F007-pin-bruteforce.js',
      'Script iterates 0000-9999 via ObjC.schedule calls',
      'Correct PIN identified in 2 minutes 47 seconds',
      'No lockout, no delay, no alert triggered at any point',
    ],
    fridaScript: 'frida-scripts/F007-pin-bruteforce.js',
    remediation:
      'Limit to 5 failed PIN attempts then require biometric or full account re-authentication. ' +
      'Apply exponential backoff between failed attempts. ' +
      'Bind the attempt counter to the OS Keychain/Keystore so it survives app data clear.',
    status: 'OPEN',
  },
  {
    id: 'F-008',
    severity: 'HIGH',
    cvss: 6.8,
    category: 'STOR',
    masvs: 'MASVS-STOR-2',
    platform: 'iOS',
    title: 'Keychain Items Accessible After Device Wipe via iCloud Backup',
    tools: ['keychain-dumper', 'frida', 'iCloud backup analysis'],
    description:
      'Authentication tokens and the app PIN stored in iOS Keychain use kSecAttrAccessibleAlways. ' +
      'This allows Keychain items to be included in iCloud backups and restored to a different device, ' +
      'bypassing all device-level security.',
    impact:
      'An attacker who compromises the victim\'s iCloud account can restore the Keychain to a new device ' +
      'and access valid session tokens without knowing the device PIN or biometrics.',
    exploitSteps: [
      'Verify attribute via Frida hook on SecItemAdd: kSecAttrAccessible = kSecAttrAccessibleAlways',
      'Perform iCloud backup: Settings > iCloud > Backup Now',
      'Restore backup to secondary device with a different passcode',
      'Run keychain-dumper on secondary device',
      'Recovered: session_token, refresh_token, app_pin — all valid and unexpired',
    ],
    fridaScript: 'frida-scripts/F008-keychain-monitor.js',
    remediation:
      'All Keychain items must use kSecAttrAccessibleWhenUnlockedThisDeviceOnly. ' +
      'This prevents backup export and device transfer. ' +
      'Never use kSecAttrAccessibleAlways or any non-ThisDeviceOnly variant for tokens or credentials.',
    status: 'OPEN',
  },
  {
    id: 'F-009',
    severity: 'HIGH',
    cvss: 7.2,
    category: 'NET',
    masvs: 'MASVS-NETWORK-1',
    platform: 'Both',
    title: 'Static API Keys in Request Headers — No Rotation Policy',
    tools: ['Burp Suite', 'mitmproxy'],
    description:
      'Static API keys are transmitted in the X-API-Key request header on every API call. ' +
      'Keys are never rotated and appear to be valid indefinitely. ' +
      'Captured via traffic interception, they work without any additional auth context.',
    impact:
      'Any captured API key grants permanent backend access. ' +
      'There is no token revocation or expiry mechanism. ' +
      'Keys found in intercepted traffic would remain valid until manually rotated.',
    exploitSteps: [
      'Intercept traffic via Burp Suite (SSL bypass already applied from F-003)',
      'Observe: X-API-Key: ak-live-demobank-8f3a2b9c1d7e header on all requests',
      'Replay key in standalone curl request: curl -H "X-API-Key: ak-live-demobank-8f3a2b9c1d7e" https://api.demobank.app/v1/accounts',
      'Response: full account data returned — key works without any session context',
      'Tested key validity after 7 days — still active, no rotation observed',
    ],
    fridaScript: null,
    remediation:
      'Replace static API keys with short-lived JWT tokens or OAuth2 access tokens (15-60 min TTL). ' +
      'Implement server-side key rotation on a schedule. ' +
      'Tie API access to the authenticated user session, not a shared static key.',
    status: 'OPEN',
  },
  {
    id: 'F-010',
    severity: 'HIGH',
    cvss: 6.5,
    category: 'CODE',
    masvs: 'MASVS-CODE-4',
    platform: 'Android',
    title: 'Exported Activity Accepts Arbitrary Intents — No Permission Check',
    tools: ['drozer', 'adb'],
    description:
      'A settings activity is exported in AndroidManifest.xml without a permission requirement. ' +
      'Any third-party app can send intents to this activity, triggering internal navigation ' +
      'including the account deletion confirmation dialog.',
    impact:
      'A malicious app silently installed alongside the banking app can trigger destructive actions ' +
      'including initiating account deletion, resetting app settings, and bypassing internal navigation guards.',
    exploitSteps: [
      'Run drozer: run app.activity.info -a com.demobank.app',
      'Found: com.demobank.app/.ui.SettingsActivity exported=true, no permissions required',
      'Send intent: adb shell am start -n com.demobank.app/.ui.SettingsActivity --es action DELETE_ACCOUNT',
      'Result: account deletion confirmation dialog presented without any authentication',
      'Confirmed: malicious app can trigger this without any user interaction',
    ],
    fridaScript: null,
    remediation:
      'Add android:exported="false" to all activities not intended for external access. ' +
      'For those that must be exported, add android:permission with a custom signature-level permission. ' +
      'Validate and reject unexpected intent extras before acting on them.',
    status: 'OPEN',
  },
  {
    id: 'F-011',
    severity: 'MEDIUM',
    cvss: 4.3,
    category: 'PLAT',
    masvs: 'MASVS-PLATFORM-2',
    platform: 'Android',
    title: 'FLAG_SECURE Not Set on Sensitive Screens',
    tools: ['adb', 'manual testing'],
    description:
      'The account summary, payment, and credential screens do not set FLAG_SECURE. ' +
      'Screenshots of these screens can be taken by the OS, recent apps thumbnail, and any ' +
      'app with screen recording permission.',
    impact:
      'Malware with RECORD_AUDIO or screen capture capability can silently capture account ' +
      'numbers, balances, and payment details displayed on screen.',
    exploitSteps: [
      'Navigate to account summary screen showing balance and account number',
      'adb shell screencap -p /sdcard/screen.png — capture succeeds',
      'Also visible in Android recent apps thumbnail — sensitive data exposed',
    ],
    fridaScript: null,
    remediation:
      'Add getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) ' +
      'in onCreate() for all activities displaying sensitive information. ' +
      'This prevents screenshots and removes the screen from recent apps thumbnails.',
    status: 'OPEN',
  },
  {
    id: 'F-012',
    severity: 'MEDIUM',
    cvss: 5.9,
    category: 'CRYP',
    masvs: 'MASVS-CRYPTO-2',
    platform: 'Both',
    title: 'Weak PRNG Used for Session Token Generation',
    tools: ['jadx', 'static analysis'],
    description:
      'java.util.Random (Android) and an equivalent weak PRNG (iOS) are used to generate ' +
      'session identifiers. java.util.Random uses a linear congruential generator seeded with ' +
      'the system clock — predictable with knowledge of the seed time.',
    impact:
      'An attacker who can observe one or more tokens and approximate the generation time can ' +
      'predict subsequent tokens. This enables session prediction attacks without authentication.',
    exploitSteps: [
      'Identify in jadx: new Random(System.currentTimeMillis()).nextLong()',
      'Observe a token and record the timestamp of the request',
      'Brute-force seed within ±1 second window: ~2000 possible seeds',
      'Regenerate candidate tokens and test against API',
      'Matching token found within ~1500 attempts in testing',
    ],
    fridaScript: 'frida-scripts/F012-prng-monitor.js',
    remediation:
      'Replace java.util.Random with SecureRandom throughout. ' +
      'On iOS replace with SecRandomCopyBytes. ' +
      'Never seed a PRNG with time-based values for security-sensitive operations.',
    status: 'OPEN',
  },
  {
    id: 'F-013',
    severity: 'LOW',
    cvss: 2.7,
    category: 'CODE',
    masvs: 'MASVS-CODE-3',
    platform: 'iOS',
    title: 'Debug Symbols Present in Release IPA',
    tools: ['nm', 'otool', 'class-dump'],
    description:
      'The release IPA contains dSYM debug symbols, exposing function names, class hierarchy, ' +
      'internal API path strings, and method signatures to a reverse engineer.',
    impact:
      'Significantly reduces the effort required to reverse engineer the application. ' +
      'Internal endpoint paths, authentication logic structure, and business logic are all visible.',
    exploitSteps: [
      'Extract IPA and inspect binary: nm -U DemoBank | grep -i "auth\\|token\\|secret"',
      'Output: _validateJWTToken, _storeCredentialToKeychain, _fetchAccountBalance',
      'Run class-dump: class-dump DemoBank > headers.h',
      'Internal endpoint paths visible in header dump: /internal/v2/admin/users',
    ],
    fridaScript: null,
    remediation:
      'Strip debug symbols from all release builds by setting Strip Debug Symbols to Yes ' +
      'in Xcode build settings. Add symbol stripping as a mandatory CI/CD pipeline step. ' +
      'Never ship dSYM files with the IPA.',
    status: 'OPEN',
  },
  {
    id: 'F-014',
    severity: 'INFO',
    cvss: 0.0,
    category: 'STOR',
    masvs: 'MASVS-STOR-3',
    platform: 'Android',
    title: 'Stack Traces and Internal URLs Written to Logcat',
    tools: ['adb'],
    description:
      'Verbose debug logging is active in the release build. ' +
      'Full stack traces, internal API endpoint URLs, and network error details ' +
      'are written to Logcat using Log.d and Log.e.',
    impact:
      'Any app with READ_LOGS permission (granted to some system apps and adb) can read these logs. ' +
      'Internal endpoint structure and error patterns aid reconnaissance.',
    exploitSteps: [
      'Connect adb and run: adb logcat | grep -i demobank',
      'Output includes: D/DemoBank: POST https://internal-api.demobank.app/v2/auth/validate',
      'Stack traces visible on failed requests: java.net.SocketTimeoutException at ...',
    ],
    fridaScript: null,
    remediation:
      'Disable all Log.d and Log.v calls in release builds using ProGuard rules or a build-flavour logging wrapper. ' +
      'Use a logging framework (Timber) that no-ops in release. ' +
      'Never log endpoint URLs, tokens, or stack traces in production.',
    status: 'OPEN',
  },
];

const MASVS_COVERAGE = [
  { id: 'MASVS-STOR-1', control: 'No sensitive data on external storage', level: 'L1', status: 'FAIL', platform: 'Android', findingId: 'F-002' },
  { id: 'MASVS-STOR-2', control: 'Keychain/Keystore used correctly', level: 'L2', status: 'FAIL', platform: 'iOS', findingId: 'F-008' },
  { id: 'MASVS-STOR-3', control: 'No sensitive data in app logs', level: 'L1', status: 'FAIL', platform: 'Android', findingId: 'F-014' },
  { id: 'MASVS-STOR-4', control: 'No sensitive data in keyboard cache', level: 'L1', status: 'PASS', platform: 'Both', findingId: null },
  { id: 'MASVS-CRYP-1', control: 'Strong cipher suites only (no ECB/RC4/MD5)', level: 'L1', status: 'FAIL', platform: 'Both', findingId: 'F-006' },
  { id: 'MASVS-CRYP-2', control: 'CSPRNG for all random values', level: 'L1', status: 'FAIL', platform: 'Both', findingId: 'F-012' },
  { id: 'MASVS-CRYP-3', control: 'AES key length >= 128 bits', level: 'L1', status: 'PASS', platform: 'Both', findingId: null },
  { id: 'MASVS-AUTH-1', control: 'Remote endpoint authentication enforced', level: 'L1', status: 'PASS', platform: 'Both', findingId: null },
  { id: 'MASVS-AUTH-2', control: 'Secrets not hardcoded in binary', level: 'L1', status: 'FAIL', platform: 'Both', findingId: 'F-001' },
  { id: 'MASVS-AUTH-7', control: 'Brute-force lockout on local auth', level: 'L2', status: 'FAIL', platform: 'Both', findingId: 'F-007' },
  { id: 'MASVS-NET-1', control: 'TLS 1.2+ enforced, no fallback', level: 'L1', status: 'PASS', platform: 'Both', findingId: null },
  { id: 'MASVS-NET-2', control: 'Certificate pinning implemented', level: 'L2', status: 'FAIL', platform: 'Both', findingId: 'F-003' },
  { id: 'MASVS-PLAT-2', control: 'FLAG_SECURE on sensitive screens', level: 'L1', status: 'FAIL', platform: 'Android', findingId: 'F-011' },
  { id: 'MASVS-PLAT-4', control: 'Pasteboard not used for sensitive data', level: 'L2', status: 'FAIL', platform: 'iOS', findingId: 'F-005' },
  { id: 'MASVS-CODE-3', control: 'Debug symbols stripped from release', level: 'L1', status: 'FAIL', platform: 'iOS', findingId: 'F-013' },
  { id: 'MASVS-CODE-4', control: 'All IPC input validated and sanitised', level: 'L1', status: 'FAIL', platform: 'Android', findingId: 'F-004,F-010' },
];

module.exports = { FINDINGS, MASVS_COVERAGE };
