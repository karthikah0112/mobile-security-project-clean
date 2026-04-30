// ============================================================
// F012-prng-monitor.js — Detect weak PRNG usage
// Finding: F-012 — Weak PRNG for Session Token Generation
// Usage: frida -U -f com.demobank.app -l F012-prng-monitor.js
// ============================================================

Java.perform(function () {
  console.log('[F-012] PRNG Monitor loaded');

  // ── Hook java.util.Random (WEAK) ──────────────────────────
  var Random = Java.use('java.util.Random');

  Random.$init.overload().implementation = function () {
    console.log('\n[F-012] 🚨 java.util.Random created with no seed (seeded from time)');
    console.log('[F-012]    This is PREDICTABLE. Use java.security.SecureRandom instead.');
    printStack();
    return this.$init();
  };

  Random.$init.overload('long').implementation = function (seed) {
    console.log('\n[F-012] 🚨 java.util.Random created with seed: ' + seed);
    if (seed < 1000000000000) { // timestamp-like seed
      console.log('[F-012]    ⚠️  Seed looks time-based — highly predictable!');
    }
    printStack();
    return this.$init(seed);
  };

  Random.nextLong.implementation = function () {
    var val = this.nextLong();
    console.log('[F-012] java.util.Random.nextLong() = ' + val + ' (WEAK PRNG!)');
    return val;
  };

  Random.nextInt.overload().implementation = function () {
    var val = this.nextInt();
    console.log('[F-012] java.util.Random.nextInt() = ' + val + ' (WEAK PRNG!)');
    return val;
  };

  // ── Hook Math.random() (also weak) ────────────────────────
  var Math = Java.use('java.lang.Math');
  Math.random.implementation = function () {
    var val = this.random();
    console.log('[F-012] ⚠️  Math.random() = ' + val + ' (not cryptographically secure)');
    return val;
  };

  // ── Hook SecureRandom (GOOD — log when used correctly) ────
  var SecureRandom = Java.use('java.security.SecureRandom');

  SecureRandom.$init.overload().implementation = function () {
    console.log('\n[F-012] ✅  SecureRandom created (good!)');
    return this.$init();
  };

  SecureRandom.nextBytes.implementation = function (bytes) {
    this.nextBytes(bytes);
    var hex = Array.from(bytes).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    console.log('[F-012] ✅  SecureRandom.nextBytes(' + bytes.length + ' bytes) = ' + hex.substring(0, 32) + '...');
  };

  SecureRandom.nextLong.implementation = function () {
    var val = this.nextLong();
    console.log('[F-012] ✅  SecureRandom.nextLong() = ' + val);
    return val;
  };

  // ── UUID generation (often used for session IDs) ──────────
  try {
    var UUID = Java.use('java.util.UUID');
    UUID.randomUUID.implementation = function () {
      var uuid = this.randomUUID();
      console.log('[F-012] UUID.randomUUID() = ' + uuid.toString());
      console.log('[F-012]    ℹ️  UUID.randomUUID() uses SecureRandom internally — acceptable for session IDs');
      return uuid;
    };
  } catch (e) {}

  function printStack() {
    try {
      var stack = Java.use('android.util.Log').getStackTraceString(
        Java.use('java.lang.Exception').$new()
      ).split('\n').slice(1, 5);
      console.log('[F-012]    Stack: ' + stack.join('\n              '));
    } catch (e) {}
  }

  console.log('[F-012] PRNG hooks active. Log in or trigger any session-generating action.');
});
