// ============================================================
// F006-crypto-monitor.js — Monitor crypto operations
// Finding: F-006 — AES-ECB Mode Used for Local Data Encryption
// Usage: frida -U -f com.demobank.app -l F006-crypto-monitor.js
// ============================================================

Java.perform(function () {
  console.log('[F-006] Crypto Monitor loaded');

  var weakModes  = ['ECB', 'CBC', 'RC4', 'DES', 'MD5', 'SHA1'];
  var strongModes = ['GCM', 'CCM', 'ChaCha20'];

  // ── Hook Cipher.getInstance ───────────────────────────────
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
    var isWeak   = weakModes.some(m => transformation.toUpperCase().includes(m));
    var isStrong = strongModes.some(m => transformation.toUpperCase().includes(m));

    if (isWeak) {
      console.log('\n[F-006] 🚨 WEAK CIPHER: Cipher.getInstance("' + transformation + '")');
      console.log('[F-006]    Stack: ' + Java.use('android.util.Log').getStackTraceString(
        Java.use('java.lang.Exception').$new()
      ).split('\n').slice(1, 5).join('\n           '));
    } else if (isStrong) {
      console.log('\n[F-006] ✅  Strong cipher: Cipher.getInstance("' + transformation + '")');
    } else {
      console.log('\n[F-006] ℹ️  Cipher.getInstance("' + transformation + '")');
    }
    return this.getInstance(transformation);
  };

  // ── Hook Cipher.init to capture keys ──────────────────────
  Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
    var modeStr = mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : 'WRAP/UNWRAP';
    var keyBytes = key.getEncoded();
    var keyHex   = Array.from(keyBytes).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    console.log('[F-006] Cipher.init() mode=' + modeStr + ' key=' + keyHex.substring(0, 32) + '...');
    return this.init(mode, key);
  };

  // ── Hook MessageDigest (MD5/SHA1 detection) ───────────────
  try {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function (algo) {
      if (['MD5', 'SHA-1', 'SHA1'].includes(algo.toUpperCase())) {
        console.log('\n[F-006] ⚠️  Weak hash: MessageDigest.getInstance("' + algo + '")');
      }
      return this.getInstance(algo);
    };
  } catch (e) {}

  // ── Hook SecretKeySpec to capture key material ─────────────
  try {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
      var keyHex = Array.from(key).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
      console.log('[F-006] SecretKeySpec created: algo=' + algo + ' keyLen=' + key.length * 8 + ' bits  key=' + keyHex.substring(0, 32) + '...');
      return this.$init(key, algo);
    };
  } catch (e) {}

  // ── Hook IvParameterSpec (ECB has no IV) ──────────────────
  try {
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function (iv) {
      var ivHex = Array.from(iv).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
      console.log('[F-006] ✅  IV used: ' + ivHex + '  (good — not ECB)');
      return this.$init(iv);
    };
  } catch (e) {}

  // ── Hook GCMParameterSpec ──────────────────────────────────
  try {
    var GCMParameterSpec = Java.use('javax.crypto.spec.GCMParameterSpec');
    GCMParameterSpec.$init.overload('int', '[B').implementation = function (tLen, iv) {
      console.log('[F-006] ✅  GCM mode: tagLen=' + tLen + ' bits');
      return this.$init(tLen, iv);
    };
  } catch (e) {}

  console.log('[F-006] Crypto hooks active. Trigger app features that store/load data.');
});
