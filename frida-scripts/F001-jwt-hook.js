// ============================================================
// F001-jwt-hook.js — Hook JWT token creation and validation
// Finding: F-001 — JWT Secret Hardcoded in Binary
// Usage: frida -U -f com.demobank.app -l F001-jwt-hook.js
// ============================================================

Java.perform(function () {
  console.log('[F-001] JWT Hook loaded');

  // Hook common JWT library methods (JJWT, java-jwt)
  try {
    var Jwts = Java.use('io.jsonwebtoken.Jwts');

    // Hook builder to capture signing key
    Jwts.builder.implementation = function () {
      console.log('[F-001] Jwts.builder() called — watch for .signWith()');
      return this.builder();
    };
  } catch (e) {
    console.log('[F-001] JJWT not found, trying java-jwt...');
  }

  try {
    var Algorithm = Java.use('com.auth0.jwt.algorithms.Algorithm');

    Algorithm.HMAC256.overload('java.lang.String').implementation = function (secret) {
      console.log('[F-001] ⚠️  JWT signing secret found!');
      console.log('[F-001]    Secret: ' + secret);
      console.log('[F-001]    Stack: ' + Java.use('android.util.Log').getStackTraceString(
        Java.use('java.lang.Exception').$new()
      ));
      return this.HMAC256(secret);
    };
  } catch (e) {
    console.log('[F-001] java-jwt Algorithm not found: ' + e);
  }

  // Hook String contains/equals to catch hardcoded secret comparisons
  try {
    var String = Java.use('java.lang.String');
    var targetKeywords = ['secret', 'jwt', 'token', 'sk-', 'key'];

    String.equals.implementation = function (other) {
      var result = this.equals(other);
      var self = this.toString();
      // Only log if looks like a secret
      if (self.length > 20 && targetKeywords.some(k => self.toLowerCase().includes(k))) {
        console.log('[F-001] String.equals on potential secret: ' + self.substring(0, 30) + '...');
      }
      return result;
    };
  } catch (e) {
    console.log('[F-001] String hook failed: ' + e);
  }

  // Hook SharedPreferences to catch token reads/writes
  try {
    var SharedPreferences = Java.use('android.content.SharedPreferences');
    var Editor = Java.use('android.content.SharedPreferences$Editor');

    // Hook putString to catch token writes
    var EditorImpl = Java.use('com.android.providers.settings.SettingsProvider$MySettingsObserver');
  } catch (e) {}

  // More reliable: hook all putString calls via the concrete implementation
  Java.choose('android.app.SharedPreferencesImpl$EditorImpl', {
    onMatch: function (instance) {},
    onComplete: function () {},
  });

  // Hook the actual editor put
  try {
    var ContextImpl = Java.use('android.app.ContextImpl');
    ContextImpl.getSharedPreferences.overload('java.lang.String', 'int').implementation = function (name, mode) {
      var sp = this.getSharedPreferences(name, mode);
      console.log('[F-001] SharedPreferences opened: ' + name);
      return sp;
    };
  } catch (e) {}

  console.log('[F-001] Hooks active. Interact with the app now.');
});
