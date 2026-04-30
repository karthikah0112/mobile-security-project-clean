// ============================================================
// F004-deeplink-monitor.js — Monitor deeplink and intent handling
// Finding: F-004 — Deeplink Path Traversal
// Usage: frida -U -f com.demobank.app -l F004-deeplink-monitor.js
// ============================================================

Java.perform(function () {
  console.log('[F-004] Deeplink Monitor loaded');

  // ── Hook Activity.getIntent() to see incoming intents ─────
  var Activity = Java.use('android.app.Activity');
  Activity.getIntent.implementation = function () {
    var intent = this.getIntent();
    if (intent !== null) {
      try {
        var data = intent.getData();
        if (data !== null) {
          console.log('\n[F-004] Deep link received!');
          console.log('[F-004]    URI: ' + data.toString());
          console.log('[F-004]    Scheme: ' + data.getScheme());
          console.log('[F-004]    Host:   ' + data.getHost());
          console.log('[F-004]    Path:   ' + data.getPath());
          console.log('[F-004]    Query:  ' + data.getQuery());

          // Check for path traversal
          var path = data.getQueryParameter('file') || data.getPath() || '';
          if (path.includes('../') || path.includes('..%2F') || path.includes('%2e%2e')) {
            console.log('[F-004]    🚨 PATH TRAVERSAL DETECTED in: ' + path);
          }
        }

        // Log all extras
        var extras = intent.getExtras();
        if (extras !== null) {
          var keys = extras.keySet().toArray();
          keys.forEach(function (key) {
            var val = extras.get(key);
            console.log('[F-004]    Extra: ' + key + ' = ' + val);
          });
        }
      } catch (e) {}
    }
    return intent;
  };

  // ── Hook File operations to catch path traversal writes ───
  var File = Java.use('java.io.File');
  File.$init.overload('java.lang.String').implementation = function (path) {
    if (path && (path.includes('../') || path.includes('/data/') || path.includes('/proc/'))) {
      console.log('\n[F-004] ⚠️  File() instantiated with path: ' + path);
      console.log('[F-004]    Stack: ' + Java.use('android.util.Log').getStackTraceString(
        Java.use('java.lang.Exception').$new()
      ).split('\n').slice(1, 4).join('\n           '));
    }
    return this.$init(path);
  };

  // ── Hook FileOutputStream to catch writes ─────────────────
  var FileOutputStream = Java.use('java.io.FileOutputStream');
  FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function (file, append) {
    var path = file.getAbsolutePath();
    console.log('\n[F-004] FileOutputStream write to: ' + path);
    if (path.includes('../') || !path.startsWith('/data/user/0/com.demobank')) {
      console.log('[F-004]    🚨 SUSPICIOUS PATH — possible path traversal!');
    }
    return this.$init(file, append);
  };

  // ── Hook Intent parsing for exported activities ───────────
  var Intent = Java.use('android.content.Intent');
  Intent.getStringExtra.implementation = function (name) {
    var val = this.getStringExtra(name);
    if (val !== null) {
      console.log('[F-004] Intent.getStringExtra("' + name + '") = ' + val);
    }
    return val;
  };

  console.log('[F-004] Deeplink hooks active.');
  console.log('[F-004] Test with: adb shell am start -a android.intent.action.VIEW -d "demobank://open?file=../../databases/userdata.db"');
});
