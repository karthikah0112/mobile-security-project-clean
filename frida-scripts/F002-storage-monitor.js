// ============================================================
// F002-storage-monitor.js — Monitor all data storage writes
// Finding: F-002 — Cleartext PII in SharedPreferences
// Usage: frida -U -f com.demobank.app -l F002-storage-monitor.js
// ============================================================

Java.perform(function () {
  console.log('[F-002] Storage Monitor loaded');

  var sensitiveKeys = ['email', 'phone', 'token', 'password', 'session', 'auth', 'user', 'account'];

  // ── SharedPreferences writes ──────────────────────────────
  Java.choose('android.app.SharedPreferencesImpl$EditorImpl', {
    onMatch: function (editor) {
      var putString = editor.putString;
      editor.putString.implementation = function (key, value) {
        var isSensitive = sensitiveKeys.some(k => key.toLowerCase().includes(k));
        if (isSensitive) {
          console.log('[F-002] ⚠️  SharedPreferences.putString()');
          console.log('[F-002]    Key:   ' + key);
          console.log('[F-002]    Value: ' + (value ? value.substring(0, 80) : 'null'));
        }
        return putString.call(this, key, value);
      };
    },
    onComplete: function () {},
  });

  // ── File writes ───────────────────────────────────────────
  try {
    var FileOutputStream = Java.use('java.io.FileOutputStream');

    FileOutputStream.$init.overload('java.lang.String').implementation = function (path) {
      console.log('[F-002] FileOutputStream opened: ' + path);
      return this.$init(path);
    };

    FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
      console.log('[F-002] FileOutputStream opened: ' + file.getAbsolutePath());
      return this.$init(file);
    };
  } catch (e) {
    console.log('[F-002] FileOutputStream hook failed: ' + e);
  }

  // ── SQLite writes ─────────────────────────────────────────
  try {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');

    SQLiteDatabase.insert.implementation = function (table, nullColHack, values) {
      console.log('[F-002] SQLiteDatabase.insert() table: ' + table);
      if (values) {
        var keys = values.keySet().toArray();
        for (var i = 0; i < keys.length; i++) {
          var k = keys[i];
          var v = values.get(k);
          var isSensitive = sensitiveKeys.some(s => String(k).toLowerCase().includes(s));
          if (isSensitive) {
            console.log('[F-002]    ⚠️  ' + k + ' = ' + v);
          }
        }
      }
      return this.insert(table, nullColHack, values);
    };

    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
      // Look for INSERT/UPDATE of sensitive data
      if (/INSERT|UPDATE/i.test(sql)) {
        console.log('[F-002] SQLiteDatabase.execSQL: ' + sql.substring(0, 100));
      }
      return this.execSQL(sql);
    };
  } catch (e) {
    console.log('[F-002] SQLiteDatabase hook failed: ' + e);
  }

  // ── Keystore (positive — should be used for secrets) ──────
  try {
    var KeyStore = Java.use('java.security.KeyStore');

    KeyStore.setEntry.implementation = function (alias, entry, protParam) {
      console.log('[F-002] ✅  KeyStore.setEntry() alias: ' + alias);
      return this.setEntry(alias, entry, protParam);
    };
  } catch (e) {}

  console.log('[F-002] Storage hooks active. Interact with the app now.');
});
