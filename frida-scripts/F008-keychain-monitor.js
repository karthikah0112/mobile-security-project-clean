// ============================================================
// F008-keychain-monitor.js — Monitor iOS Keychain operations
// Finding: F-008 — Keychain Items Use kSecAttrAccessibleAlways
// Usage: frida -U -f com.demobank.app -l F008-keychain-monitor.js
// Platform: iOS only
// ============================================================

if (ObjC.available) {
  console.log('[F-008] iOS Keychain Monitor loaded');

  var Security = Module.findBaseAddress('Security');
  if (!Security) {
    console.log('[F-008] Security framework not found');
  } else {

    // ── Accessibility constants (from Security.framework) ────
    // Values of kSecAttrAccessible
    var ACCESS_LEVELS = {
      'ak':    'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly  ✅ BEST',
      'ck':    'kSecAttrAccessibleWhenUnlockedThisDeviceOnly     ✅ GOOD',
      'dk':    'kSecAttrAccessibleWhenUnlocked                   ⚠️  OK (allows backup)',
      'ak~':   'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly ⚠️  OK',
      'dk~':   'kSecAttrAccessibleAfterFirstUnlock               ⚠️  Allows backup',
      'dku':   'kSecAttrAccessibleAlwaysThisDeviceOnly           ⚠️  Weak',
      'aku':   'kSecAttrAccessibleAlways                         🚨 INSECURE — allows backup!',
    };

    // ── Hook SecItemAdd ───────────────────────────────────────
    var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
    if (SecItemAdd) {
      Interceptor.attach(SecItemAdd, {
        onEnter: function (args) {
          var query = ObjC.Object(args[0]);
          console.log('\n[F-008] SecItemAdd() called');
          analyzeKeychainQuery(query);
        },
        onLeave: function (retval) {
          var status = retval.toInt32();
          console.log('[F-008] SecItemAdd result: ' + (status === 0 ? '✅ errSecSuccess' : '❌ ' + status));
        },
      });
    }

    // ── Hook SecItemUpdate ────────────────────────────────────
    var SecItemUpdate = Module.findExportByName('Security', 'SecItemUpdate');
    if (SecItemUpdate) {
      Interceptor.attach(SecItemUpdate, {
        onEnter: function (args) {
          var query = ObjC.Object(args[0]);
          console.log('\n[F-008] SecItemUpdate() called');
          analyzeKeychainQuery(query);
        },
      });
    }

    // ── Hook SecItemCopyMatching (reads) ──────────────────────
    var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
    if (SecItemCopyMatching) {
      Interceptor.attach(SecItemCopyMatching, {
        onEnter: function (args) {
          var query = ObjC.Object(args[0]);
          this.resultPtr = args[1];

          // Get service name if present
          try {
            var service = query.objectForKey_(ObjC.classes.NSString.stringWithString_('svce'));
            if (service) {
              console.log('\n[F-008] SecItemCopyMatching() — reading: ' + service.toString());
            }
          } catch (e) {}
        },
        onLeave: function (retval) {
          var status = retval.toInt32();
          if (status === 0 && this.resultPtr) {
            try {
              var result = new ObjC.Object(this.resultPtr.readPointer());
              console.log('[F-008] SecItemCopyMatching result: ' + result.toString().substring(0, 100));
            } catch (e) {}
          }
        },
      });
    }

    // ── Helper: analyze query dict for accessibility level ────
    function analyzeKeychainQuery(query) {
      try {
        // Check kSecAttrAccessible
        var accessible = query.objectForKey_(ObjC.classes.NSString.stringWithString_('pdmn'));
        if (accessible) {
          var level = accessible.toString();
          var desc  = ACCESS_LEVELS[level] || 'Unknown: ' + level;
          console.log('[F-008]    kSecAttrAccessible: ' + desc);
          if (level === 'aku') {
            console.log('[F-008]    🚨 VULNERABLE: kSecAttrAccessibleAlways allows iCloud backup!');
          }
        }

        // Check kSecAttrService
        var service = query.objectForKey_(ObjC.classes.NSString.stringWithString_('svce'));
        if (service) console.log('[F-008]    kSecAttrService (key name): ' + service.toString());

        // Check kSecAttrAccount
        var account = query.objectForKey_(ObjC.classes.NSString.stringWithString_('acct'));
        if (account) console.log('[F-008]    kSecAttrAccount: ' + account.toString());

      } catch (e) {
        console.log('[F-008] Query analysis error: ' + e);
      }
    }

    console.log('[F-008] Keychain hooks active. Log in to the app to trigger Keychain operations.');
  }
} else {
  console.log('[F-008] ObjC not available — this script requires iOS.');
}
