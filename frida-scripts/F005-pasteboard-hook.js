// ============================================================
// F005-pasteboard-hook.js — Monitor iOS Pasteboard writes
// Finding: F-005 — Auth Token Written to iOS Pasteboard
// Usage: frida -U -f com.demobank.app -l F005-pasteboard-hook.js
// Platform: iOS only
// ============================================================

if (ObjC.available) {
  console.log('[F-005] iOS Pasteboard Monitor loaded');

  var UIPasteboard = ObjC.classes.UIPasteboard;
  if (!UIPasteboard) {
    console.log('[F-005] UIPasteboard not found — is this an iOS device?');
  } else {

    // ── Hook setString: ───────────────────────────────────────
    var setString = UIPasteboard['- setString:'];
    if (setString) {
      Interceptor.attach(setString.implementation, {
        onEnter: function (args) {
          var value = ObjC.Object(args[2]).toString();
          console.log('\n[F-005] ⚠️  UIPasteboard.setString() called!');
          console.log('[F-005]    Value: ' + value.substring(0, 120));
          if (value.toLowerCase().startsWith('bearer ') || value.length > 40) {
            console.log('[F-005]    🚨 POTENTIAL AUTH TOKEN WRITTEN TO PASTEBOARD!');
          }
          console.log('[F-005]    Stack: ' + Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n           '));
        },
      });
    }

    // ── Hook setValue:forPasteboardType: ──────────────────────
    var setValue = UIPasteboard['- setValue:forPasteboardType:'];
    if (setValue) {
      Interceptor.attach(setValue.implementation, {
        onEnter: function (args) {
          var value = ObjC.Object(args[2]);
          var type  = ObjC.Object(args[3]).toString();
          console.log('\n[F-005] UIPasteboard.setValue:forPasteboardType:');
          console.log('[F-005]    Type:  ' + type);
          console.log('[F-005]    Value: ' + value.toString().substring(0, 120));
        },
      });
    }

    // ── Hook setItems: ────────────────────────────────────────
    var setItems = UIPasteboard['- setItems:'];
    if (setItems) {
      Interceptor.attach(setItems.implementation, {
        onEnter: function (args) {
          var items = ObjC.Object(args[2]);
          console.log('\n[F-005] UIPasteboard.setItems: ' + items.toString().substring(0, 200));
        },
      });
    }

    // ── Monitor reads (background snooping simulation) ────────
    var getString = UIPasteboard['- string'];
    if (getString) {
      Interceptor.attach(getString.implementation, {
        onLeave: function (retval) {
          if (retval) {
            var val = ObjC.Object(retval).toString();
            if (val && val.length > 0) {
              console.log('\n[F-005] UIPasteboard.string READ: ' + val.substring(0, 80));
            }
          }
        },
      });
    }

    console.log('[F-005] Pasteboard hooks active. Trigger a copy action in the app.');
  }
} else {
  console.log('[F-005] ObjC not available — this script requires iOS.');
}
