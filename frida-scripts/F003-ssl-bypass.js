// ============================================================
// F003-ssl-bypass.js — SSL Certificate Pinning Bypass
// Finding: F-003 — No SSL Pinning Implemented
// Usage (Android): frida -U -f com.demobank.app -l F003-ssl-bypass.js
// Usage (iOS):     frida -U -f com.demobank.app -l F003-ssl-bypass.js
// ============================================================

// ── Detect platform ───────────────────────────────────────────
var isAndroid = Java !== undefined;

// ── Android SSL bypass ────────────────────────────────────────
if (Java.available) {
  Java.perform(function () {
    console.log('[F-003] Android SSL bypass loaded');

    // ── 1. Disable TrustManager verification ─────────────────
    try {
      var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
      var SSLContext    = Java.use('javax.net.ssl.SSLContext');

      var TrustManagerImpl = Java.registerClass({
        name: 'com.bypass.UniversalTrustManager',
        implements: [TrustManager],
        methods: {
          checkClientTrusted: function (chain, authType) {},
          checkServerTrusted: function (chain, authType) {},
          getAcceptedIssuers:  function () { return []; },
        },
      });

      var ctx = SSLContext.getInstance('TLS');
      ctx.init(null, [TrustManagerImpl.$new()], null);
      SSLContext.getDefault.implementation = function () { return ctx; };
      console.log('[F-003] ✅  TrustManager bypass active');
    } catch (e) {
      console.log('[F-003] TrustManager bypass failed: ' + e);
    }

    // ── 2. Bypass OkHttp CertificatePinner ───────────────────
    try {
      var CertificatePinner = Java.use('okhttp3.CertificatePinner');
      CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, certs) {
        console.log('[F-003] ✅  OkHttp CertificatePinner.check() bypassed for: ' + hostname);
      };
      CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, certs) {
        console.log('[F-003] ✅  OkHttp CertificatePinner.check() bypassed for: ' + hostname);
      };
    } catch (e) {
      console.log('[F-003] OkHttp pinner not found (app may not use OkHttp): ' + e);
    }

    // ── 3. Bypass Conscrypt / AndroidOpenSSL ──────────────────
    try {
      var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
      OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, authMethod) {
        console.log('[F-003] ✅  Conscrypt verifyCertificateChain bypassed');
      };
    } catch (e) {}

    // ── 4. Bypass HttpsURLConnection ──────────────────────────
    try {
      var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
      HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
        console.log('[F-003] ✅  Bypassed setDefaultHostnameVerifier');
        var AlwaysTrue = Java.registerClass({
          name: 'com.bypass.AlwaysHostnameVerifier',
          implements: [Java.use('javax.net.ssl.HostnameVerifier')],
          methods: {
            verify: function (hostname, session) {
              console.log('[F-003] HostnameVerifier.verify() for: ' + hostname + ' → true');
              return true;
            },
          },
        });
        return this.setDefaultHostnameVerifier(AlwaysTrue.$new());
      };
    } catch (e) {}

    // ── 5. Log all HTTPS URLs ─────────────────────────────────
    try {
      var URL = Java.use('java.net.URL');
      URL.openConnection.overload().implementation = function () {
        var url = this.toString();
        if (url.startsWith('https')) {
          console.log('[F-003] HTTPS request to: ' + url);
        }
        return this.openConnection();
      };
    } catch (e) {}

    console.log('[F-003] All Android SSL bypasses active.');
    console.log('[F-003] Configure Burp Suite proxy on same network and intercept traffic.');
  });
}

// ── iOS SSL bypass ────────────────────────────────────────────
if (ObjC.available) {
  console.log('[F-003] iOS SSL bypass loaded');

  // ── 1. NSURLSession delegate bypass ──────────────────────
  try {
    var NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
      // Hook didReceiveChallenge
      var hook = ObjC.classes.NSURLSessionTask['- URLSession:didReceiveChallenge:completionHandler:'];
      if (hook) {
        Interceptor.attach(hook.implementation, {
          onEnter: function (args) {
            console.log('[F-003] iOS URLSession challenge intercepted');
            var completionHandler = new ObjC.Block(args[4]);
            completionHandler(1, null); // NSURLSessionAuthChallengeCancelAuthenticationChallenge = 2, UseCredential = 0
          },
        });
      }
    }
  } catch (e) {
    console.log('[F-003] iOS URLSession hook failed: ' + e);
  }

  // ── 2. SecTrustEvaluate bypass ────────────────────────────
  try {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
        console.log('[F-003] ✅  SecTrustEvaluate bypassed');
        result.writeU32(1); // kSecTrustResultProceed
        return 0;           // errSecSuccess
      }, 'int', ['pointer', 'pointer']));
    }
  } catch (e) {
    console.log('[F-003] SecTrustEvaluate hook failed: ' + e);
  }

  // ── 3. SecTrustEvaluateWithError bypass ───────────────────
  try {
    var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithError) {
      Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
        console.log('[F-003] ✅  SecTrustEvaluateWithError bypassed');
        return 1; // true = trusted
      }, 'bool', ['pointer', 'pointer']));
    }
  } catch (e) {
    console.log('[F-003] SecTrustEvaluateWithError hook failed: ' + e);
  }

  console.log('[F-003] iOS SSL bypasses active.');
}
