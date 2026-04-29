"""
test_api.py — PhishGuard v2.1 test suite
Run while server is live:
  uvicorn main:app --reload --port 8000
  python test_api.py
"""

import sys
import requests

BASE = "http://localhost:8000"

# ─────────────────────────────────────────────────────────────────────────────
# Test cases
# Each entry: name, expected verdict, payload
# ─────────────────────────────────────────────────────────────────────────────
TESTS = [
    # ── PHISHING ─────────────────────────────────────────────────────────────
    {
        "name":   "PHISHING — IP address URL + no HTTPS + password + hidden iframes",
        "expect": "PHISHING",
        "payload": {
            "url": "http://192.168.1.1/paypal/secure-login",
            "phishingMetrics": {"flags": {"noHttps": True}},
            "content": {
                "wordsCount": 60, "linkCount": 3, "paragraphCount": 0,
                "iframeCount": 2, "hiddenframesCount": 2, "imagecount": 3,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": True, "hasEmailField": True,
                "hiddenFieldCount": 5, "crossdomain": 1,
            },
            "scripts": {"externalScriptCount": 8, "inlineScriptCount": 20},
            "cookies": {"cookieCount": 18},
            "behavior": {"timeOnPage": 1200, "scrollDepth": 10, "clickCount": 0},
        },
    },
    {
        "name":   "PHISHING — shortened URL + @ in URL (email injection)",
        "expect": "PHISHING",
        "payload": {
            "url": "http://bit.ly/3xAbc12?redirect=http://evil.com@paypal.com/login",
            "phishingMetrics": {"flags": {"noHttps": True}},
            "content": {
                "wordsCount": 40, "linkCount": 2, "paragraphCount": 0,
                "iframeCount": 0, "hiddenframesCount": 0,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": True, "hasEmailField": False,
                "hiddenFieldCount": 0, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 1},
            "cookies": {"cookieCount": 2},
            "behavior": {"timeOnPage": 800, "scrollDepth": 5, "clickCount": 0},
        },
    },
    {
        "name":   "PHISHING — cross-domain form action (credential harvest)",
        "expect": "PHISHING",
        "payload": {
            "url": "http://secure-bank-login.com/account/verify",
            "phishingMetrics": {"flags": {"noHttps": True}},
            "content": {
                "wordsCount": 80, "linkCount": 4, "paragraphCount": 0,
                "iframeCount": 0, "hiddenframesCount": 0,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": True, "hasEmailField": True,
                "hiddenFieldCount": 6, "crossdomain": 1,
            },
            "scripts": {"externalScriptCount": 2},
            "cookies": {"cookieCount": 4},
            "behavior": {"timeOnPage": 600, "scrollDepth": 15, "clickCount": 0},
        },
    },
    {
        "name":   "PHISHING — raw IP + many hidden inputs + no paragraphs",
        "expect": "PHISHING",
        "payload": {
            "url": "http://10.0.0.5/amazon/signin",
            "phishingMetrics": {"flags": {"noHttps": True}},
            "content": {
                "wordsCount": 50, "linkCount": 1, "paragraphCount": 0,
                "iframeCount": 0, "hiddenframesCount": 0,
            },
            "formData": {
                "formCount": 2, "hasPasswordField": True, "hasEmailField": True,
                "hiddenFieldCount": 8, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 1},
            "cookies": {"cookieCount": 1},
            "behavior": {"timeOnPage": 300, "scrollDepth": 5, "clickCount": 0},
        },
    },

    # ── SUSPICIOUS ────────────────────────────────────────────────────────────
    {
        "name":   "SUSPICIOUS — lookalike domain + no HTTPS + password field",
        "expect": "SUSPICIOUS",
        "payload": {
            "url": "http://paypa1-secure.verify-account.net/confirm?token=abc123",
            "phishingMetrics": {"flags": {"noHttps": True}},
            "content": {
                "wordsCount": 120, "linkCount": 8, "paragraphCount": 1,
                "iframeCount": 0, "hiddenframesCount": 0,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": True, "hasEmailField": True,
                "hiddenFieldCount": 2, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 2},
            "cookies": {"cookieCount": 3},
            "behavior": {"timeOnPage": 4200, "scrollDepth": 30, "clickCount": 1},
        },
    },
    {
        "name":   "SUSPICIOUS — very long URL with many params",
        "expect": "SUSPICIOUS",
        "payload": {
            "url": (
                "https://login-verify-your-account-now.suspicious-domain.xyz"
                "/secure/verify?user=john&token=XYZ&redirect=http://evil.com"
                "&session=abcde12345&extra=padding_to_make_long"
            ),
            "phishingMetrics": {"flags": {"noHttps": False}},
            "content": {
                "wordsCount": 200, "linkCount": 10, "paragraphCount": 1,
                "iframeCount": 0, "hiddenframesCount": 0,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": True, "hasEmailField": False,
                "hiddenFieldCount": 3, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 3},
            "cookies": {"cookieCount": 5},
            "behavior": {"timeOnPage": 2000, "scrollDepth": 20, "clickCount": 1},
        },
    },
    {
        "name":   "SUSPICIOUS — sparse content + form + many external scripts",
        "expect": "SUSPICIOUS",
        "payload": {
            "url": "https://not-quite-right.com/login",
            "phishingMetrics": {"flags": {"noHttps": False}},
            "content": {
                "wordsCount": 90, "linkCount": 5, "paragraphCount": 0,
                "iframeCount": 0, "hiddenframesCount": 0,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": True, "hasEmailField": False,
                "hiddenFieldCount": 1, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 6},
            "cookies": {"cookieCount": 2},
            "behavior": {"timeOnPage": 1500, "scrollDepth": 25, "clickCount": 0},
        },
    },

    # ── LEGITIMATE ────────────────────────────────────────────────────────────
    {
        "name":   "LEGITIMATE — video platform (many links + HTTPS)",
        "expect": "LEGITIMATE",
        "payload": {
            "url": "https://example-video-platform.com/watch?v=SAMPLE001",
            "phishingMetrics": {"flags": {"noHttps": False, "manyLinks": True}},
            "content": {
                "wordsCount": 380, "linkCount": 175, "paragraphCount": 2,
                "iframeCount": 1, "hiddenframesCount": 0, "imagecount": 120,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": False, "hasEmailField": False,
                "hiddenFieldCount": 0, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 3, "inlineScriptCount": 30},
            "cookies": {"cookieCount": 10},
            "behavior": {"timeOnPage": 15400, "scrollDepth": 85, "clickCount": 3},
        },
    },
    {
        "name":   "LEGITIMATE — e-commerce product page",
        "expect": "LEGITIMATE",
        "payload": {
            "url": "https://shop.example.com/products/laptop-pro-15?ref=sale&utm_source=email",
            "phishingMetrics": {"flags": {"noHttps": False}},
            "content": {
                "wordsCount": 600, "linkCount": 80, "paragraphCount": 8,
                "iframeCount": 0, "hiddenframesCount": 0, "imagecount": 20,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": False, "hasEmailField": False,
                "hiddenFieldCount": 2, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 4, "inlineScriptCount": 10},
            "cookies": {"cookieCount": 8},
            "behavior": {"timeOnPage": 25000, "scrollDepth": 70, "clickCount": 5},
        },
    },
    {
        "name":   "LEGITIMATE — news article (content-heavy, HTTPS)",
        "expect": "LEGITIMATE",
        "payload": {
            "url": "https://news.example.org/world/2026/04/article-title-here",
            "phishingMetrics": {"flags": {"noHttps": False}},
            "content": {
                "wordsCount": 1200, "linkCount": 40, "paragraphCount": 15,
                "iframeCount": 0, "hiddenframesCount": 0, "imagecount": 5,
            },
            "formData": {
                "formCount": 0, "hasPasswordField": False, "hasEmailField": False,
                "hiddenFieldCount": 0, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 2},
            "cookies": {"cookieCount": 4},
            "behavior": {"timeOnPage": 180000, "scrollDepth": 95, "clickCount": 2},
        },
    },
    {
        "name":   "LEGITIMATE — SaaS login page (HTTPS, minimal form, known pattern)",
        "expect": "LEGITIMATE",
        "payload": {
            "url": "https://app.myservice.io/login",
            "phishingMetrics": {"flags": {"noHttps": False}},
            "content": {
                "wordsCount": 350, "linkCount": 12, "paragraphCount": 3,
                "iframeCount": 0, "hiddenframesCount": 0,
            },
            "formData": {
                "formCount": 1, "hasPasswordField": True, "hasEmailField": True,
                "hiddenFieldCount": 1, "crossdomain": 0,
            },
            "scripts": {"externalScriptCount": 2},
            "cookies": {"cookieCount": 5},
            "behavior": {"timeOnPage": 8000, "scrollDepth": 50, "clickCount": 2},
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
def run():
    width = 60
    print("=" * width)
    print("  PhishGuard v2.1 — Test Suite")
    print("=" * width)

    # Health check
    try:
        h = requests.get(BASE + "/health", timeout=4).json()
        print(f"\n✅  API online — model: {h['model']}  "
              f"({h['features']} ML features, {h['rules']} rules)\n")
    except Exception as exc:
        print(f"\n❌  Cannot reach API at {BASE}  ({exc})")
        print("    Start it with:  uvicorn main:app --reload --port 8000\n")
        sys.exit(1)

    passed = 0
    for t in TESTS:
        try:
            resp = requests.post(BASE + "/predict", json=t["payload"], timeout=8)
            resp.raise_for_status()
            r = resp.json()
        except Exception as exc:
            print(f"❌  {t['name']}")
            print(f"   Request error: {exc}\n")
            continue

        ok     = r["verdict"] == t["expect"]
        passed += ok
        icon   = "✅" if ok else "⚠️ "

        print(f"{icon} {t['name']}")
        print(
            f"   Verdict:  {r['verdict']:<12}"
            f"(expected {t['expect']:<12})  "
            f"Risk: {r['risk']}"
        )
        print(
            f"   ML prob:  {r['ml_probability']:.2%}   "
            f"Rule score: {r['rule_score']}   "
            f"{r['latency_ms']} ms"
        )
        if r["triggered_rules"]:
            for rule in r["triggered_rules"]:
                print(f"   [{rule['severity']:<8}] {rule['rule']}  +{rule['points']}")
        print()

    print("=" * width)
    status = "🎉 All passed!" if passed == len(TESTS) else f"⚠️  {passed}/{len(TESTS)} passed"
    print(f"  {status}")
    print("=" * width)
    sys.exit(0 if passed == len(TESTS) else 1)


if __name__ == "__main__":
    run()
