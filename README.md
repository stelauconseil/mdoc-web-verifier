# ISO 18013-5 Web Verifier (mDL Reader)

A single-page **Progressive Web App (PWA)** that implements ISO 18013-5 mobile Driver's License (mDL) reader functionality directly in the browser using Web Bluetooth. It scans QR codes, connects over BLE, establishes a secure session, and exchanges encrypted mDL data.

This project is intentionally self-contained and has **no build step**. The UI lives in `index.html` and the logic is organized into small feature files under `js/`. **Install it as an app** for offline access and a native-like experience!

## Features

- 📱 **Progressive Web App** - Install on desktop or mobile, works offline with elegant status badge
- 📷 QR code scanning (camera) to extract Device Engagement data
- 🔵 Web Bluetooth GATT communication with the wallet device
- 🔐 ISO 18013-5 compliant session establishment
- 🔒 AES-256-GCM encryption with per-spec IV generation
- 📦 CBOR encoding/decoding for protocol messages
- 🔍 X.509 certificate validation with IACA trust anchors
- ✅ COSE_Sign1 verification using @noble/curves (ES256/ES384/ES512) with DER→raw conversion and low‑S normalization
- 🧭 IACA selection via AKI/SKI matching, OID-based curve/hash detection
- � Per-document Verification Status (Signature/Chain) with effective algorithm + curve display
- 📄 MSO viewer with classic toggle/copy and decoded JSON (bytes rendered as base64)
- �🛠️ Diagnostics view and extensive console logging
- ⚡ Fast loading with intelligent Service Worker caching strategies
- 🔔 Automatic update notifications when new versions are available
- ✨ Glassmorphic floating badge showing app status (installed/offline mode)
- 🌐 Works in modern Chromium browsers (secure context / HTTPS required)

## PWA Installation

### Quick Install

1. Visit the app over HTTPS
2. Look for the **install prompt** or click the ⊕ icon in the address bar
3. Click **"Install"** to add it to your device
4. Enjoy the native app experience with a floating status badge showing "✨ Installed App"

### Benefits of Installing

- ✅ **Works offline** - Full functionality after first visit
- ✅ **Instant loading** - Cached assets for near-instant startup
- ✅ **Native experience** - Fullscreen without browser UI
- ✅ **Visual feedback** - Elegant floating badge shows app/offline status
- ✅ **Auto updates** - Get notified when updates are available
- ✅ **Quick access** - Launch from home screen or desktop

### PWA Status Badge

When installed or running with offline support, a beautiful floating badge appears in the top-right corner:

- **✨ Installed App** (green) - Running as installed PWA
- **🔄 Offline Ready** (blue) - Service Worker active, offline support enabled

The badge uses a glassmorphic design with backdrop blur and smooth slide-in animation. On mobile, it automatically scales down for better usability.

If you want to explore PWA capabilities locally, see `pwa-test.html` in this repo for quick checks (HTTPS, SW, manifest, install status).

## Quickstart

Because Web Bluetooth requires a secure context, you must serve this page over HTTPS (file:// won’t work). Below are a few options for local development on macOS.

### Option A: Caddy (automatic local TLS)

1. Install Caddy (one-time):

- brew install caddy

2. Start a file server from this folder:

- caddy file-server --browse --listen :8443

3. Open https://localhost:8443 in Chrome.

Note: The browser may prompt to trust Caddy’s local CA on first run.

### Option B: mkcert + http-server

1. Install prerequisites (one-time):

- brew install mkcert nss
- mkcert -install

2. Generate a localhost certificate in this folder:

- mkcert localhost
  This creates `localhost.pem` and `localhost-key.pem`.

3. Serve over HTTPS using any static server. For example, with http-server:

- npx http-server -S -C localhost.pem -K localhost-key.pem -p 8443

4. Open https://localhost:8443 in Chrome.

> Tip: You can also host this on any HTTPS-capable static site (e.g., GitHub Pages). Ensure the origin is secure and Web Bluetooth is allowed.

## Browser requirements

- Chromium-based browser (Chrome/Edge) on desktop
- Secure context (HTTPS)
- Camera permission (for QR scanning)
- Bluetooth permission (for BLE connection)
- On macOS, some advertising APIs require Chrome Canary + flags; standard GATT connections work on stable Chrome

## Using the app

### Normal Usage Flow

1. Open the app over HTTPS in a supported browser.
2. **(Optional)** Install the app for offline access and native experience.
3. Select which document fields to request and send the request.
4. Click **Scan QR** and present the wallet's Device Engagement QR (or paste an `mdoc://` URI if supported).
5. The app parses Device Engagement to find BLE options (service UUID and optional address).
6. Click **Connect** to establish a GATT connection to the wallet.
7. The protocol state machine starts; the session is established by exchanging ephemeral keys.
8. Approve the request on the wallet app; the response is received and decrypted.
9. Use the **Diagnostics** button and browser DevTools for detailed logs and session info.

### Testing PWA Features

Visit **pwa-test.html** to verify PWA functionality:

- ✅ Check HTTPS and browser API support
- ✅ Verify Service Worker registration
- ✅ Test manifest loading and parsing
- ✅ Check installation status
- ✅ Inspect cache contents
- 🛠️ Debug utilities (unregister SW, clear cache)

Or run a Lighthouse audit in Chrome DevTools for a comprehensive PWA score.

## Architecture overview

This project follows a self-contained, browser-run architecture with Progressive Web App enhancements. The core UI resides in `index.html` and feature logic is split across a few small files in `js/`. Everything loads directly in the browser (no bundler).

### Core Files

- **index.html** — UI, wiring, and PWA integration
- **js/activity-log.js** — UI logging helpers
- **js/device-engagement.js** — Parse mdoc URI + Device Engagement, BLE options, eSenderKey
- **js/request-builder.js** — Build document requests (mDL, EU PID, Age/Photo ID, mICOV, mVC)
- **js/wallet-response.js** — Decrypt/display responses, Verification Status, MSO viewer
- **js/iaca-management.js** — IACA storage and selection (AKI/SKI)
- **noble-curves.min.js** — Local ECDSA verification library (@noble/curves)
- **manifest.json** — Web app manifest for PWA installation (name, icons, theme)
- **sw.js** — Service Worker with intelligent caching strategies
- **assets/icon-192.png** / **assets/icon-512.png** — App icons

### PWA Architecture

- **Cache Strategy**:
  - Cache-first for app shell (instant loading)
  - Network-first for CDN resources (always fresh with fallback)
  - Runtime caching for visited resources
- **Update Mechanism**: Version-based cache invalidation with user notifications
- **Offline Support**: Full functionality preserved with cached assets

### Key Dependencies

- jsQR@1.4.0 (CDN) — QR code scanning via camera frames
- cbor-web@9.0.2 (CDN) — CBOR encoding/decoding for ISO 18013-5
- @noble/curves (local `noble-curves.min.js`) — COSE_Sign1 ECDSA verification (P‑256/384/521 + brainpool mapping)
- Web Crypto API — ECDH, HKDF, AES‑GCM
- Web Bluetooth API — BLE GATT communication

## Development guide

Adding new request types:

- In `buildRequestByType()`, add a new case and set fields to true to request (false = intent‑to‑retain only). Existing builders cover mDL, EU PID, age verification, photo ID, mICOV, and mVC.

Supporting new document types:

- Update `docType` and `nameSpaces` accordingly, e.g.:
  - `baseRequest.docRequests[0].itemsRequest.docType = "your.new.doctype"`
  - `baseRequest.docRequests[0].itemsRequest.nameSpaces = { "your.new.namespace": {} }`

Debugging tips:

- Use the Diagnostics button to view the full system state
- Open DevTools and inspect:
  - `window.sessionDebug.skReader` / `skDevice`
  - `window.sessionDebug.lastEncrypt`
  - `window.sessionEstablished`
- Watch the Web Bluetooth connection state in DevTools

Common issues:

- No prompt on wallet: ensure requested fields are set to true
- Connection drops: wallets often disconnect between operations (normal)
- Wrong docType: must exactly match wallet’s supported types
- Encryption mismatch: verify SessionTranscript and IV construction

## Security considerations

- Reader authentication is not implemented (readerAuth: null)
- Session keys are kept only in memory and cleared on page reload
- IV generation follows ISO 18013-5 (identifier(8) || counter(4))
- Transcript AAD uses the SessionTranscript hash per spec
- Use only in secure contexts; do not expose secrets or keys

## Browser flags (macOS)

- HTTPS is required for Web Bluetooth
- For certain advertising APIs on macOS, Chrome Canary + experimental flags may be necessary
- Standard GATT usage typically works on stable Chrome without flags

## Project structure

```
mdoc-web-verifier/
├── index.html               # Main UI, wiring, PWA integration
├── js/
│   ├── activity-log.js     # UI logging
│   ├── device-engagement.js# DeviceEngagement + BLE options
│   ├── iaca-management.js  # IACA trust store helpers
│   ├── request-builder.js  # Request builders (mDL, EU PID, age, photo, mICOV, mVC)
│   └── wallet-response.js  # Decrypt/display, verification, MSO viewer
├── noble-curves.min.js     # @noble/curves (local)
├── assets/
│   ├── icon-192.png        # App icon (192×192)
│   └── icon-512.png        # App icon (512×512)
├── manifest.json           # PWA manifest
├── sw.js                   # Service Worker
├── pwa-test.html           # PWA testing utilities
├── backup/                 # Saved snapshots of index.html
└── README.md               # This file
```

There is no build system; the page runs directly in the browser. PWA features work seamlessly without compilation or bundling.

## Roadmap / ideas

- ✅ ~~Progressive Web App support~~ (Completed!)
- ✅ ~~Offline functionality~~ (Completed!)
- ✅ ~~Install prompts and update notifications~~ (Completed!)
- Reader authentication (optional per ISO 18013-5)
- UX improvements and field presets
- Additional wallet compatibility tests
- Automated tests for crypto and CBOR encoding

## Contributing

Contributions and bug reports are welcome. Given the no-build, browser-run architecture, please keep changes scoped and well‑commented. If adding new flows or external dependencies, prefer CDN‑based or single-file libraries and document the rationale in this README.

---

### CHANGES

#### version 19

- Split the monolith into clear modules under `js/` while keeping zero build.
- COSE_Sign1 verification via @noble/curves with DER→raw conversion and low‑S normalization.
- OID‑based curve/hash detection; IACA selection via AKI/SKI.
- ES384 support end‑to‑end (and ES512 when curve dictates); display effective algorithm and curve.
- Fixed SessionEstablishment.data to use raw AES‑GCM output (ciphertext || tag) per ISO 18013‑5.
- Restored and improved UI: per‑document Verification Status and classic MSO viewer with decoded JSON and copy.
