# ISO 18013-5 Web Verifier (mDL Reader)

A single-page **Progressive Web App (PWA)** that implements ISO 18013-5 mobile Driver's License (mDL) reader functionality directly in the browser using Web Bluetooth. It scans QR codes, connects over BLE, establishes a secure session, and exchanges encrypted mDL data.

This project is intentionally self-contained: everything lives in a single `index.html` file (HTML, CSS, and JavaScript). No build step is required. **Install it as an app** for offline access and native-like experience!

## Features

- 📱 **Progressive Web App** - Install on desktop or mobile, works offline with elegant status badge
- 📷 QR code scanning (camera) to extract Device Engagement data
- 🔵 Web Bluetooth GATT communication with the wallet device
- 🔐 ISO 18013-5 compliant session establishment
- 🔒 AES-256-GCM encryption with per-spec IV generation
- 📦 CBOR encoding/decoding for protocol messages
- 🔍 X.509 certificate validation with IACA trust anchors
- 🛠️ Diagnostics view and extensive console logging
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

See [PWA_SETUP.md](PWA_SETUP.md) for detailed installation and development guide, or [PWA_README.md](PWA_README.md) for a quick overview of all PWA features.

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
3. Click **Scan QR** and present the wallet's Device Engagement QR (or paste an `mdoc://` URI if supported).
4. The app parses Device Engagement to find BLE options (service UUID and optional address).
5. Click **Connect** to establish a GATT connection to the wallet.
6. The protocol state machine starts; the session is established by exchanging ephemeral keys.
7. Select which document fields to request and send the request.
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

This project follows a single-file architecture with Progressive Web App enhancements. The core app resides in `index.html` and is loaded directly in the browser via CDNs.

### Core Files

- **index.html** — Full app with UI, BLE, crypto, CBOR, QR logic, and PWA integration
- **manifest.json** — Web app manifest for PWA installation (name, icons, theme)
- **sw.js** — Service Worker with intelligent caching strategies
- **icon-192.svg** / **icon-512.svg** — App icons with branded design

### PWA Architecture

- **Cache Strategy**:
  - Cache-first for app shell (instant loading)
  - Network-first for CDN resources (always fresh with fallback)
  - Runtime caching for visited resources
- **Update Mechanism**: Version-based cache invalidation with user notifications
- **Offline Support**: Full functionality preserved with cached assets

### Key External Dependencies (CDN)

- jsQR@1.4.0 — QR code scanning via camera frames
- cbor-web@9.0.2 — CBOR encoding/decoding for ISO 18013-5
- Web Crypto API — ECDH, HKDF, AES-GCM
- Web Bluetooth API — BLE GATT communication

## Protocol highlights (ISO 18013-5)

### 1) Device Engagement processing

- `extractCborFromMdocUri(uri)` — extracts CBOR from mdoc URIs (including data URIs, hex/base64)
- `parseMdocUriAndDE(uri)` — parses CBOR into (service UUID, mdoc public key)
- `tryExtractBleOptions(root)` — finds BLE service UUID (DE field 10/11) and optional address (field 20)

### 2) Session establishment

- Ephemeral key pair: `makeReaderEphemeralKeyPair()` (P-256 ECDH)
- Transcript AAD: `buildTranscriptAAD()` (SessionTranscript = [DeviceEngagement, EReaderKey, Handover])
- Session keys: `deriveSessionKey()` via HKDF → SKReader (requests) + SKDevice (responses)

SessionEstablishment object per spec:

- eReaderKey: tag(24, bstr .cbor COSE_Key)
- data: bstr (encrypted request payload)

### 3) Encryption model

- Algorithm: AES-256-GCM (NIST SP 800-38D)
- Reader encrypts requests with SKReader
- mdoc encrypts responses with SKDevice
- IV: 12 bytes = identifier(8) || counter(4 big-endian)
  - Reader identifier: 00 00 00 00 00 00 00 00
  - mdoc identifier: 00 00 00 00 00 00 00 01
  - Message counter starts at 1; increment before each subsequent encryption with the same key
- AAD: empty
- Output: ciphertext || 16-byte tag

Most request/response payloads are wrapped in COSE_Encrypt0. The notable exception is SessionEstablishment.data (see below).

## Important compatibility note: SessionEstablishment.data format

Some wallets (e.g., Multipaz) expect the SessionEstablishment `data` field to be the raw AES-GCM output (ciphertext || tag), not a COSE_Encrypt0 structure. The ISO 18013-5 spec states that the value shall be the concatenation of the ciphertext and all 16 bytes of the authentication tag.

Implemented fix in this project:

- The `buildLegacySessionEstablishmentWithData()` path uses raw AES-GCM output for `data`.
- A helper such as `aesGcmEncryptRaw()` returns the raw bytes (ciphertext || auth_tag) using the per-spec IV derivation.
- Regular encrypted requests/responses after SessionEstablishment still use COSE_Encrypt0.

Testing checklist:

- data starts with ciphertext (not a CBOR array marker 0x83)
- length = plaintext_length + 16 bytes
- IV = identifier(8) || counter(4), big-endian
- AAD = empty

## BLE communication flow

1. QR scan → extract BLE service UUID from Device Engagement
2. BLE connect → GATT with 3 characteristics (state, C2S, S2C)
3. State machine → writeState(0x01) to start protocol
4. Session establishment → exchange ephemeral keys
5. Encrypted requests → send document requests

Protocol state machine:

- IDLE (0x00) → START (0x01) → DATA_TRANSFER → END (0x02)

## Development guide

Adding new request types:

- In `buildRequestByType()`, add a new case and set fields to true to request (false = intent-to-retain only).

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
├── index.html              # Main application (HTML/CSS/JS)
├── manifest.json           # PWA manifest (app metadata)
├── sw.js                   # Service Worker (offline support)
├── icon-192.svg            # App icon (192×192)
├── icon-512.svg            # App icon (512×512)
├── generate-icons.sh       # Script to generate PNG icons
├── pwa-test.html          # PWA testing utilities
├── PWA_SETUP.md           # Comprehensive PWA guide
├── PWA_CONVERSION.md      # Technical PWA documentation
├── PWA_README.md          # Quick PWA overview
└── README.md              # This file
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
- Push notifications for updates (requires backend)
- Share target API for receiving QR codes from other apps

## Contributing

Contributions and bug reports are welcome. Given the single-file architecture, please keep changes scoped and well-commented. If adding new flows or external dependencies, prefer CDN-based, widely-used libraries and document the rationale in this README.
