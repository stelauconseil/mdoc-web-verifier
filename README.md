# ISO 18013-5 Web Verifier (mDL Reader)

A single-page web application that implements ISO 18013-5 mobile Driver's License (mDL) reader functionality directly in the browser using Web Bluetooth. It scans QR codes, connects over BLE, establishes a secure session, and exchanges encrypted mDL data.

This project is intentionally self-contained: everything lives in a single `index.html` file (HTML, CSS, and JavaScript). No build step is required.

## Features

- QR code scanning (camera) to extract Device Engagement data
- Web Bluetooth GATT communication with the wallet device
- ISO 18013-5 compliant session establishment
- AES-256-GCM encryption with per-spec IV generation
- CBOR encoding/decoding for protocol messages
- Diagnostics view and extensive console logging
- Works in modern Chromium browsers (secure context / HTTPS required)

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

1. Open the app over HTTPS in a supported browser.
2. Click Scan QR and present the wallet’s Device Engagement QR (or paste an `mdoc://` URI if supported).
3. The app parses Device Engagement to find BLE options (service UUID and optional address).
4. Click Connect to establish a GATT connection to the wallet.
5. The protocol state machine starts; the session is established by exchanging ephemeral keys.
6. Select which document fields to request and send the request.
7. Approve the request on the wallet app; the response is received and decrypted.
8. Use the Diagnostics button and browser DevTools for detailed logs and session info.

## Architecture overview

This project follows a single-file architecture. Everything resides in `index.html` and is loaded directly in the browser via CDNs.

- index.html — full app with UI, BLE, crypto, CBOR, and QR logic

Key external dependencies (CDN):

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

- index.html — entire application (HTML/CSS/JS)

There is no build system; the page runs directly in the browser.

## Roadmap / ideas

- Reader authentication (optional per ISO 18013-5)
- UX improvements and field presets
- Additional wallet compatibility tests
- Automated tests for crypto and CBOR encoding

## Contributing

Contributions and bug reports are welcome. Given the single-file architecture, please keep changes scoped and well-commented. If adding new flows or external dependencies, prefer CDN-based, widely-used libraries and document the rationale in this README.
