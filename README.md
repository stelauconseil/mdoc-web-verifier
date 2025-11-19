# ISO 18013-5 Web Verifier (mDL Reader)

A single-page web app that reads ISO 18013-5 mobile Driver’s License (mDL) mDoc over Web Bluetooth. It scans the wallet’s Device Engagement QR, connects via BLE, establishes a secure session, and verifies COSE_Sign1 with X.509 trust anchors.

- No build step. Runs directly in the browser.
- Optional install as a PWA for offline use.

## Requirements

- Chromium browser (Chrome/Edge) over HTTPS
- Camera access (QR scan) and Bluetooth access (BLE)
- The wallet must implement “Server Peripheral” over BLE as defined by ISO 18013-5

## Quick start

1. Open the app over HTTPS.
2. Click Scan QR and show the wallet’s Device Engagement QR (or paste an mdoc:// URI).
3. Connect over BLE when prompted; approve on the wallet.
4. View the response and verification status in the UI.

Tips

- Use Diagnostics for logs and session details.
- Wallets may disconnect between steps; reconnect as needed.

## Features (short)

- QR scan → BLE connect → secure session (AES‑GCM with spec IV)
- COSE_Sign1 verification via @noble/curves (ES256/ES384/ES512), DER→raw, low‑S
- Reader authentication
- IACA trust store with AKI/SKI matching and OID-driven curve/hash detection
- Classic MSO viewer and per-document Verification Status
- Request presets incl. mDL, EU PID, age/photo ID, mICOV, mVC

## VICAL (Verified Issuer CA List)

You can bulk‑import issuer CAs:

- Import from file: preferred and most reliable.
- Import from URI: supported; the app handles CBOR/COSE/CWT, JSON, data URIs, and base64 blobs. It retries transient HTTP errors (503/5xx/429) and optionally supports a CORS proxy via `opts.corsProxyBase` if the server blocks cross‑origin requests. If fetch is blocked or unstable, download the file and use Import from file instead.

Example URI:

- https://nzta.mdoc.online/NZTATestVical.vical
- https://vical.dts.aamva.org/vical/vc/vc-2025-09-27-1758957681255

The import summary shows imported, skipped (duplicates), unknown (non‑cert entries), and errors.

## Security notes

- Session keys kept in memory only; cleared on reload
- SessionEstablishment.data uses raw AES‑GCM ciphertext||tag per ISO 18013‑5

## Troubleshooting

- CORS/503 when importing by URI → try again (automatic retries), or import by file; optionally pass a CORS proxy.
- No prompt on the wallet → ensure requested fields are set to true.
- Wrong docType → match the wallet’s exact supported type.
- BLE disconnects → normal behavior for some wallets; reconnect.

## Files

- index.html — UI and wiring
- js/ — feature modules (device engagement, requests, responses, IACA, logs)
- sw.js / manifest.json — optional PWA

## Recent changes

- VICAL import by URI is more robust: content‑type aware (CBOR/COSE/JSON), retry/backoff for 503/5xx/429, optional CORS proxy fallback; import by file unchanged.
