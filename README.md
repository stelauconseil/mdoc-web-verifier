# ISO 18013-5 Web Verifier

This site lets you try ISO 18013-5 mobile IDs (mDL / mDoc) directly in your browser:

- Scan a wallet’s Device Engagement QR code
- Connect over Web Bluetooth
- See the verified data returned by your wallet

No account, server, or local install is required. Everything runs in your browser.

---

## Who this is for

- People testing mobile ID wallets (mDL, EUDI PID, etc.)
- Integrators who want to see what their wallet sends on real ISO 18013-5 sessions
- Researchers exploring privacy, unlinkability, and age-based attestations

You do **not** need to be a developer or to understand CBOR/COSE to use the basic flows.

---

## What you can do

### 1. Main mDL / mDoc reader (home page)

The home page (index.html) is a general-purpose ISO 18013-5 reader.

High‑level flow:

1. Open the site over HTTPS in a Chromium-based browser (Chrome / Edge).
2. Select the Digital Credentials you want to request
3. Click **Scan QR** and point the camera at the wallet’s Device Engagement QR, or paste an `mdoc://` URI.
4. When the browser asks, allow **camera** and **Bluetooth** access.
5. Select which data to request using the on‑screen options.
6. Approve the request in your wallet; the page shows the result with a clear, human‑readable layout.

Notes:

- Works with wallets that support **Server Peripheral over BLE** as defined in ISO 18013‑5.
- You can see per‑document verification status and the raw values if you want to inspect them.

### 2. Visitor Log (visitor.html)

The **Visitor Log** page is an example of how to use mobile IDs for simple check‑in / check‑out without a backend.

What it does:

- Lets visitors scan their mobile ID (EUDI PID or mDL) to create a local entry
- Stores entries **only in your browser** (no server, no upload)
- Shows a table with date, name, document type, and in/out times

How to use it:

1. Open `visitor.html` (or use the **Go to → Visitor log** menu on the home page).
2. Click **Scan QR Code** and scan the wallet’s Device Engagement QR.
3. Approve the request in the wallet.
4. The visitor is added to the log; scanning again can update their time‑out.

This page is meant to demonstrate a privacy‑respecting check‑in flow using mobile IDs without needing a server.

### 3. Attestation Unlinkability Test (unlikability_test.html)

The **Unlinkability Test** page explores how linkable different attestations from the same device are.

What it tests:

- Requests **minimal data** (for example, only `age_over_18` or `nationality`)
- Extracts the **MSO deviceKey** from each response
- Tells you whether a new scan likely came from the **same device** or a **different one**

How to use it:

1. Open `unlikability_test.html` (or use the **Go to → Unlinkability test** menu on the home page).
2. Choose what to request:
    - **EU PID : nationality**
    - **AV : age_over_18**
    - **mDL : age_over_18**
3. Click **Scan QR Code** and scan your wallet’s Device Engagement QR.
4. Approve the request in the wallet.
5. The page shows:
    - A **Holder status** message (new holder vs same holder)
    - The **Last device key** fingerprint
    - A local history of all device keys seen in this browser

No personal data or keys are sent anywhere; everything is kept in local storage and can be cleared by your browser.

---

## Supported document types

Depending on your wallet, the main reader and example pages can work with:

- **mDL** – `org.iso.18013.5.1.mDL` (Mobile Driving Licence)
- **EU PID** – `eu.europa.ec.eudi.pid.1` (Person Identification Data)
- **EU Age Verification** – `eu.europa.ec.av.1` (age‑only attestations such as `age_over_18`)
- **Photo ID** – `org.iso.23220.photoID.1` (+ related ISO 23220 namespaces)
- **mICOV** – `org.micov.1` (vaccination / test attestations)
- **mVC** – `org.iso.7367.1.mVC` (vehicle card)
- **Studend Card** - `fr.ft.hsc.1` (+ related ISO 23220 namespaces)

Your wallet may not support all of these doctypes; the app will only show data for documents actually returned by the wallet.

---

## Requirements

- Chromium browser (Chrome / Edge) over **HTTPS**
- Camera permission (for QR scanning)
- Bluetooth permission (for BLE)
- A wallet that supports ISO 18013‑5 **Server Peripheral over BLE**

If your browser does not support Web Bluetooth or you are not on HTTPS, connection will not work.

---

## Security & privacy

This verifier implements comprehensive security controls per ISO 18013-5:

### Cryptographic Verification

- **COSE_Sign1 signature verification** – Validates the issuer's digital signature on each document using ECDSA with curves P-256, P-384, P-521, and Brainpool variants
- **Certificate chain validation** – Verifies issuer certificates against trusted IACA (Issuer Authority Certificate Authority) root certificates with automatic AKI/SKI matching
- **Value digests integrity checks** – Validates SHA-256 digests with tag(24) encoding for all data elements per ISO 18013-5 specification
- **DeviceAuth verification** – Confirms holder authentication using device signatures and session transcript matching
- **SessionTranscript validation** – Ensures session context integrity between reader and wallet

### Privacy & Data Handling

- Sessions are established using the algorithms defined in ISO 18013‑5
- Session keys live only in browser memory and are cleared when you reload or close the page
- The **Visitor Log** and **Unlinkability Test** pages store data only in your browser (local storage) for your own experiments
- **No data is sent to any backend by this app**

### Trust Anchors

- Pre-loaded with 36+ IACA root certificates from major issuers (France, Netherlands, US states, test environments)
- Support for custom IACA certificate import via VICAL format
- Automatic detection of certificate curve types and signature algorithms

---

## Advanced features

If you are familiar with mDL / mDoc internals, the main page also includes:

- VICAL (Verified Issuer CA List) import for issuer CA certificates
- COSE_Sign1 verification with X.509 trust anchors
- Classic MSO viewer and detailed verification status per document

You can import issuer CA lists either from a file or from a URI. When importing from a URI, the app understands CBOR/COSE/CWT or JSON payloads and shows which issuers were imported or skipped.

---

## Troubleshooting

- **Browser says Web Bluetooth not available**: make sure you use Chrome or Edge over HTTPS.
- **No prompt on the wallet**: ensure the requested document type and fields are supported by your wallet.
- **BLE disconnects often**: some wallets intentionally disconnect between operations; simply scan and reconnect.
- **Import of issuer lists fails**: download the file and use import‑from‑file on the main page instead of URI import.

---

### License

This project is licensed under the Apache License 2.0.
See the LICENSE and NOTICE files for details.
