# ISO 18013-5 Web Verifier

This site lets you test an EUDI Wallet or any ISO 18013-5 wallet (mDL / mDoc) from your computer, directly in the browser:

- Scan a wallet’s Device Engagement QR code
- Connect over Web Bluetooth
- See the data returned by your wallet and a verdict for each credential
- Sign your requests with a reader access certificate (reader authentication)
- Add your own ISO 18013-5 credential definitions from CDDL

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

The home page (index.html) is a general-purpose ISO 18013-5 reader. A progress bar at the top shows the three steps: **Choose**, **Scan**, **Results**.

High‑level flow:

1. Open the site over HTTPS in a supported browser (Chrome on desktop or
   Android, Edge or Brave on desktop, or Bluefy on iOS).
2. **Choose credentials.** Credentials are grouped by family (Identity, Transport, Medical, Student, User-defined). Expand a group and tick one or more credentials; each group shows how many are selected, and the line above the Scan button lists everything that will be requested. The **Scan QR Code** button stays disabled until at least one credential is selected.
3. **Scan.** Click **Scan QR Code** and point the camera at the wallet’s Device Engagement QR code. No camera? Use **Paste an mdoc: URI instead** below the button.
4. When the QR code is recognised, the button turns green and reads **Connect to Wallet**. Click it and allow Bluetooth access when prompted. If the connection fails, the button stays on **Connect to Wallet** so you can retry with the same QR code.
5. Approve the request in your wallet.
6. **Results.** Each returned credential gets a verdict (**Credential verified**, **Verified, with warnings** or **Verification failed**) with a checklist: issuer signature, certificate chain, device authentication and data integrity. Below it you find the returned namespaces and attributes, and a **Technical Details** section (issuer signature, MSO, document signer certificate, ICAO passive authentication when present).
7. Click **New Verification** at the bottom of the results to start again with the same credential selection.

Notes:

- Works with wallets that support **Server Peripheral over BLE** as defined in ISO 18013‑5.
- Built-in and user-defined credentials can be selected together in the same request.
- The badge next to the Scan button shows whether reader authentication is on; click it to open its settings.
- Light and dark themes follow your system setting.

#### Session Log panel

The **Session Log** button in the top bar opens a side panel that can stay open during a test:

- **Activity Log**: every step of the session, with an option to log verbose details to the browser console.
- **Device Engagement**: the parsed QR payload (status, service UUID, BLE address), the BLE packet size (MTU, 244 bytes by default, lower it to 20 if the connection is unstable), and a field to paste an `mdoc:` URI by hand (from the clipboard or a laser scanner).

#### Settings panel

The **Settings** button opens:

- **Reader Authentication** (see below)
- **Issuer Certificates (IACA)**: trusted issuer roots, PEM import, VICAL import, reset to defaults
- **Passport Trust List (CSCA)**: country signing CAs for ICAO passive authentication

#### Reader authentication

Turn on **Reader Authentication** in Settings to sign each request (ISO 18013-5 ReaderAuth), so the wallet can show the holder who is asking for their data:

1. Paste your **reader access certificate** (PEM) and the matching **private key** (PEM, PKCS#8 or SEC1 EC key). The reader name (certificate Common Name) is displayed once the certificate is read.
2. Optionally, turn on **Registration certificate (WRPRC)** and import the EU wallet-relying party registration certificate (binary CWT file up to 256 KiB, or pasted as base64 / base64url). It tells the wallet which data you are registered to request, and why, and must be issued for the reader access certificate above.
3. Click **Save Reader Settings**. **Remove Saved Key and Certificates** deletes them from the browser.

The private key is stored **unencrypted** in the browser's `localStorage`. Use test keys only; production keys belong in secure hardware (HSM, TPM).

### 2. Visitor Log (visitor.html)

The **Visitor Log** page is an example of how to use mobile IDs for simple check‑in / check‑out without a backend.

What it does:

- Lets visitors scan their mobile ID (EUDI PID or mDL) to create a local entry
- Stores entries **only in your browser** (no server, no upload)
- Shows a table with date, name, document type, and in/out times

How to use it:

1. Open `visitor.html`.
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

1. Open `unlikability_test.html`.
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
- **BIDA** – `eu.europa.ec.eudi.bida.1` (Basic Identification Data Attestation)
- **EU Age Verification** – `eu.europa.ec.av.1` (age‑only attestations such as `age_over_18`)
- **Photo ID** – `org.iso.23220.photoid.1` (+ related ISO 23220 namespaces)
- **mICOV** – `org.micov.1` (vaccination / test attestations)
- **French CPS** – `fr.ft.hp.1.hpa` (Carte Professionnelle de Santé), available
  in Basic and Full modes across the `org.iso.23220.1` and `fr.ans.hp.1`
  namespaces
- **mVC** – `org.iso.7367.2.1.mVC` (vehicle card)
- **Bicycle ID card** – `fr.idak.mbicycle.1` (bicycle owner and identification data)
- **Student Card** – `fr.ft.hsc.1` (+ related ISO 23220 namespaces)

Your wallet may not support all of these doctypes; the app will only show data for documents actually returned by the wallet.

### User-defined credentials

The main reader supports custom ISO 18013-5 credential definitions. Definitions
are validated and stored in the browser's `localStorage`; they are not uploaded
to a server.

To add and request a credential:

1. Expand **User-defined credentials** on the main page.
2. Paste a supported CDDL profile.
3. Click **Add Credential**.
4. Select **Basic** to request only mandatory claims, or **Full** to request all
   declared claims. The credential can be combined with any built-in credential.
5. Scan the wallet QR code and complete the normal presentation flow.

Saved definitions remain available after a page reload. Use **Edit** to load a definition back into the editor, then **Save Changes** to update it. Editing can change the display name, docType, namespaces, claims, and formats. Use **Cancel Editing** to discard editor changes or **Delete** to remove the locally stored definition. Clearing the browser's site data also removes these profiles.

#### Supported CDDL profile

This feature accepts the following focused CDDL profile structure rather than an arbitrary CDDL document:

- `displayName` defines the label shown in the credential selector.
- `docType` defines the ISO 18013-5 document type.
- `namespaces` is an array containing one or more namespace definitions.
- Each namespace definition contains its string identifier and a `claims` map.
- Claims use standard CDDL group entries such as `family_name: tstr`.
- A regular member represents a mandatory claim in the source rulebook.
- A member prefixed with `?` represents an optional claim.
- The type after `:` records the claim's CDDL format, such as `tstr` or `bool`.
- Multiple namespaces may be declared in the same profile.

```cddl
example-card = {
  displayName: "Example card",
  docType: "example.card.1",
  namespaces: [
    {
      namespace: "example.card.1",
      claims: {
        family_name: tstr,
        given_name: tstr,
        ? portrait: bstr,
      },
    }
  ],
}
```

In **Basic** mode, only regular CDDL members (mandatory claims) are placed in the presentation request. In **Full** mode, optional members prefixed with `?` are included as well. Every requested claim uses `intentToRetain: false`. Basic and Full are mutually exclusive for a given user-defined credential.

When the wallet returns the credential, the normal result viewer displays its docType, each namespace, every returned claim, and the available cryptographic verification results.

---

## Requirements

Supported browsers (the site must be served over **HTTPS**):

| Browser | Platform | Download |
| --- | --- | --- |
| Google Chrome | Desktop / Android | [Download Chrome](https://www.google.com/chrome/download-chrome/) |
| Microsoft Edge | Desktop | [Download Edge](https://www.microsoft.com/edge/download) |
| Brave | Desktop | [Download Brave](https://brave.com/download/) |
| Bluefy – Web BLE Browser | iOS / iPadOS | [Download from the App Store](https://apps.apple.com/us/app/bluefy-web-ble-browser/id1492822055) |

- Camera permission (for QR scanning)
- Bluetooth permission (for BLE)
- A wallet that supports ISO 18013‑5 **Server Peripheral over BLE**

If your browser does not support Web Bluetooth or you are not on HTTPS, connection will not work.

---

## Example

Multipaz mDL :

https://github.com/user-attachments/assets/c54cd5df-aaa7-4707-8672-135198173ec6

France Identité Wallet:

https://github.com/user-attachments/assets/3bd11229-92c4-4c2f-8e30-16d502d7fb51

---

## Security & privacy

This verifier implements comprehensive security controls per ISO 18013-5:

### Cryptographic Verification

- **COSE_Sign1 signature verification** – Validates the issuer's digital signature on each document using ECDSA with curves P-256, P-384, P-521, and Brainpool variants
- **Certificate chain validation** – Verifies issuer certificates against trusted IACA (Issuer Authority Certificate Authority) root certificates with automatic AKI/SKI matching
- **Value digests integrity checks** – Validates SHA-256 digests with tag(24) encoding for all data elements per ISO 18013-5 specification
- **DeviceAuth verification** – Confirms holder authentication using device signatures and session transcript matching
- **SessionTranscript validation** – Ensures session context integrity between reader and wallet
- **ICAO passive authentication** – For Photo ID / DTC documents carrying ICAO data groups (`org.iso.23220.datagroups.1`): DG hashes against EF.SOD, SOD signature by the Document Signer, Document Signer signature by a trusted CSCA (RSA incl. SHA-224, RSA-PSS, ECDSA on P-256/384/521 and brainpoolP256/320/384/512r1, or any curve given by explicit parameters). Self-check: `node test/icao-passive-auth.test.js`

### Privacy & Data Handling

- Sessions are established using the algorithms defined in ISO 18013‑5
- Session keys live only in browser memory and are cleared when you reload or close the page
- The **Visitor Log** and **Unlinkability Test** pages store data only in your browser (local storage) for your own experiments
- User-defined CDDL credential profiles are stored only in the browser's `localStorage` and can be edited, deleted, or removed by clearing the site's data
- Reader authentication keys and certificates are stored only in the browser's `localStorage` (the private key unencrypted, see above)
- **No data is sent to any backend by this app**

### Trust Anchors

- Pre-loaded with 6 IACA root certificates (`js/iaca-defaults.js`): France Identité and France Attestations (production and test), Netherlands RDW mDL and mVR
- Support for custom IACA certificate import via VICAL format
- Passport trust list: CSCA certificates imported as PEM, DER or ICAO master lists (.ml), stored in the browser's `localStorage`
- Automatic detection of certificate curve types and signature algorithms

---

## Advanced features

If you are familiar with mDL / mDoc internals, the main page also includes:

- VICAL (Verified Issuer CA List) import for issuer CA certificates (Settings → Issuer Certificates)
- COSE_Sign1 verification with X.509 trust anchors
- Full MSO structure viewer and per-document technical details in the results
- Reader authentication with an optional WRPRC registration certificate (Settings → Reader Authentication)

You can import issuer CA lists either from a file or from a URI. When importing from a URI, the app understands CBOR/COSE/CWT or JSON payloads and shows which issuers were imported or skipped.

---

## Troubleshooting

- **Browser says Web Bluetooth not available**: make sure the page uses HTTPS
  and open it with Chrome on desktop or Android, Edge or Brave on desktop, or
  Bluefy on iOS.
- **No prompt on the wallet**: ensure the requested document type and fields are supported by your wallet.
- **BLE disconnects often**: some wallets intentionally disconnect between operations; simply scan and reconnect. If it keeps failing, lower the BLE MTU in Session Log → Device Engagement.
- **Connection failed after the scan**: click **Connect to Wallet** again; the same QR code can be reused while the wallet still shows it.
- **Scan QR Code is greyed out**: select at least one credential first.
- **Reader authentication errors**: check that the private key matches the reader access certificate; the key must be an EC key in PKCS#8 or SEC1 PEM format.
- **Import of issuer lists fails**: download the file and use import‑from‑file on the main page instead of URI import.

---

### License

This project is licensed under the Apache License 2.0.
See the LICENSE and NOTICE files for details.
