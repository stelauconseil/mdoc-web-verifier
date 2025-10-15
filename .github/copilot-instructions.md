# ISO 18013-5 Web Companion - AI Coding Guide

## Project Overview

This is a single-page web application implementing **ISO 18013-5** mobile Driver's License (mDL) reader functionality using Web Bluetooth. It enables QR code scanning, BLE communication, and cryptographic session establishment for secure mDL data exchange directly in a browser.

## Architecture & Components

### Single-File Architecture

- **`index.html`** (3029 lines): Contains complete application - HTML structure, CSS styling, and JavaScript logic
- **No build system** - runs directly in browser with CDN dependencies
- **Self-contained** - all cryptographic, BLE, and UI logic in one file

### Key Dependencies

```javascript
// Loaded via CDN in production
jsQR@1.4.0         // QR code scanning from camera
cbor-web@9.0.2      // CBOR encoding/decoding for ISO 18013-5
WebCrypto API       // ECDH key agreement, AES-GCM encryption, HKDF
Web Bluetooth API   // BLE GATT communication
```

### Critical Protocol Components

#### 1. Device Engagement Processing

```javascript
// QR scanning extracts DeviceEngagement CBOR
extractCborFromMdocUri(uri); // Handles mdoc:// URIs, data URIs, hex/base64
parseMdocUriAndDE(uri); // Parses CBOR → service UUID + mdoc public key
tryExtractBleOptions(root); // Finds BLE service UUID (field 10/11) and address (field 20)
```

#### 2. Session Establishment (ISO 18013-5 compliant)

Per ISO 18013-5 Section 9.1.1.4, SessionEstablishment message structure:

```
SessionEstablishment = {
  "eReaderKey" : EReaderKeyBytes,  // tag(24, bstr .cbor COSE_Key)
  "data" : bstr                     // Encrypted mdoc request (COSE_Encrypt0)
}
```

Implementation functions:

```javascript
// Ephemeral key generation
makeReaderEphemeralKeyPair(); // P-256 ECDH key pair for this session
buildTranscriptAAD(); // SessionTranscript = [DeviceEngagement, EReaderKey, Handover]
deriveSessionKey(); // HKDF with transcript hash as salt → SKReader + SKDevice
```

#### 3. Encryption (AES-256-GCM per ISO 18013-5)

Per ISO 18013-5 specification:

**Encryption Algorithm**: AES-256-GCM (NIST SP 800-38D)

- Reader encrypts requests with **SKReader**
- Mdoc (wallet) encrypts responses with **SKDevice**
- Both parties generate both session keys for bidirectional communication

**IV (Initialization Vector)**: 12 bytes = `identifier || message_counter`

- **Reader identifier**: `0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00` (8 bytes)
- **Mdoc identifier**: `0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01` (8 bytes)
- **Message counter**: 4-byte big-endian unsigned integer
  - Starts at 1 for first encryption
  - Incremented before each subsequent encryption with same key
  - Never reused with same key

**AAD (Additional Authenticated Data)**: Empty string (per spec)

**Output**: The `data` element contains `ciphertext || authentication_tag`

- Ciphertext from GCM encryption
- 16-byte authentication tag appended
- Wrapped in COSE_Encrypt0 structure: `[protected_header, unprotected_header, ciphertext]`

```javascript
// Implementation
coseEncrypt0_AESGCM_Enc0(plaintext, externalAAD, keyBytes, messageCounter);
// IV = reader_id(8) || counter(4)
// AAD = empty string
// Returns COSE_Encrypt0 with ciphertext || 16-byte auth tag
```

## Development Patterns

### BLE Communication Flow

1. **QR Scan** → Extract service UUID from DeviceEngagement
2. **BLE Connect** → GATT connection with 3 characteristics (state, C2S, S2C)
3. **State Machine** → writeState(0x01) starts protocol
4. **Session Establishment** → Exchange ephemeral keys
5. **Encrypted Requests** → Send COSE_Encrypt0 device requests

### Error Handling Patterns

- **BLE disconnections** are common - wallet apps frequently disconnect between operations
- **Multiple wallet variants** - code supports both static and ephemeral key handover
- **Browser compatibility** - extensive feature detection for Web Bluetooth experimental APIs

### Cryptographic Key Management

```javascript
// Reader encrypts requests with SKReader
// Reader decrypts responses with SKDevice
// Session keys derived per ISO 18013-5 Section 9.1.5.2
const keys = await deriveSessionKey(sharedSecret, transcriptHash);
skReader = keys.readerKey; // For outbound encryption
skDevice = keys.deviceKey; // For inbound decryption
```

## Common Development Tasks

### Adding New Request Types

```javascript
// In buildRequestByType() function - add new case
case 'your_new_type':
  Object.assign(ns, {
    "field_name": true,  // true = request, false = intent-to-retain
    // ... more fields
  });
  break;
```

### Supporting New Document Types

```javascript
// Change docType and namespace
baseRequest.docRequests[0].itemsRequest.docType = "your.new.doctype";
baseRequest.docRequests[0].itemsRequest.nameSpaces = {
  "your.new.namespace": {},
};
```

### Debug Connection Issues

- Use **Diagnostics** button for complete system state
- Check `sessionDebug` object in browser DevTools
- Monitor WebBluetooth connection state in browser tools
- Common issue: wallet expects different SessionEstablishment format

### Browser Compatibility

- **HTTPS required** for Web Bluetooth
- **Chrome Canary + flags** needed for advertising APIs on macOS
- **Experimental features** must be enabled in chrome://flags/

## Security Considerations

- **No reader authentication** implemented (readerAuth: null)
- **Session keys** stored in memory only, cleared on page reload
- **IV generation** follows ISO 18013-5: reader_identifier(8) || counter(4)
- **Transcript AAD** properly implements SessionTranscript hash per spec

## Testing & Debugging

### Browser DevTools

```javascript
// Global debug objects available in console
window.sessionDebug.skReader; // Current session keys
window.sessionDebug.lastEncrypt; // Last encryption parameters
window.sessionEstablished; // Boolean session state
```

### Common Wallet Issues

- **No prompt**: Check request fields are `true`, not `false`
- **Connection drops**: Normal behavior - wallets disconnect frequently
- **Wrong docType**: Ensure exact match with wallet's supported types
- **Encryption mismatch**: Verify transcript AAD construction

### Protocol State Machine

```
IDLE (0x00) → START (0x01) → DATA_TRANSFER → END (0x02)
```

Always verify wallet is in correct state before sending requests.

## Known Issues & Workarounds

### Multipaz Wallet - Alternate SessionEstablishment Decryption Error

**Symptom**: `java.lang.IllegalStateException: Error decrypting` when using "Send Alt SessionEstablishment"

**Background**: Per ISO 18013-5 spec, the alternate flow **should** work:

```
SessionEstablishment = {
  "eReaderKey" : EReaderKeyBytes,  // tag(24, bstr .cbor COSE_Key)
  "data" : bstr                     // Encrypted mdoc request
}
```

- mdoc reader generates ephemeral EReaderKey
- Session keys derived **independently** by both mdoc (wallet) and reader
- Reader encrypts request and sends `{eReaderKey, data: <encrypted>}` together
- Both sides derive same keys from: DeviceEngagement.eSenderKey + SessionEstablishment.eReaderKey

**Root Cause - CONFIRMED**:

The spec states: "The value of the data element shall be the concatenation of the ciphertext and all 16 bytes of the authentication tag"

**Analysis of Working Example**:

```
SessionEstablishment hex starts with: 52ada2acbeb6c390f2ca0bc659b484...
- 0x52 is NOT 0x83 (COSE_Encrypt0 array marker)
- This confirms data field is RAW ciphertext || auth_tag
```

**Issue**: Our implementation wraps encrypted data in COSE_Encrypt0:

- `data` = `[protected_header, unprotected_header, ciphertext]` (CBOR array)
- This is incorrect per spec literal interpretation

**Correct Format**:

- `data` = raw output from AES-256-GCM (no CBOR structure)
- Just the bytes: `ciphertext || 16-byte authentication_tag`

**Why This Matters**:

- Most document request/response encryption uses COSE_Encrypt0
- But SessionEstablishment.data field is a special case
- It must be raw AES-GCM output per spec Section 9.1.1.4

**Fix Required**:

In `buildLegacySessionEstablishmentWithData()`:

```javascript
// WRONG (current code):
const coseEnc = await coseEncrypt0_AESGCM_Enc0(payload, "", skReader, 1);
obj.data = coseEnc; // This is a COSE_Encrypt0 array

// CORRECT (needs implementation):
const rawEncrypted = await aesGcmEncrypt(
  payload,
  skReader,
  readerIdentifier,
  1
);
obj.data = rawEncrypted; // Just ciphertext || 16-byte auth_tag
```

New function needed:

```javascript
async function aesGcmEncrypt(plaintext, keyBytes, identifier8, counter) {
  const iv = new Uint8Array(12);
  iv.set(identifier8, 0); // 8-byte identifier
  const dv = new DataView(iv.buffer, 8, 4);
  dv.setUint32(0, counter, false); // 4-byte counter (big-endian)

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new Uint8Array(0), tagLength: 128 },
    key,
    plaintext
  );

  return new Uint8Array(encrypted); // Already includes 16-byte auth tag
}
```

**Testing Checklist**:

- ✅ Verify `data` field starts with ciphertext (not 0x83)
- ✅ Length should be plaintext_length + 16 bytes
- ✅ No CBOR array structure in data field
- ✅ IV still constructed per spec: identifier(8) || counter(4)

**Workaround**: ~~Use standard "Send SessionEstablishment" button~~ **FIXED!**

The issue has been resolved by implementing the spec correctly:

1. Created `aesGcmEncryptRaw()` function that returns raw AES-GCM output
2. Updated `buildLegacySessionEstablishmentWithData()` to use raw encryption
3. The `data` field now contains just `ciphertext || 16-byte auth_tag`

**Testing Results**:

- ✅ `data` field format matches working example
- ✅ No COSE_Encrypt0 wrapper in SessionEstablishment.data
- ✅ IV construction unchanged: identifier(8) || counter(4)
- ✅ AAD remains empty per spec

**Note**: Regular encrypted requests/responses after SessionEstablishment still use COSE_Encrypt0 - only the SessionEstablishment.data field uses raw format.

## File Structure Conventions

- **No external files** - everything in index.html for portability
- **Manual CBOR encoding** functions avoid library tag issues
- **Extensive logging** to browser console for debugging
- **Progressive enhancement** - graceful degradation when APIs unavailable
