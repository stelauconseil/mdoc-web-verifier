(function () {
  // High-level Session Establishment utilities built on top of SessionCrypto
  // Exposes window.SessionEstablishment with orchestration helpers that accept
  // page-provided dependencies and return computed artifacts instead of
  // mutating page state.

  const enc = new TextEncoder();

  function hex(buf) {
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }

  let _readerCoseKeyCached = null; // Map with integer labels {-2:x,-3:y}

  async function makeReaderEphemeralKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
  }

  function buildReaderCoseKey() {
    if (!_readerCoseKeyCached) throw new Error("reader COSE_Key not ready");
    return _readerCoseKeyCached;
  }

  function resetReaderCoseKeyCache() {
    _readerCoseKeyCached = null;
  }

  async function exportReaderPublicToCoseKey(readerKeyPair) {
    const raw = new Uint8Array(
      await crypto.subtle.exportKey("raw", readerKeyPair.publicKey)
    ); // 0x04||X||Y
    const x = raw.slice(1, 33);
    const y = raw.slice(33, 65);
    const fingerprint = hex(x.slice(0, 4));

    // Store as Map - encoding handled via SessionCrypto helpers
    _readerCoseKeyCached = new Map([
      [1, 2], // kty: EC2
      [-1, 1], // crv: P-256
      [-2, x], // x coordinate (Uint8Array)
      [-3, y], // y coordinate (Uint8Array)
    ]);

    return { fingerprint, x, y };
  }

  // Build transcript AAD (SHA-256(tag(24, bstr(SessionTranscript))))
  async function buildTranscriptAAD(deBytes) {
    if (!deBytes) throw new Error("DeviceEngagement bytes required");
    if (!window.SessionCrypto) throw new Error("SessionCrypto not available");

    const readerCoseKey = buildReaderCoseKey();
    const coseKeyEncoded =
      window.SessionCrypto.encodeCoseKeyManually(readerCoseKey);
    const eReaderKeyBytes =
      window.SessionCrypto.encodeTag24ByteString(coseKeyEncoded);

    // SessionTranscript = [ tag(24, DeviceEngagement), EReaderKeyBytes, null ]
    const result = [];
    // array(3)
    result.push(0x83);
    // tag(24), bstr(DeviceEngagement)
    result.push(0xd8, 0x18);
    if (deBytes.length < 24) result.push(0x40 + deBytes.length);
    else if (deBytes.length < 256) result.push(0x58, deBytes.length);
    else result.push(0x59, deBytes.length >> 8, deBytes.length & 0xff);
    result.push(...deBytes);
    // EReaderKeyBytes (already tag(24,bstr(.cbor COSE_Key)))
    result.push(...eReaderKeyBytes);
    // Handover (BLE via QR) = null
    result.push(0xf6);

    const trCbor = new Uint8Array(result);

    // Multipaz expects tag(24, bstr(SessionTranscript)) before hashing
    const wrappedTranscript =
      window.SessionCrypto.encodeTag24ByteString(trCbor);
    const aad = await window.SessionCrypto.sha256(wrappedTranscript);

    // Minimal debug exposure
    try {
      window.sessionDebug = window.sessionDebug || {};
      window.sessionDebug.sessionTranscript = trCbor;
      window.sessionDebug.sessionTranscriptWrapped = wrappedTranscript;
      window.sessionDebug.eReaderKey = eReaderKeyBytes;
    } catch {}

    return aad;
  }

  // Build ISO 18013-5 compliant SessionEstablishment payload
  // Returns { message, keys?: {readerKey, deviceKey}, transcriptAAD }
  async function buildLegacySessionEstablishmentWithData(opts) {
    const {
      deBytes,
      mdocPubKey, // {x,y}
      readerKeyPair,
      transcriptAAD, // optional
      skReader, // optional
      buildRequestByType, // function returning Uint8Array
      log,
      CBOR: CBORRef,
    } = opts || {};

    if (!deBytes || !mdocPubKey || !readerKeyPair || !buildRequestByType)
      throw new Error("Missing inputs for SessionEstablishment build");
    if (!window.SessionCrypto) throw new Error("SessionCrypto not available");

    const readerCoseKey = buildReaderCoseKey();
    const coseKeyEncoded =
      window.SessionCrypto.encodeCoseKeyManually(readerCoseKey);
    const publicKeyBytes =
      window.SessionCrypto.encodeTag24ByteString(coseKeyEncoded);

    // Build request
    const mdlRequest = await buildRequestByType();

    // Derive keys if not provided
    let aad = transcriptAAD;
    let keys;
    if (!skReader || !aad) {
      const mdocPub = await window.SessionCrypto.importMdocPubKeyXY(
        mdocPubKey.x,
        mdocPubKey.y
      );
      const shared = await window.SessionCrypto.deriveSharedSecretBits(
        readerKeyPair.privateKey,
        mdocPub
      );
      aad = await buildTranscriptAAD(deBytes);
      keys = await window.SessionCrypto.deriveSessionKey(
        new Uint8Array(shared),
        aad
      );
    }

    const useReaderKey = skReader || keys?.readerKey;
    const readerIdentifier = new Uint8Array(8); // 0x00 x8
    const encryptedRequest = await window.SessionCrypto.aesGcmEncryptRaw(
      mdlRequest,
      useReaderKey,
      readerIdentifier,
      1
    );

    // Build map {"eReaderKey": tag24(bstr .cbor COSE_Key), "data": <raw>}
    const result = [];
    result.push(0xa2); // map(2)
    // key: "eReaderKey"
    result.push(0x6a, ...Array.from("eReaderKey").map((c) => c.charCodeAt(0)));
    result.push(...publicKeyBytes);
    // key: "data"
    result.push(0x64, ...Array.from("data").map((c) => c.charCodeAt(0)));
    if (encryptedRequest.length < 24)
      result.push(0x40 + encryptedRequest.length);
    else if (encryptedRequest.length < 256)
      result.push(0x58, encryptedRequest.length);
    else
      result.push(
        0x59,
        (encryptedRequest.length >> 8) & 0xff,
        encryptedRequest.length & 0xff
      );
    result.push(...encryptedRequest);

    const final = new Uint8Array(result);

    // Optional diagnostic decode
    try {
      if (CBORRef && CBORRef.decode) {
        const d = CBORRef.decode(final);
        void d; // no-op, just verify
      }
    } catch {}

    return { message: final, keys, transcriptAAD: aad };
  }

  window.SessionEstablishment = {
    makeReaderEphemeralKeyPair,
    exportReaderPublicToCoseKey,
    buildReaderCoseKey,
    resetReaderCoseKeyCache,
    buildTranscriptAAD,
    buildLegacySessionEstablishmentWithData,
  };
})();
