(function () {
  // Session crypto helpers extracted from index.html
  // Exposes window.SessionCrypto with pure helpers that don't depend on page state

  const enc = new TextEncoder();

  function concatUint8(...arrs) {
    const n = arrs.reduce((s, a) => s + a.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) {
      out.set(a, o);
      o += a.length;
    }
    return out;
  }
  function hex(buf) {
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }

  async function importMdocPubKeyXY(x, y) {
    const u = new Uint8Array(1 + x.length + y.length);
    u[0] = 0x04;
    u.set(x, 1);
    u.set(y, 1 + x.length);
    return crypto.subtle.importKey(
      "raw",
      u,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  }
  async function deriveSharedSecretBits(privKey, pubKey) {
    const sharedSecret = await crypto.subtle.deriveBits(
      { name: "ECDH", public: pubKey },
      privKey,
      256
    );
    return sharedSecret; // ArrayBuffer
  }
  async function hkdfExtract(saltBytes, ikmBytes) {
    const key = await crypto.subtle.importKey(
      "raw",
      saltBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const prk = await crypto.subtle.sign("HMAC", key, ikmBytes);
    return new Uint8Array(prk);
  }
  async function hkdfExpand(prkBytes, infoBytes, length) {
    const prk = await crypto.subtle.importKey(
      "raw",
      prkBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    let t = new Uint8Array(0),
      okm = new Uint8Array(0),
      counter = 1;
    while (okm.length < length) {
      const input = concatUint8(t, infoBytes, Uint8Array.of(counter));
      const mac = new Uint8Array(await crypto.subtle.sign("HMAC", prk, input));
      okm = concatUint8(okm, mac);
      t = mac;
      counter++;
    }
    return okm.slice(0, length);
  }
  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  async function aesGcmEncryptRaw(
    plaintext,
    keyBytes,
    identifier8,
    messageCounter = 1
  ) {
    const iv = new Uint8Array(12);
    iv.set(identifier8 || new Uint8Array(8), 0);
    iv[8] = (messageCounter >> 24) & 0xff;
    iv[9] = (messageCounter >> 16) & 0xff;
    iv[10] = (messageCounter >> 8) & 0xff;
    iv[11] = messageCounter & 0xff;
    const aad = new Uint8Array(0);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key,
      plaintext
    );
    return new Uint8Array(encrypted);
  }

  async function coseEncrypt0_AESGCM_Enc0(
    plaintext,
    keyBytes,
    messageCounter = 1
  ) {
    const iv = new Uint8Array(12);
    iv[8] = (messageCounter >> 24) & 0xff;
    iv[9] = (messageCounter >> 16) & 0xff;
    iv[10] = (messageCounter >> 8) & 0xff;
    iv[11] = messageCounter & 0xff;
    const aad = new Uint8Array(0);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad },
        key,
        plaintext
      )
    );
    let ciphertextEncoded;
    if (ciphertext.length < 24)
      ciphertextEncoded = new Uint8Array([
        0x40 + ciphertext.length,
        ...ciphertext,
      ]);
    else if (ciphertext.length < 256)
      ciphertextEncoded = new Uint8Array([
        0x58,
        ciphertext.length,
        ...ciphertext,
      ]);
    else
      ciphertextEncoded = new Uint8Array([
        0x59,
        (ciphertext.length >> 8) & 0xff,
        ciphertext.length & 0xff,
        ...ciphertext,
      ]);
    const protectedHdr = new Uint8Array([0x43, 0xa1, 0x01, 0x03]);
    const unprotectedHdr = new Uint8Array([0xa1, 0x05, 0x4c, ...iv]);
    return new Uint8Array([
      0x83,
      ...protectedHdr,
      ...unprotectedHdr,
      ...ciphertextEncoded,
    ]);
  }

  function encodeCoseKeyManually(coseKey) {
    const result = [];
    result.push(0xa4);
    result.push(0x01);
    result.push(0x02);
    result.push(0x20);
    result.push(0x01);
    const x = coseKey.get(-2);
    result.push(0x21);
    result.push(0x58, 0x20);
    result.push(...x);
    const y = coseKey.get(-3);
    result.push(0x22);
    result.push(0x58, 0x20);
    result.push(...y);
    return new Uint8Array(result);
  }
  function encodeTag24ByteString(data) {
    const result = [];
    result.push(0xd8, 0x18);
    if (data.length < 24) result.push(0x40 + data.length);
    else if (data.length < 256) result.push(0x58, data.length);
    else result.push(0x59, data.length >> 8, data.length & 0xff);
    result.push(...data);
    return new Uint8Array(result);
  }

  async function deriveSessionKey(sharedSecret, transcriptHash) {
    const prk = await hkdfExtract(transcriptHash, sharedSecret);
    const readerInfo = enc.encode("SKReader");
    const deviceInfo = enc.encode("SKDevice");
    const readerKey = await hkdfExpand(prk, readerInfo, 32);
    const deviceKey = await hkdfExpand(prk, deviceInfo, 32);
    return { readerKey, deviceKey };
  }

  window.SessionCrypto = {
    importMdocPubKeyXY,
    deriveSharedSecretBits,
    hkdfExtract,
    hkdfExpand,
    sha256,
    aesGcmEncryptRaw,
    coseEncrypt0_AESGCM_Enc0,
    encodeCoseKeyManually,
    encodeTag24ByteString,
    deriveSessionKey,
  };
})();
