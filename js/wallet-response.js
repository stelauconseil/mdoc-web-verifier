/*
  Copyright (c) 2025 Stelau
  Author: Nicolas Chalanset

  Wallet Response module: AES-GCM decrypt helpers and view-model builder (no DOM/HTML)
*/

(function () {
  const enc = new TextEncoder();
  function hex(buf) {
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }
  function getCBOR() {
    return window.CBOR || self.CBOR || self.cbor;
  }
  const log = window.log || console.log;

  // AES-GCM decrypt helper used by this module (pure, no DOM)
  async function aesGcmDecrypt(ciphertext, keyBytes, iv, additionalData) {
    if (
      !keyBytes ||
      !(keyBytes instanceof Uint8Array) ||
      keyBytes.length === 0
    ) {
      throw new Error("Session key missing for AES-GCM decryption");
    }
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const ivU8 = iv instanceof Uint8Array ? iv : new Uint8Array(iv);
    let aadU8 = null;
    if (additionalData instanceof Uint8Array) {
      aadU8 = additionalData;
    } else if (additionalData && typeof additionalData === "string") {
      // Per spec, AAD is empty; if a string is passed, coerce to empty
      aadU8 = new Uint8Array(0);
    } else if (
      additionalData &&
      (ArrayBuffer.isView(additionalData) ||
        additionalData instanceof ArrayBuffer)
    ) {
      aadU8 =
        additionalData instanceof Uint8Array
          ? additionalData
          : new Uint8Array(additionalData.buffer || additionalData);
    } else {
      aadU8 = new Uint8Array(0);
    }
    const params = { name: "AES-GCM", iv: ivU8, tagLength: 128 };
    if (aadU8 && aadU8.length) params.additionalData = aadU8;
    const pt = await crypto.subtle.decrypt(
      params,
      key,
      ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext)
    );
    return new Uint8Array(pt);
  }

  // JSON conversion helper used by response rendering and debug views
  function convertToJSON(obj) {
    if (obj === null || obj === undefined) return obj;
    // Represent raw bytes in a friendlier structure with base64
    if (obj instanceof Uint8Array) {
      const bin = Array.from(obj);
      let b64 = "";
      try {
        b64 = btoa(String.fromCharCode(...bin));
      } catch (_) {
        // Fallback for very large arrays
        let s = "";
        for (let i = 0; i < obj.length; i += 0x8000) {
          s += String.fromCharCode.apply(null, obj.subarray(i, i + 0x8000));
        }
        b64 = btoa(s);
      }
      return { _type: "bytes", _length: obj.length, _base64: b64 };
    }
    if (ArrayBuffer.isView(obj)) return Array.from(obj);
    if (obj instanceof ArrayBuffer) return Array.from(new Uint8Array(obj));
    if (Array.isArray(obj)) return obj.map((item) => convertToJSON(item));
    if (obj instanceof Map) {
      const out = {};
      for (const [k, v] of obj.entries()) out[k] = convertToJSON(v);
      return out;
    }
    if (obj instanceof Set) return Array.from(obj).map((v) => convertToJSON(v));
    if (obj instanceof Date) return obj.toISOString();
    if (typeof obj === "object") {
      const res = {};
      for (const [k, v] of Object.entries(obj)) res[k] = convertToJSON(v);
      return res;
    }
    return obj;
  }

  // Build a pure JSON view-model for rendering in index.html (no DOM/HTML here)
  function buildResponseViewModel(deviceResponse) {
    const CBOR = getCBOR();
    const getField = (obj, key) =>
      obj instanceof Map ? obj.get(key) : obj?.[key];
    const getFieldAny = (obj, keys) => {
      if (!obj) return undefined;
      for (const k of keys) {
        const v = obj instanceof Map ? obj.get(k) : obj?.[k];
        if (v !== undefined) return v;
      }
      return undefined;
    };

    // Helper: unwrap CBOR.Tagged and decode bstr.cbor or raw Uint8Array into JS structures
    const toUint8 = (v) => {
      if (v instanceof Uint8Array) return v;
      if (ArrayBuffer.isView(v))
        return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
      if (v instanceof ArrayBuffer) return new Uint8Array(v);
      if (Array.isArray(v)) {
        try {
          return new Uint8Array(v);
        } catch (_) {
          return null;
        }
      }
      return null;
    };
    const tryDecodeCBOR = (bytes) => {
      try {
        if (
          !bytes ||
          !(bytes instanceof Uint8Array) ||
          !CBOR ||
          typeof CBOR.decode !== "function"
        )
          return null;
        const dec = CBOR.decode(bytes);
        if (
          dec &&
          (Array.isArray(dec) || dec instanceof Map || typeof dec === "object")
        )
          return dec;
        return null;
      } catch (_) {
        return null;
      }
    };
    // Helper: decode a JSON-bytes object (from convertToJSON) back to Uint8Array
    const fromJsonBytes = (obj) => {
      if (!obj || typeof obj !== "object") return null;
      if (obj._type === "bytes" && typeof obj._base64 === "string") {
        try {
          const bin = atob(obj._base64);
          const out = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
          return out;
        } catch (_) {
          return null;
        }
      }
      return null;
    };
    const unwrapTaggedOrCbor = (v) => {
      let cur = v;
      let changed = true;
      let guard = 0;
      while (changed && guard++ < 4) {
        changed = false;
        if (cur && cur.constructor && cur.constructor.name === "Tagged") {
          cur = cur.value;
          changed = true;
          continue;
        }
        // Also handle plain-object Tag(24) shapes coming from JSON snapshots
        if (
          cur &&
          typeof cur === "object" &&
          cur.tag === 24 &&
          cur.value !== undefined
        ) {
          let bytes = toUint8(cur.value);
          if (!bytes) bytes = fromJsonBytes(cur.value);
          if (bytes) {
            const dec = tryDecodeCBOR(bytes);
            if (dec != null) {
              cur = dec;
              changed = true;
              continue;
            }
          }
        }
        const u8 = toUint8(cur);
        if (u8) {
          const dec = tryDecodeCBOR(u8);
          if (dec != null) {
            cur = dec;
            changed = true;
            continue;
          }
        }
      }
      return cur;
    };

    const model = {
      version: getField(deviceResponse, "version") || "1.0",
      documents: [],
      rawJSON: null,
    };

    try {
      model.rawJSON = convertToJSON(deviceResponse);
    } catch (_) {
      model.rawJSON = null;
    }

    const documents = getField(deviceResponse, "documents");
    if (!Array.isArray(documents)) return model;

    // Helper to normalize a possibly CBOR.Tagged issuerSignedItem
    const normalizeIssuerItem = (item) => {
      let it = item;
      try {
        if (
          it &&
          it.constructor &&
          it.constructor.name === "Tagged" &&
          it.tag === 24
        ) {
          const bytes = new Uint8Array(it.value);
          it = CBOR.decode(bytes);
        }
        // Handle JSON-shaped tag/value as well
        else if (
          it &&
          typeof it === "object" &&
          it.tag === 24 &&
          it.value !== undefined
        ) {
          let bytes = toUint8(it.value);
          if (!bytes) bytes = fromJsonBytes(it.value);
          if (bytes) {
            it = CBOR.decode(bytes);
          }
        }
      } catch (_) {}
      return it;
    };

    const isPortraitField = (id) => {
      const s = String(id || "").toLowerCase();
      return (
        s.includes("portrait") ||
        s.includes("image") ||
        s.includes("photo") ||
        s.includes("signature_usual_mark")
      );
    };

    const detectBinary = (u8) => {
      let mimeType = "application/octet-stream";
      let formatLabel = "Unknown";
      if (u8 && u8.length >= 2) {
        if (u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) {
          mimeType = "image/jpeg";
          formatLabel = "JPEG";
        } else if (
          u8.length >= 12 &&
          u8[0] === 0x00 &&
          u8[1] === 0x00 &&
          u8[2] === 0x00 &&
          u8[3] === 0x0c &&
          u8[4] === 0x6a &&
          u8[5] === 0x50 &&
          u8[6] === 0x20 &&
          u8[7] === 0x20 &&
          u8[8] === 0x0d &&
          u8[9] === 0x0a &&
          u8[10] === 0x87 &&
          u8[11] === 0x0a
        ) {
          mimeType = "image/jp2";
          formatLabel = "JPEG2000";
        } else if (
          u8[0] === 0xff &&
          u8[1] === 0x4f &&
          u8.length >= 4 &&
          u8[2] === 0xff &&
          u8[3] === 0x51
        ) {
          mimeType = "image/jp2";
          formatLabel = "JPEG2000";
        }
      }
      return { mimeType, formatLabel };
    };

    const valueToEntry = (elementIdentifier, elementValue) => {
      // Default entry
      const entry = {
        elementIdentifier,
        label:
          typeof window !== "undefined" &&
          typeof window.formatFieldName === "function"
            ? window.formatFieldName(elementIdentifier)
            : String(elementIdentifier),
        valueKind: "text",
        text: "",
        raw: null,
        binary: null,
      };
      try {
        entry.raw = convertToJSON(elementValue);
      } catch (_) {
        entry.raw = null;
      }

      // Tagged values
      if (
        elementValue &&
        elementValue.constructor &&
        elementValue.constructor.name === "Tagged"
      ) {
        if (elementValue.tag === 1004) {
          // RFC3339 full-date string (YYYY-MM-DD)
          const dateStr = elementValue.value;
          let txt = String(dateStr);
          try {
            // Use locale short date (e.g., 10/30/2025) without time
            txt = new Date(dateStr).toLocaleDateString();
          } catch (_) {}
          entry.valueKind = "date";
          entry.text = txt;
          return entry;
        } else if (elementValue.tag === 0) {
          entry.valueKind = "time-rfc3339";
          entry.text = String(elementValue.value);
          return entry;
        } else if (elementValue.tag === 1) {
          entry.valueKind = "time-epoch";
          try {
            entry.text = new Date(elementValue.value * 1000).toLocaleString();
          } catch {
            entry.text = String(elementValue.value);
          }
          return entry;
        }
        // Fallback
        entry.valueKind = "tagged";
        entry.text = String(elementValue.value);
        return entry;
      }

      // Plain-object tag values (e.g., { tag:1004, value: "YYYY-MM-DD" })
      if (
        elementValue &&
        typeof elementValue === "object" &&
        typeof elementValue.tag === "number" &&
        elementValue.value !== undefined
      ) {
        if (elementValue.tag === 1004) {
          let txt = String(elementValue.value);
          try {
            txt = new Date(elementValue.value).toLocaleDateString();
          } catch {}
          entry.valueKind = "date";
          entry.text = txt;
          return entry;
        }
        if (elementValue.tag === 0) {
          entry.valueKind = "time-rfc3339";
          entry.text = String(elementValue.value);
          return entry;
        }
        if (elementValue.tag === 1) {
          entry.valueKind = "time-epoch";
          try {
            entry.text = new Date(elementValue.value * 1000).toLocaleString();
          } catch {
            entry.text = String(elementValue.value);
          }
          return entry;
        }
        // Other tags fall through to object handling below
      }

      // Binary
      if (
        elementValue instanceof Uint8Array ||
        ArrayBuffer.isView(elementValue)
      ) {
        const u8 =
          elementValue instanceof Uint8Array
            ? elementValue
            : new Uint8Array(
                elementValue.buffer,
                elementValue.byteOffset,
                elementValue.byteLength
              );
        const { mimeType, formatLabel } = detectBinary(u8);
        entry.valueKind = isPortraitField(elementIdentifier)
          ? "portrait"
          : "bytes";
        entry.text = `<binary ${u8.length} bytes>`;
        entry.binary = { length: u8.length, mimeType, formatLabel };
        try {
          if (mimeType !== "image/jp2") {
            const b64 = btoa(String.fromCharCode(...u8));
            entry.binary.dataUri = `data:${mimeType};base64,${b64}`;
          }
        } catch (_) {}
        return entry;
      }

      // JSON-shaped bytes object (from convertToJSON) -> treat as binary too
      if (
        elementValue &&
        elementValue._type === "bytes" &&
        elementValue._base64
      ) {
        try {
          const bin = atob(elementValue._base64);
          const u8 = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
          const { mimeType, formatLabel } = detectBinary(u8);
          entry.valueKind = isPortraitField(elementIdentifier)
            ? "portrait"
            : "bytes";
          entry.text = `<binary ${u8.length} bytes>`;
          entry.binary = { length: u8.length, mimeType, formatLabel };
          if (mimeType !== "image/jp2") {
            entry.binary.dataUri = `data:${mimeType};base64,${elementValue._base64}`;
          }
          return entry;
        } catch (_) {
          // fall through to object handling
        }
      }

      if (elementValue instanceof Date) {
        entry.valueKind = "date";
        try {
          entry.text = elementValue.toISOString().split("T")[0];
        } catch {
          entry.text = String(elementValue);
        }
        return entry;
      }
      if (typeof elementValue === "boolean") {
        entry.valueKind = "boolean";
        entry.text = elementValue ? "Yes" : "No";
        return entry;
      }
      if (typeof elementValue === "number") {
        entry.valueKind = "number";
        entry.text = String(elementValue);
        return entry;
      }
      if (Array.isArray(elementValue)) {
        entry.valueKind = "array";
        try {
          entry.text = JSON.stringify(elementValue);
        } catch {
          entry.text = String(elementValue);
        }
        return entry;
      }
      if (elementValue && typeof elementValue === "object") {
        entry.valueKind = "object";
        try {
          entry.text = JSON.stringify(convertToJSON(elementValue));
        } catch {
          entry.text = String(elementValue);
        }
        return entry;
      }

      // Fallback text
      entry.valueKind = "text";
      entry.text = String(elementValue ?? "");
      return entry;
    };

    for (const doc of documents) {
      const docModel = {
        docType: getField(doc, "docType") || "Unknown",
        issuerSigned: {
          nameSpaces: {},
          _rawNameSpaces: {}, // for debugging/renderer fallback
        },
        deviceSigned: null, // not expanded for now
        signature: null, // summary of issuerAuth
      };

      const issuerSigned = getField(doc, "issuerSigned");
      let nameSpaces = issuerSigned
        ? getFieldAny(issuerSigned, ["nameSpaces", 1])
        : null;
      // Unwrap CBOR-wrapped namespaces if needed
      nameSpaces = unwrapTaggedOrCbor(nameSpaces);
      if (nameSpaces) {
        const nsEntries =
          nameSpaces instanceof Map
            ? Array.from(nameSpaces.entries())
            : Object.entries(nameSpaces);
        for (const [nsName, nsItemsRaw] of nsEntries) {
          const items = [];
          // Unwrap namespace contents (may be Tagged or bstr.cbor)
          const nsItems = unwrapTaggedOrCbor(nsItemsRaw);
          // keep raw for fallback/diagnostics
          try {
            docModel.issuerSigned._rawNameSpaces[nsName] =
              convertToJSON(nsItems);
          } catch (_) {}

          // Case 1: Standard array of IssuerSignedItem
          if (Array.isArray(nsItems)) {
            for (let item of nsItems) {
              try {
                const it = unwrapTaggedOrCbor(normalizeIssuerItem(item));
                let elementIdentifier = getFieldAny(it, [
                  "elementIdentifier",
                  0,
                ]);
                let elementValue = getFieldAny(it, ["elementValue", 1]);
                if (elementIdentifier !== undefined) {
                  items.push(valueToEntry(elementIdentifier, elementValue));
                }
              } catch (_) {}
            }
          }

          // Case 2: Map of elementIdentifier -> elementValue or -> IssuerSignedItem
          else if (nsItems instanceof Map) {
            for (const [k, v] of nsItems.entries()) {
              try {
                const it = unwrapTaggedOrCbor(normalizeIssuerItem(v));
                let elementIdentifier = getFieldAny(it, [
                  "elementIdentifier",
                  0,
                ]);
                let elementValue = getFieldAny(it, ["elementValue", 1]);
                if (elementIdentifier === undefined) {
                  // Treat key as identifier and value as the element value
                  elementIdentifier = k;
                  elementValue = it;
                }
                items.push(valueToEntry(elementIdentifier, elementValue));
              } catch (_) {}
            }
          }

          // Case 3: Plain object of elementIdentifier -> value or -> IssuerSignedItem
          else if (nsItems && typeof nsItems === "object") {
            for (const [k, v] of Object.entries(nsItems)) {
              try {
                const it = unwrapTaggedOrCbor(normalizeIssuerItem(v));
                let elementIdentifier = getFieldAny(it, [
                  "elementIdentifier",
                  0,
                ]);
                let elementValue = getFieldAny(it, ["elementValue", 1]);
                if (elementIdentifier === undefined) {
                  elementIdentifier = k;
                  elementValue = it;
                }
                items.push(valueToEntry(elementIdentifier, elementValue));
              } catch (_) {}
            }
          }

          // Assign collected items (may be empty if truly empty)
          docModel.issuerSigned.nameSpaces[nsName] = items;
        }
      }

      // Signature summary (issuerAuth → COSE_Sign1)
      const issuerAuth = issuerSigned
        ? getField(issuerSigned, "issuerAuth")
        : null;
      if (issuerAuth) {
        try {
          let cose = issuerAuth;
          if (
            cose &&
            cose.constructor &&
            cose.constructor.name === "Tagged" &&
            cose.tag === 24
          ) {
            cose = CBOR.decode(new Uint8Array(cose.value));
          }
          if (Array.isArray(cose) && cose.length >= 4) {
            const [prot, unprot, payload /*, sig*/] = cose;
            let protectedData = {};
            if (prot && prot.length > 0) {
              try {
                const dec = CBOR.decode(new Uint8Array(prot));
                protectedData =
                  dec instanceof Map ? Object.fromEntries(dec) : dec;
              } catch (_) {}
            }
            const alg =
              protectedData[1] ||
              (unprot instanceof Map ? unprot.get(1) : unprot?.[1]);
            let algLabel = "Unknown";
            if (alg === -7) algLabel = "ES256 (ECDSA with SHA-256)";
            else if (alg === -35) algLabel = "ES384 (ECDSA with SHA-384)";
            else if (alg === -36) algLabel = "ES512 (ECDSA with SHA-512)";
            else if (alg === -8) algLabel = "EdDSA";
            else if (alg != null) algLabel = `Algorithm ${alg}`;

            const issuerCertRaw =
              unprot instanceof Map ? unprot.get(33) : unprot?.[33];
            const firstCert = Array.isArray(issuerCertRaw)
              ? issuerCertRaw[0]
              : issuerCertRaw;
            let certSummary = null;
            try {
              if (
                firstCert &&
                (firstCert instanceof Uint8Array ||
                  ArrayBuffer.isView(firstCert))
              ) {
                const der =
                  firstCert instanceof Uint8Array
                    ? firstCert
                    : new Uint8Array(
                        firstCert.buffer,
                        firstCert.byteOffset,
                        firstCert.byteLength
                      );
                const info = window.extractCertInfo
                  ? window.extractCertInfo(der)
                  : {};
                const validity = window.extractCertValidity
                  ? window.extractCertValidity(der)
                  : null;
                certSummary = {
                  subject: info.subjectDN || info.subjectCN || null,
                  issuer: info.issuerDN || info.issuerCN || null,
                  notBefore: validity?.notBefore || null,
                  notAfter: validity?.notAfter || null,
                };
              }
            } catch (_) {}

            // MSO summary from payload (robust across tags and key shapes)
            let mso = null;
            let msoSummary = null;
            try {
              const pBytes =
                payload instanceof Uint8Array
                  ? payload
                  : new Uint8Array(payload);
              mso = CBOR.decode(pBytes);
              // Unwrap Tag(24) bstr.cbor if present (instance or plain-object shape)
              let guard = 0;
              while (mso && guard++ < 3) {
                if (
                  mso &&
                  mso.constructor &&
                  mso.constructor.name === "Tagged" &&
                  mso.tag === 24 &&
                  mso.value
                ) {
                  const inner = toUint8(mso.value);
                  if (inner) {
                    mso = CBOR.decode(inner);
                    continue;
                  }
                }
                if (
                  mso &&
                  typeof mso === "object" &&
                  mso.tag === 24 &&
                  mso.value !== undefined
                ) {
                  const inner2 = toUint8(mso.value) || fromJsonBytes(mso.value);
                  if (inner2) {
                    mso = CBOR.decode(inner2);
                    continue;
                  }
                }
                break;
              }

              // Helper: robust field getter for both tstr and small-int keys
              const mget = (obj, keys) => {
                if (!obj) return undefined;
                for (const k of keys) {
                  const v = obj instanceof Map ? obj.get(k) : obj?.[k];
                  if (v !== undefined) return v;
                }
                return undefined;
              };

              // Normalize time values: supports Tag(0) RFC3339, Tag(1) epoch seconds, Tag(1004) full-date, Date or string
              const toISO = (v) => {
                if (v == null) return null;
                try {
                  // Handle CBOR.Tagged
                  if (v && v.constructor && v.constructor.name === "Tagged") {
                    if (v.tag === 0) {
                      // RFC3339 text already
                      return new Date(v.value).toISOString();
                    }
                    if (v.tag === 1) {
                      // Epoch seconds
                      return new Date(v.value * 1000).toISOString();
                    }
                    if (v.tag === 1004) {
                      // full-date YYYY-MM-DD
                      return new Date(v.value).toISOString();
                    }
                    // Other tags: try value recursively
                    return toISO(v.value);
                  }
                  // Handle plain-object tag shapes
                  if (
                    typeof v === "object" &&
                    typeof v.tag === "number" &&
                    v.value !== undefined
                  ) {
                    if (v.tag === 0) return new Date(v.value).toISOString();
                    if (v.tag === 1)
                      return new Date(v.value * 1000).toISOString();
                    if (v.tag === 1004) return new Date(v.value).toISOString();
                    return toISO(v.value);
                  }
                  if (v instanceof Date) return v.toISOString();
                  if (typeof v === "number")
                    return new Date(v * 1000).toISOString();
                  if (typeof v === "string") return new Date(v).toISOString();
                  return new Date(v).toISOString();
                } catch {
                  return null;
                }
              };

              const docType = mget(mso, ["docType", 0]);
              const validityInfo = mget(mso, ["validityInfo", 3]);
              const vf = validityInfo
                ? mget(validityInfo, ["validFrom", 1])
                : null;
              const vu = validityInfo
                ? mget(validityInfo, ["validUntil", 2])
                : null;
              const signedAt = validityInfo
                ? mget(validityInfo, ["signed", 0])
                : null;
              const digestAlgorithm = mget(mso, ["digestAlgorithm", 2]);
              console.log("mso:", mso);
              msoSummary = {
                docType: docType || null,
                signed: toISO(signedAt),
                validFrom: toISO(vf),
                validUntil: toISO(vu),
                digestAlgorithm: digestAlgorithm || null,
              };
            } catch (_) {}

            docModel.signature = {
              algorithm: algLabel,
              certificate: certSummary,
              mso: msoSummary,
              coseSign1: cose,
            };
          }
        } catch (_) {
          docModel.signature = null;
        }
      }

      model.documents.push(docModel);
    }

    return model;
  }

  // Decrypt COSE_Encrypt0 → DeviceResponse object (no rendering)
  async function decryptCoseEncrypt0ToObject(encryptedData) {
    const CBOR = getCBOR();
    const coseEnc0 = CBOR.decode(encryptedData);
    if (!Array.isArray(coseEnc0) || coseEnc0.length !== 3)
      throw new Error(
        "Invalid COSE_Encrypt0 structure - expected 3-element array"
      );
    const [protectedHeaderBytes, unprotectedHeader, ciphertext] = coseEnc0;
    // Read IV from unprotected header (header key 5)
    const iv =
      unprotectedHeader instanceof Map
        ? unprotectedHeader.get(5)
        : unprotectedHeader?.[5];
    if (!iv) throw new Error("No IV found in unprotected header");
    const plaintext = await aesGcmDecrypt(
      new Uint8Array(ciphertext),
      window.skDevice ? new Uint8Array(window.skDevice) : null,
      new Uint8Array(iv),
      ""
    );
    return CBOR.decode(plaintext);
  }

  // Decrypt SessionEstablishment.data (raw AES-GCM) → DeviceResponse object
  async function decryptSessionEstablishmentDataToObject(encryptedData) {
    const mdocIdentifier = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]);
    const counter = 1;
    const iv = new Uint8Array(12);
    iv.set(mdocIdentifier, 0);
    new DataView(iv.buffer, 8, 4).setUint32(0, counter, false);
    const plaintext = await aesGcmDecrypt(
      encryptedData,
      window.skDevice ? new Uint8Array(window.skDevice) : null,
      iv,
      new Uint8Array(0)
    );
    return getCBOR().decode(plaintext);
  }

  // Public API (pure functions only)
  window.WalletResponse = {
    aesGcmDecrypt,
    decryptCoseEncrypt0ToObject,
    decryptSessionEstablishmentDataToObject,
    buildResponseViewModel,
    convertToJSON,
    // Legacy aliases for backward compatibility (return objects; no DOM side-effects)
    decryptSessionEstablishmentData: decryptSessionEstablishmentDataToObject,
    decryptAndDisplayResponse: async function (encryptedData) {
      // Previously decrypted and displayed; now returns the decoded object
      return await decryptCoseEncrypt0ToObject(encryptedData);
    },
    // Back-compat shim: deprecated name returns the view model
    displayDeviceResponse: function (deviceResponse) {
      console.warn(
        "[WalletResponse] displayDeviceResponse is deprecated; use buildResponseViewModel instead."
      );
      return buildResponseViewModel(deviceResponse);
    },
  };

  // All DOM/HTML helpers removed from this module
})();
