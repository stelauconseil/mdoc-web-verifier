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

  // --- Safe Base64 for large Uint8Array (avoids spread argument limits) ---
  function bytesToBase64(u8) {
    if (!u8 || u8.length === 0) return "";
    try {
      // Fast path for small buffers
      if (u8.length < 0x8000) {
        return btoa(String.fromCharCode.apply(null, u8));
      }
    } catch (e) {
      console.log("bytesToBase64: fallback for large array", e);
      // fall through to chunked path
    }
    let s = "";
    for (let i = 0; i < u8.length; i += 0x8000) {
      const chunk = u8.subarray(i, Math.min(i + 0x8000, u8.length));
      s += String.fromCharCode.apply(null, chunk);
    }
    return btoa(s);
  }

  // --- Minimal BER-TLV helpers for ICAO DG parsing ---
  function readTag(bytes, offset = 0) {
    let i = offset;
    if (i >= bytes.length) throw new Error("readTag: out of range");
    const first = bytes[i++];
    let tagBytes = [first];
    // Long-form tag if low 5 bits are all ones (0x1F)
    if ((first & 0x1f) === 0x1f) {
      // Subsequent bytes with MSB=1 indicate continuation
      while (i < bytes.length) {
        const b = bytes[i++];
        tagBytes.push(b);
        if ((b & 0x80) === 0) break;
      }
    }
    const tagHex = tagBytes
      .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
      .join("");
    return { tagHex, next: i, constructed: (tagBytes[0] & 0x20) === 0x20 };
  }
  function readLength(bytes, offset = 0) {
    if (offset >= bytes.length) throw new Error("readLength: out of range");
    let lenByte = bytes[offset++];
    if ((lenByte & 0x80) === 0) {
      // short form
      return { length: lenByte, next: offset };
    }
    const numBytes = lenByte & 0x7f;
    if (numBytes === 0) throw new Error("Indefinite length not supported");
    let length = 0;
    for (let i = 0; i < numBytes; i++) {
      if (offset >= bytes.length)
        throw new Error("readLength: truncated length");
      length = (length << 8) | bytes[offset++];
    }
    return { length, next: offset };
  }
  function findTLV(bytes, start, end, targetTags) {
    // Depth-first scan; enter constructed values to find nested TLVs
    const limit = Math.min(end, bytes.length);
    let i = Math.max(0, start | 0);
    while (i < limit) {
      const { tagHex, next: afterTag, constructed } = readTag(bytes, i);
      if (afterTag >= limit) break;
      const { length, next: afterLen } = readLength(bytes, afterTag);
      const vStart = afterLen;
      const vEnd = Math.min(afterLen + length, limit);
      if (targetTags.has(tagHex)) {
        return { tagHex, start: vStart, end: vEnd };
      }
      if (constructed && length > 0) {
        const inner = findTLV(bytes, vStart, vEnd, targetTags);
        if (inner) return inner;
      }
      i = vEnd;
    }
    return null;
  }

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
        s === "fac" || // mICOV attestation face image
        s.includes("face") ||
        s.includes("signature_usual_mark") ||
        s === "dg2" // ICAO 9303 DG2 is biometric template (portrait)
      );
    };

    // ICAO 9303 Data Group decoder
    const decodeICAODataGroup = (elementIdentifier, u8) => {
      const id = String(elementIdentifier).toLowerCase();

      if (id === "dg1") {
        // DG1 contains Machine Readable Zone (MRZ)
        return decodeICAODG1(u8);
      } else if (id === "dg2") {
        // DG2 contains biometric template (portrait)
        return decodeICAODG2(u8);
      }
      // Add more DGs as needed (DG3-DG16)
      return null;
    };

    // Decode ICAO 9303 DG1 (Machine Readable Zone)
    const decodeICAODG1 = (u8) => {
      try {
        // DG1 outer wrapper is typically 0x61 (constructed). We search its value for 5F1F (MRZ).
        let start = 0,
          end = u8.length;
        if (u8[0] === 0x61) {
          const lenInfo = readLength(u8, 1);
          start = lenInfo.next;
          end = Math.min(start + lenInfo.length, u8.length);
        }

        // Locate the MRZ value (5F1F) inside the DG1 content
        const mrzTlv = findTLV(u8, start, end, new Set(["5F1F"]));
        let mrzBytes;
        if (mrzTlv) {
          mrzBytes = u8.slice(mrzTlv.start, mrzTlv.end);
          console.log("DG1: Found MRZ (5F1F), size:", mrzBytes.length);
        } else {
          // Fallback: some encodings may present 5F1F at start of the content; detect and strip
          let off = start;
          if (u8[off] === 0x5f && u8[off + 1] === 0x1f) {
            const lenInfo2 = readLength(u8, off + 2);
            mrzBytes = u8.slice(
              lenInfo2.next,
              Math.min(lenInfo2.next + lenInfo2.length, end)
            );
            console.warn(
              "DG1: 5F1F detected at start; using its value slice. Size:",
              mrzBytes.length
            );
          } else {
            // Last resort: treat content as plain ASCII and attempt to clean a stray leading tag/len
            mrzBytes = u8.slice(start, end);
            console.warn(
              "DG1: 5F1F not found; using raw DG1 content as MRZ candidate (size:",
              mrzBytes.length,
              ")"
            );
          }
        }

        // Sanitize ASCII: keep printable + '<'; drop control chars
        let mrzText = new TextDecoder("ascii", { fatal: false }).decode(
          mrzBytes
        );
        mrzText = mrzText.replace(/[\x00\r\n]+/g, "");
        // If the content accidentally starts with 0x5F 0x1F and a single printable (length echo like 'Z'), strip them
        if (
          mrzText.length >= 3 &&
          mrzText.charCodeAt(0) === 0x5f &&
          mrzText.charCodeAt(1) === 0x1f
        ) {
          // Drop first 3 chars (tag + one length byte heuristic)
          mrzText = mrzText.slice(3);
        }

        // Split into known MRZ line formats
        const lines = splitMrzIntoLines(mrzText);
        // Determine MRZ format (TD1 3x30, TD2 2x36, TD3 2x44)
        let format = null;
        if (lines && lines.length === 3 && lines.every((l) => l.length === 30))
          format = "TD1";
        else if (
          lines &&
          lines.length === 2 &&
          lines.every((l) => l.length === 44)
        )
          format = "TD3";
        else if (
          lines &&
          lines.length === 2 &&
          lines.every((l) => l.length === 36)
        )
          format = "TD2";
        console.log("📄 Decoded ICAO DG1 (MRZ) lines:", lines);

        return {
          type: "mrz",
          lines,
          text: lines.join("\n"),
          parsed: parseMRZ(lines),
          format,
        };
      } catch (e) {
        console.error("❌ Failed to decode ICAO DG1:", e);
        return null;
      }
    };

    // Heuristic splitter for MRZ text into lines (TD1 3x30, TD2 2x36, TD3 2x44)
    function splitMrzIntoLines(s) {
      const t = (s || "").replace(/\s+/g, "");
      const L = t.length;
      if (L === 0) return [];

      // Prefer exact-length patterns; do not infer by leading 'P' or 'ID' since 2-line MRZ exist for both
      const candidates = [
        { w: 44, n: 2 }, // TD3
        { w: 36, n: 2 }, // TD2
        { w: 30, n: 3 }, // TD1
      ];

      const exact = candidates.find(({ w, n }) => L === w * n);
      if (exact) {
        const out = [];
        for (let i = 0; i < exact.n; i++)
          out.push(t.slice(i * exact.w, (i + 1) * exact.w));
        return out;
      }

      // Allow small slack (+2) seen in some encodings
      for (const { w, n } of candidates) {
        if (L >= w * n && L <= w * n + 2) {
          const out = [];
          for (let i = 0; i < n; i++) out.push(t.slice(i * w, (i + 1) * w));
          if (out.every((line) => line.length === w)) return out;
        }
      }

      // Fallbacks: exact multiples
      if (L % 44 === 0 && L / 44 <= 3) return t.match(/.{44}/g) || [t];
      if (L % 36 === 0 && L / 36 <= 3) return t.match(/.{36}/g) || [t];
      if (L % 30 === 0 && L / 30 <= 3) return t.match(/.{30}/g) || [t];

      // Approximate by closest 2-line or 3-line split
      if (L > 0) {
        const mid = Math.floor(L / 2);
        if (L >= 60 && L <= 92) return [t.slice(0, mid), t.slice(mid)];
        const w = Math.floor(L / 3) || L;
        return [t.slice(0, w), t.slice(w, 2 * w), t.slice(2 * w)];
      }
      return [t];
    }

    // Decode ICAO 9303 DG2 (Biometric Template)
    const decodeICAODG2 = (u8) => {
      try {
        // DG2 structure: tag 0x75, length, biometric info template
        let offset = 0;

        // Skip tag and length
        if (u8[offset] === 0x75) {
          offset++; // Skip tag
          let length = u8[offset++];
          if (length & 0x80) {
            const lengthBytes = length & 0x7f;
            length = 0;
            for (let i = 0; i < lengthBytes; i++) {
              length = (length << 8) | u8[offset++];
            }
          }
        }

        // Parse biometric info template (tag 0x7F61)
        if (u8[offset] === 0x7f && u8[offset + 1] === 0x61) {
          offset += 2; // Skip tag
          let bioLength = u8[offset++];
          if (bioLength & 0x80) {
            const lengthBytes = bioLength & 0x7f;
            bioLength = 0;
            for (let i = 0; i < lengthBytes; i++) {
              bioLength = (bioLength << 8) | u8[offset++];
            }
          }
        }

        // Look for biometric data block (tag 0x5F2E) and extract embedded image inside it
        while (offset < u8.length - 2) {
          if (u8[offset] === 0x5f && u8[offset + 1] === 0x2e) {
            offset += 2; // Skip tag
            let dataLength = u8[offset++];
            if (dataLength & 0x80) {
              const lengthBytes = dataLength & 0x7f;
              dataLength = 0;
              for (let i = 0; i < lengthBytes; i++) {
                dataLength = (dataLength << 8) | u8[offset++];
              }
            }

            // Extract the Biometric Data Block (may contain header + image)
            const bdb = u8.slice(offset, offset + dataLength);

            // Try to locate an actual image inside the BDB
            const embedded = (function extractEmbeddedImageFromBDB(bytes) {
              const findAt = (sig) => {
                for (let i = 0; i <= bytes.length - sig.length; i++) {
                  let ok = true;
                  for (let j = 0; j < sig.length; j++) {
                    if (bytes[i + j] !== sig[j]) {
                      ok = false;
                      break;
                    }
                  }
                  if (ok) return i;
                }
                return -1;
              };
              const sigJPEG = [0xff, 0xd8, 0xff];
              const sigJP2 = [
                0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a,
                0x87, 0x0a,
              ];
              const sigJ2K = [0xff, 0x4f, 0xff, 0x51];
              const idxJP2 = findAt(sigJP2);
              const idxJ2K = findAt(sigJ2K);
              const idxJPG = findAt(sigJPEG);
              let kind = null;
              let idx = -1;
              // Prefer JP2/J2K if present, else JPEG
              if (idxJP2 >= 0) {
                kind = "jp2";
                idx = idxJP2;
              } else if (idxJ2K >= 0) {
                kind = "j2k";
                idx = idxJ2K;
              } else if (idxJPG >= 0) {
                kind = "jpeg";
                idx = idxJPG;
              }
              if (idx >= 0) {
                return { kind, bytes: bytes.slice(idx) };
              }
              return null;
            })(bdb);

            const imageData = embedded ? embedded.bytes : bdb;
            console.log(
              "🖼️ Decoded ICAO DG2 (Portrait), image bytes:",
              imageData.length,
              embedded ? `(embedded ${embedded.kind})` : "(raw BDB)"
            );

            return {
              type: "portrait",
              imageData: imageData,
              length: imageData.length,
            };
          }
          offset++;
        }

        console.warn("⚠️ No biometric data found in DG2");
        return null;
      } catch (e) {
        console.error("❌ Failed to decode ICAO DG2:", e);
        return null;
      }
    };

    // Basic MRZ parser for TD1 (3x30), TD2 (2x36), TD3 (2x44)
    const parseMRZ = (lines) => {
      if (!lines || lines.length === 0) return null;
      try {
        const L = lines.map((l) => (l ? l.trim() : ""));
        const parsed = {};

        // TD1: 3x30
        if (
          L.length === 3 &&
          L[0].length === 30 &&
          L[1].length === 30 &&
          L[2].length === 30
        ) {
          const [l1, l2, l3] = L;
          parsed.documentType = l1.substring(0, 1);
          parsed.issuingCountry = l1.substring(2, 5);
          // Document number (l1 6–14) and nationality (l2 16–18) approximate extraction
          parsed.documentNumber = l1.substring(5, 14).replace(/</g, "").trim();
          parsed.nationality = l2.substring(15, 18);
          parsed.dateOfBirth = l2.substring(0, 6);
          parsed.sex = l2.substring(7, 8);
          parsed.expirationDate = l2.substring(8, 14);
          // Names (l3) "SURNAME<<GIVEN<NAMES" style
          const names = l3.split("<<");
          parsed.surname = (names[0] || "").replace(/</g, " ").trim();
          parsed.givenNames = (names[1] || "").replace(/</g, " ").trim();
          return parsed;
        }

        // TD2: 2x36
        if (L.length === 2 && L[0].length === 36 && L[1].length === 36) {
          const [l1, l2] = L;
          parsed.documentType = l1.substring(0, 1);
          parsed.issuingCountry = l1.substring(2, 5);
          // Names from l1
          const names = l1.substring(5).split("<<");
          parsed.surname = (names[0] || "").replace(/</g, " ").trim();
          parsed.givenNames = (names[1] || "").replace(/</g, " ").trim();
          // Line 2 fields
          parsed.documentNumber = l2.substring(0, 9).replace(/</g, "").trim();
          parsed.nationality = l2.substring(10, 13);
          parsed.dateOfBirth = l2.substring(13, 19);
          parsed.sex = l2.substring(20, 21);
          parsed.expirationDate = l2.substring(21, 27);
          return parsed;
        }

        // TD3: 2x44 (passports)
        if (L.length === 2 && L[0].length === 44 && L[1].length === 44) {
          const [l1, l2] = L;
          parsed.documentType = l1.substring(0, 2).trim();
          parsed.issuingCountry = l1.substring(2, 5);
          const names = l1.substring(5).split("<<");
          parsed.surname = (names[0] || "").replace(/</g, " ").trim();
          parsed.givenNames = (names[1] || "").replace(/</g, " ").trim();
          parsed.passportNumber = l2.substring(0, 9).replace(/</g, "").trim();
          parsed.nationality = l2.substring(10, 13);
          parsed.dateOfBirth = l2.substring(13, 19);
          parsed.sex = l2.substring(20, 21);
          parsed.expirationDate = l2.substring(21, 27);
          return parsed;
        }

        // Unknown format: return best-effort keys
        parsed.raw = L;
        return parsed;
      } catch (e) {
        console.error("❌ Failed to parse MRZ:", e);
        return null;
      }
    };

    const detectBinary = (u8) => {
      let mimeType = "application/octet-stream";
      let formatLabel = "Unknown";
      if (u8 && u8.length >= 2) {
        // JPEG/JFIF: starts with FF D8 FF
        if (u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) {
          mimeType = "image/jpeg";
          // Check if it's specifically JFIF (FF D8 FF E0 ... JFIF)
          if (
            u8.length >= 11 &&
            u8[3] === 0xe0 &&
            u8[6] === 0x4a &&
            u8[7] === 0x46 &&
            u8[8] === 0x49 &&
            u8[9] === 0x46
          ) {
            formatLabel = "JFIF";
          } else {
            formatLabel = "JPEG";
          }
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

    // Helper: decode JPEG2000 to JPEG data URL using openjpeg and canvas
    function jp2ToJpegDataUrl(u8) {
      try {
        console.log("🖼️ Attempting JP2 to JPEG conversion, bytes:", u8.length);
        if (typeof openjpeg === "undefined") {
          console.warn(
            "⚠️ openjpeg not available for JP2 conversion - check if openjpeg.js loaded properly"
          );
          return null;
        }
        console.log("✅ openjpeg available, parsing...");

        // Convert Uint8Array to regular array for openjpeg
        const dataArray = Array.from(u8);
        const result = openjpeg(dataArray, "jp2");

        if (!result || !result.data || !result.width || !result.height) {
          console.warn("⚠️ openjpeg returned invalid result:", result);
          return null;
        }

        console.log(
          "📐 JP2 parsed, dimensions:",
          result.width,
          "x",
          result.height
        );

        const { width, height, data } = result;

        // Create canvas and convert planar RGB data to RGBA
        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        const imageData = ctx.createImageData(width, height);

        console.log("🎨 Converting planar RGB to RGBA ImageData...");

        // Convert 24-bit planar RGB to 32-bit RGBA
        // openjpeg returns data as [R0,R1,R2...Rn, G0,G1,G2...Gn, B0,B1,B2...Bn]
        const pixelCount = width * height;
        for (let i = 0; i < pixelCount; i++) {
          const r = data[i]; // Red plane
          const g = data[i + pixelCount]; // Green plane
          const b = data[i + 2 * pixelCount]; // Blue plane

          const rgba_idx = i * 4;
          imageData.data[rgba_idx] = r; // R
          imageData.data[rgba_idx + 1] = g; // G
          imageData.data[rgba_idx + 2] = b; // B
          imageData.data[rgba_idx + 3] = 255; // A (fully opaque)
        }

        ctx.putImageData(imageData, 0, 0);

        const dataUrl = canvas.toDataURL("image/jpeg", 0.92);
        console.log(
          "✅ JP2 to JPEG conversion successful, data URL length:",
          dataUrl.length
        );
        return dataUrl;
      } catch (e) {
        console.error("❌ JP2 to JPEG conversion failed:", e);
        return null;
      }
    }

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

        // Check if this is an ICAO 9303 data group
        const icaoData = decodeICAODataGroup(elementIdentifier, u8);
        if (icaoData) {
          if (icaoData.type === "mrz") {
            entry.valueKind = "mrz";
            entry.text = icaoData.text;
            entry.icao = icaoData;
            console.log("✅ Decoded ICAO DG1 (MRZ) for", elementIdentifier);
            return entry;
          } else if (icaoData.type === "portrait" && icaoData.imageData) {
            // Process the extracted image data instead of the full DG2
            const imgU8 = icaoData.imageData;
            let { mimeType, formatLabel } = detectBinary(imgU8);
            entry.valueKind = "portrait";
            entry.text = `<ICAO portrait ${imgU8.length} bytes>`;
            entry.binary = { length: imgU8.length, mimeType, formatLabel };
            entry.icao = icaoData;

            // Handle portrait conversion/display
            if (imgU8.length === 0) {
              entry.binary.empty = true;
              return entry;
            }
            if (
              mimeType === "image/jp2" &&
              isPortraitField(elementIdentifier)
            ) {
              console.log(
                "🖼️ Processing JPEG2000 ICAO portrait field:",
                elementIdentifier
              );
              const dataUrl = jp2ToJpegDataUrl(imgU8);
              if (dataUrl) {
                console.log(
                  "✅ JP2 conversion successful for ICAO",
                  elementIdentifier
                );
                entry.binary.converted = true;
                entry.binary.convertedFrom = mimeType;
                entry.binary.mimeType = "image/jpeg";
                entry.binary.formatLabel = "JPEG (converted)";
                entry.binary.dataUri = dataUrl;
              } else {
                console.warn(
                  "❌ JP2 conversion failed for ICAO",
                  elementIdentifier
                );
              }
            } else {
              if (imgU8.length > 0) {
                const b64 = bytesToBase64(imgU8);
                entry.binary.dataUri = `data:${mimeType};base64,${b64}`;
              }
            }
            console.log(
              "✅ Decoded ICAO DG2 (Portrait) for",
              elementIdentifier
            );
            return entry;
          }
        }

        // Standard binary handling for non-ICAO data
        let { mimeType, formatLabel } = detectBinary(u8);
        entry.valueKind = isPortraitField(elementIdentifier)
          ? "portrait"
          : "bytes";
        entry.text = `<binary ${u8.length} bytes>`;
        entry.binary = { length: u8.length, mimeType, formatLabel };
        try {
          // If portrait has 0 bytes, don't produce a data URI so UI won't render an <img>
          if (isPortraitField(elementIdentifier) && u8.length === 0) {
            entry.binary.empty = true;
            return entry;
          }
          if (mimeType === "image/jp2" && isPortraitField(elementIdentifier)) {
            const dataUrl = jp2ToJpegDataUrl(u8);
            if (dataUrl) {
              entry.binary.converted = true;
              entry.binary.convertedFrom = mimeType;
              entry.binary.mimeType = "image/jpeg";
              entry.binary.formatLabel = "JPEG - converted from JPEG2000";
              entry.binary.dataUri = dataUrl;
            }
          } else {
            if (u8.length > 0) {
              const b64 = bytesToBase64(u8);
              entry.binary.dataUri = `data:${mimeType};base64,${b64}`;
            }
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
          let { mimeType, formatLabel } = detectBinary(u8);
          entry.valueKind = isPortraitField(elementIdentifier)
            ? "portrait"
            : "bytes";
          entry.text = `<binary ${u8.length} bytes>`;
          entry.binary = { length: u8.length, mimeType, formatLabel };
          // If portrait has 0 bytes, don't produce a data URI so UI won't render an <img>
          if (isPortraitField(elementIdentifier) && u8.length === 0) {
            entry.binary.empty = true;
            return entry;
          }
          if (mimeType === "image/jp2" && isPortraitField(elementIdentifier)) {
            const dataUrl = jp2ToJpegDataUrl(u8);
            if (dataUrl) {
              entry.binary.converted = true;
              entry.binary.convertedFrom = mimeType;
              entry.binary.mimeType = "image/jpeg";
              entry.binary.formatLabel = "JPEG - converted from JPEG2000";
              entry.binary.dataUri = dataUrl;
              return entry;
            }
          }
          if (u8.length > 0) {
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
