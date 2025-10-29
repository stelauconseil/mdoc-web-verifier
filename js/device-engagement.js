/*
  Copyright (c) 2025 Stelau
  Author: Nicolas Chalanset

  Device Engagement module
  Parses mdoc URI, extracts DeviceEngagement, BLE options, and wallet eSenderKey
*/

(function () {
  function getCBOR() {
    return window.CBOR || self.CBOR || self.cbor;
  }
  const log = window.log || console.log;
  const enc = new TextEncoder();
  function hex(buf) {
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }

  function b64ToBytesBrowserSafe(b64) {
    b64 = b64.replace(/\s+/g, "").replace(/[^A-Za-z0-9+/=]/g, "");
    const pad = b64.length % 4 === 0 ? 0 : 4 - (b64.length % 4);
    b64 += "=".repeat(pad);
    const raw = atob(b64);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  // Some keyboard-wedge laser scanners substitute base64url characters.
  // Normalize common artifacts to valid base64url before decoding.
  function normalizeScannerArtifacts(s) {
    return (
      s
        // Known substitutions observed: '!' -> '_' and '§' -> '-'
        .replace(/!/g, "_")
        .replace(/§/g, "-")
        // Normalize various dash characters to simple hyphen-minus
        .replace(/[–—−\u2010\u2011\u2012\u2013\u2014\u2212\uFF0D]/g, "-")
        // Normalize fullwidth underscore if ever present
        .replace(/[\uFF3F]/g, "_")
    );
  }
  function b64urlToBytesSafe(maybeB64Url) {
    let s = maybeB64Url.trim();
    try {
      s = decodeURIComponent(s);
    } catch (_) {}
    // Apply normalization for scanner substitutions BEFORE url-safe to base64
    s = normalizeScannerArtifacts(s);
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    return b64ToBytesBrowserSafe(s);
  }
  function looksLikeHex(s) {
    const cleaned = s.replace(/[\s:]/g, "");
    return cleaned.length >= 2 && /^[0-9A-Fa-f]+$/.test(cleaned);
  }
  function hexToBytes(s) {
    const cleaned = s.replace(/[\s:]/g, "");
    const out = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2)
      out[i / 2] = parseInt(cleaned.substr(i, 2), 16);
    return out;
  }

  function extractCborFromMdocUri(uri) {
    let s = uri.trim();
    const schemeMatch = s.match(/^[A-Za-z]+:/);
    if (schemeMatch) s = s.slice(schemeMatch[0].length);

    if (/^data:application\/cbor;base64,/i.test(s)) {
      const b64 = s.split(",")[1] || "";
      return b64ToBytesBrowserSafe(b64);
    }
    const qm = s.indexOf("?");
    if (qm >= 0) {
      const params = new URLSearchParams(s.slice(qm + 1));
      const cand = params.get("de") || params.get("data") || params.get("ep");
      if (!cand) throw new Error("mdoc URI has query but no DE param");
      if (looksLikeHex(cand)) return hexToBytes(cand);
      return b64urlToBytesSafe(cand);
    }
    if (/[;,]/.test(s)) {
      const parts = s
        .split(/[;,]/)
        .map((p) => p.trim())
        .filter(Boolean)
        .sort((a, b) => b.length - a.length);
      for (const part of parts) {
        try {
          const sub = part.replace(/^(de2?|ep|data):/i, "");
          if (looksLikeHex(sub)) return hexToBytes(sub);
          return b64urlToBytesSafe(sub);
        } catch (_) {}
      }
    }
    if (looksLikeHex(s)) return hexToBytes(s);
    try {
      return b64urlToBytesSafe(s);
    } catch (e) {}
    const m = uri.match(/[A-Za-z0-9\-_]{20,}={0,2}/);
    if (m) return b64urlToBytesSafe(m[0]);
    throw new Error("Unable to locate/normalize CBOR payload in mdoc URI");
  }

  function tryExtractBleOptions(root) {
    const isUUIDStr = (s) =>
      typeof s === "string" &&
      /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
        s
      );
    const asUuidString = (bytes) => {
      if (!(bytes instanceof Uint8Array) || bytes.length !== 16) return null;
      const h = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(
        16,
        20
      )}-${h.slice(20)}`;
    };
    const takeFirst = (found) => {
      if (found.uuidStr)
        return {
          uuidStr: found.uuidStr.toLowerCase(),
          uuidBytes: null,
          addrBytes: found.addrBytes || null,
        };
      if (found.uuidBytes)
        return {
          uuidBytes: found.uuidBytes,
          uuidStr: null,
          addrBytes: found.addrBytes || null,
        };
      return null;
    };
    const found = { uuidBytes: null, uuidStr: null, addrBytes: null };
    function readBleOptions(opts) {
      if (!opts) return;
      const scanKV = (k, v) => {
        if (
          (k === 10 ||
            k === 11 ||
            k === "uuid" ||
            k === "serviceUuid" ||
            k === "service_uuid") &&
          v
        ) {
          if (!found.uuidBytes && v instanceof Uint8Array && v.length === 16)
            found.uuidBytes = v;
          if (!found.uuidStr && isUUIDStr(v)) found.uuidStr = v;
        }
        if (
          (k === 20 ||
            k === "bleDeviceAddress" ||
            k === "address" ||
            k === "mac" ||
            k === "addr") &&
          v instanceof Uint8Array
        ) {
          if (!found.addrBytes) found.addrBytes = v;
        }
        if (v && typeof v === "object") {
          if (v instanceof Map) {
            for (const [kk, vv] of v.entries()) scanKV(kk, vv);
          } else {
            for (const kk of Object.keys(v)) scanKV(kk, v[kk]);
          }
        }
      };
      if (opts instanceof Map) {
        for (const [k, v] of opts.entries()) scanKV(k, v);
      } else if (typeof opts === "object") {
        for (const k of Object.keys(opts)) scanKV(k, opts[k]);
      }
    }
    function isBleMethod(node) {
      if (!node) return false;
      const typeNum =
        node instanceof Map
          ? node.has(0)
            ? node.get(0)
            : node.get("type") ?? node.get("t")
          : typeof node === "object"
          ? node.type ?? node.t ?? node[0]
          : undefined;
      if (typeNum === 2) return true;
      const getStr = (k) => {
        if (node instanceof Map)
          return (node.get(k) ?? "").toString().toLowerCase();
        if (typeof node === "object")
          return (node[k] ?? "").toString().toLowerCase();
        return "";
      };
      const tstr = [getStr("transport"), getStr("method"), getStr("type")].join(
        " "
      );
      return ["ble", "bluetooth", "bluetoothle", "gatt"].some((s) =>
        tstr.includes(s)
      );
    }
    function getMethodOptions(node) {
      if (!node) return null;
      if (node instanceof Map) {
        if (node.has(2)) return node.get(2);
        if (node.has("options")) return node.get("options");
        return (
          node.get("peripheral") ||
          node.get("server") ||
          node.get("central") ||
          null
        );
      } else if (typeof node === "object") {
        return (
          node[2] ||
          node.options ||
          node.peripheral ||
          node.server ||
          node.central ||
          null
        );
      }
      return null;
    }
    function dfs(node) {
      if (!node) return;
      if (isBleMethod(node)) {
        readBleOptions(getMethodOptions(node));
        if (takeFirst(found)) return;
      }
      if (Array.isArray(node) && node.length >= 3 && node[0] === 2) {
        readBleOptions(node[2]);
        if (takeFirst(found)) return;
      }
      if (Array.isArray(node)) {
        for (const it of node) dfs(it);
        return;
      }
      if (node instanceof Map) {
        for (const [k, v] of node.entries()) dfs(v);
        return;
      }
      if (typeof node === "object") {
        for (const k of Object.keys(node)) dfs(node[k]);
      }
    }
    dfs(root);
    return takeFirst(found);
  }

  function parseMdocUriAndDE(uri) {
    const CBOR = getCBOR();
    if (!CBOR) throw new Error("CBOR library not available");
    const deBytes = extractCborFromMdocUri(uri);
    let de;
    try {
      de = CBOR.decode(deBytes);
    } catch (_e) {
      const maybe = CBOR.decode(deBytes);
      if (
        maybe instanceof CBOR.Tagged &&
        maybe.tag === 24 &&
        maybe.value instanceof Uint8Array
      ) {
        de = CBOR.decode(maybe.value);
      } else {
        throw new Error("CBOR decode failed for Device Engagement");
      }
    }
    const bo = tryExtractBleOptions(de);
    if (!bo) throw new Error("BLE options not found in Device Engagement");
    const asUuidString = (bytes) => {
      if (!(bytes instanceof Uint8Array) || bytes.length !== 16) return null;
      const h = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(
        16,
        20
      )}-${h.slice(20)}`;
    };
    const uuid = bo.uuidStr
      ? bo.uuidStr
      : bo.uuidBytes
      ? asUuidString(bo.uuidBytes)
      : null;
    const addr = bo.addrBytes
      ? Array.from(bo.addrBytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(":")
      : null;

    let coseKey = null;
    if (Array.isArray(de?.security)) {
      for (let i = 0; i < de.security.length; i++) {
        const sec = de.security[i];
        if (sec instanceof Map && sec.has(33)) {
          coseKey = sec.get(33);
          break;
        }
        if (typeof sec === "object" && 33 in sec) {
          coseKey = sec[33];
          break;
        }
      }
      if (!coseKey) {
        for (let i = 0; i < de.security.length; i++) {
          const sec = de.security[i];
          if (sec instanceof Map && sec.has(3)) {
            coseKey = sec.get(3);
            break;
          }
          if (typeof sec === "object" && 3 in sec) {
            coseKey = sec[3];
            break;
          }
        }
      }
    } else if (de?.security) {
      const sec = de.security;
      if (sec instanceof Map) {
        if (sec.has(33)) coseKey = sec.get(33);
        else if (sec.has(3)) coseKey = sec.get(3);
      } else if (typeof sec === "object") {
        if (33 in sec) coseKey = sec[33];
        else if (3 in sec) coseKey = sec[3];
      }
    }
    if (!coseKey) {
      const CBOR = getCBOR();
      const scan = (o) => {
        if (!o) return null;
        if (
          o instanceof CBOR.Tagged &&
          o.tag === 24 &&
          o.value instanceof Uint8Array
        ) {
          try {
            const decoded = CBOR.decode(o.value);
            if (decoded instanceof Map) {
              if (
                decoded.get(1) === 2 &&
                decoded.get(-1) &&
                decoded.get(-2) &&
                decoded.get(-3)
              )
                return decoded;
            } else if (
              typeof decoded === "object" &&
              decoded[1] === 2 &&
              decoded[-1] &&
              decoded[-2] &&
              decoded[-3]
            )
              return decoded;
          } catch (_) {}
        }
        if (o instanceof Map) {
          if (o.get(1) === 2 && o.get(-1) && o.get(-2) && o.get(-3)) return o;
          for (const [k, v] of o.entries()) {
            const r = scan(v);
            if (r) return r;
          }
        } else if (typeof o === "object" && !Array.isArray(o)) {
          if (o[1] === 2 && o[-1] && o[-2] && o[-3]) return o;
          for (const [k, v] of Object.entries(o)) {
            const r = scan(v);
            if (r) return r;
          }
        } else if (Array.isArray(o)) {
          for (let i = 0; i < o.length; i++) {
            const r = scan(o[i]);
            if (r) return r;
          }
        }
        return null;
      };
      coseKey = scan(de);
    }
    if (!coseKey) throw new Error("mdoc ephemeral COSE_Key not found in DE");
    const getField = (k) =>
      coseKey instanceof Map ? coseKey.get(k) : coseKey[k];
    const xField = getField(-2) || getField("x");
    const yField = getField(-3) || getField("y");
    const x = new Uint8Array(xField);
    const y = new Uint8Array(yField);
    if (x.length !== 32 || y.length !== 32)
      throw new Error(
        `Invalid COSE_Key coordinates: x=${x.length}, y=${y.length}`
      );
    return { deBytes, uuid, addr, x, y, coseKey };
  }

  window.DeviceEngagement = {
    b64ToBytesBrowserSafe,
    b64urlToBytesSafe,
    looksLikeHex,
    hexToBytes,
    extractCborFromMdocUri,
    tryExtractBleOptions,
    parseMdocUriAndDE,
  };
})();
