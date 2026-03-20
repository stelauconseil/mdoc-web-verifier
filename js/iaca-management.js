/*
  Copyright (c) 2026 Stelau
  Author: Nicolas Chalanset

  IACA Management module
  Extracted IACA storage and UI helpers
*/

(function () {
    function getCBOR() {
        return window.CBOR || self.CBOR || self.cbor;
    }
    // Storage keys
    const IACA_STORAGE_KEY = "mdoc_iaca_certificates";
    const IACA_VERSION_KEY = "mdoc_iaca_version";
    // Version used only for default IACA bundle migrations (independent from PWA/app version)
    const IACA_DATA_VERSION = 50;

    // Initialize IACA storage with defaults
    function initializeIACAs() {
        const storedVersion =
            parseInt(localStorage.getItem(IACA_VERSION_KEY)) || 0;
        let stored = localStorage.getItem(IACA_STORAGE_KEY);

        if (storedVersion < IACA_DATA_VERSION) {
            console.log(
                `Updating IACA certificates from version ${storedVersion} to ${IACA_DATA_VERSION}`,
            );
            let userAddedCerts = [];
            if (stored) {
                try {
                    const existingIacas = JSON.parse(stored);
                    userAddedCerts = existingIacas.filter((iaca) => {
                        return !(
                            Array.isArray(window.DEFAULT_IACA_CERTIFICATES) &&
                            window.DEFAULT_IACA_CERTIFICATES.some(
                                (defaultCert) => defaultCert.pem === iaca.pem,
                            )
                        );
                    });
                    console.log(
                        `Preserving ${userAddedCerts.length} user-added certificate(s)`,
                    );
                } catch (e) {
                    console.error(
                        "Failed to parse stored IACAs during update:",
                        e,
                    );
                }
            }
            const updatedIacas = [
                ...(window.DEFAULT_IACA_CERTIFICATES || []),
                ...userAddedCerts,
            ];
            localStorage.setItem(
                IACA_STORAGE_KEY,
                JSON.stringify(updatedIacas),
            );
            localStorage.setItem(IACA_VERSION_KEY, String(IACA_DATA_VERSION));
            console.log(
                `IACA certificates updated: ${
                    (window.DEFAULT_IACA_CERTIFICATES || []).length
                } default(s), ${userAddedCerts.length} user-added`,
            );
            return updatedIacas;
        }

        if (!stored) {
            localStorage.setItem(
                IACA_STORAGE_KEY,
                JSON.stringify(window.DEFAULT_IACA_CERTIFICATES || []),
            );
            localStorage.setItem(IACA_VERSION_KEY, String(IACA_DATA_VERSION));
            return window.DEFAULT_IACA_CERTIFICATES || [];
        }

        try {
            const iacas = JSON.parse(stored);
            iacas.forEach((iaca) => {
                if (iaca.active === undefined) iaca.active = true;
            });
            return iacas;
        } catch (e) {
            console.error("Failed to parse stored IACAs, using defaults:", e);
            localStorage.setItem(
                IACA_STORAGE_KEY,
                JSON.stringify(window.DEFAULT_IACA_CERTIFICATES || []),
            );
            localStorage.setItem(IACA_VERSION_KEY, String(IACA_DATA_VERSION));
            return window.DEFAULT_IACA_CERTIFICATES || [];
        }
    }

    function getIACAs() {
        return initializeIACAs();
    }
    function getActiveIACAs() {
        return getIACAs().filter((iaca) => iaca.active !== false);
    }

    function parsePEMCertificate(pem) {
        try {
            const b64 = pem
                .replace(/-----BEGIN CERTIFICATE-----/, "")
                .replace(/-----END CERTIFICATE-----/, "")
                .replace(/\s+/g, "");
            const binaryString = atob(b64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++)
                bytes[i] = binaryString.charCodeAt(i);
            let subject = "Unknown";
            let subjectDN = null;
            try {
                const certInfo = window.extractCertInfo
                    ? window.extractCertInfo(bytes)
                    : null;
                if (certInfo && certInfo.subjectCN)
                    subject = certInfo.subjectCN;
                if (certInfo && certInfo.subjectDN)
                    subjectDN = certInfo.subjectDN;
            } catch (e) {
                console.warn(
                    "Could not extract subject CN, trying fallback method",
                );
                const certStr = new TextDecoder("utf-8", {
                    fatal: false,
                }).decode(bytes);
                const cnMatch = certStr.match(/CN=([^,\n\r]+)/);
                if (cnMatch) subject = cnMatch[1].trim();
            }
            return { subject, subjectDN, bytes, pem };
        } catch (e) {
            console.error("Failed to parse PEM certificate:", e);
            return null;
        }
    }

    // Normalize a PEM certificate for comparison (return base64 body only)
    function pemToB64Body(pem) {
        try {
            return pem
                .replace(/-----BEGIN CERTIFICATE-----/g, "")
                .replace(/-----END CERTIFICATE-----/g, "")
                .replace(/\s+/g, "")
                .trim();
        } catch {
            return (pem || "").trim();
        }
    }

    async function pemToCryptoKey(pem) {
        try {
            const b64 = pem
                .replace(/-----BEGIN CERTIFICATE-----/, "")
                .replace(/-----END CERTIFICATE-----/, "")
                .replace(/\s+/g, "");
            const binaryString = atob(b64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++)
                bytes[i] = binaryString.charCodeAt(i);
            const key = await window.extractPublicKeyFromCert(bytes);
            if (!key) {
                console.error(
                    "Failed to extract public key from IACA certificate",
                );
                return null;
            }
            return key;
        } catch (e) {
            if (e.name === "DataError") {
                console.error(
                    "IACA certificate is missing, invalid, or has an unsupported key format:",
                    e.message,
                );
            } else {
                console.error(
                    "Failed to import certificate as CryptoKey:",
                    e.message,
                );
            }
            return null;
        }
    }

    function addIACA(pem, name = null, isTest = false) {
        const certInfo = parsePEMCertificate(pem);
        if (!certInfo) throw new Error("Invalid PEM certificate format");
        const iacas = getIACAs();
        // Compare using normalized base64 bodies to avoid whitespace/line-break dupes
        const incomingB64 = pemToB64Body(pem);
        if (
            iacas.some((i) => {
                try {
                    return pemToB64Body(i.pem) === incomingB64;
                } catch {
                    return i.pem === pem; // fallback exact
                }
            })
        )
            throw new Error("This certificate is already installed");
        // Store a canonical PEM built from DER bytes to keep formatting consistent
        const canonicalPem = (function () {
            try {
                return derToPem(certInfo.bytes);
            } catch {
                return pem.trim();
            }
        })();
        const newIACA = {
            name: name || certInfo.subject || "Unknown Certificate",
            pem: canonicalPem,
            issuer: certInfo.subject || "Unknown",
            addedAt: new Date().toISOString(),
            active: true,
            test: isTest,
        };
        iacas.push(newIACA);
        localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(iacas));
        return newIACA;
    }

    // === VICAL (Verified Issuer CA List) import ===
    function derToPem(derBytes) {
        const b64 = btoa(String.fromCharCode(...derBytes));
        const lines = b64.match(/.{1,64}/g) || [];
        return [
            "-----BEGIN CERTIFICATE-----",
            ...lines,
            "-----END CERTIFICATE-----",
            "",
        ].join("\n");
    }

    function normalizeBytesMaybeArray(val) {
        if (val instanceof Uint8Array) return val;
        if (Array.isArray(val) && val.length && typeof val[0] === "number")
            return new Uint8Array(val);
        if (val && val.buffer && typeof val.length === "number")
            return new Uint8Array(val);
        return null;
    }

    function extractPemFromEntry(entry) {
        // Returns an array of normalized entries: [{pem, name?, test?}, ...]
        const out = [];

        // Helper: base64url decode
        const b64urlToBytes = (s) => {
            try {
                const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
                const pad =
                    b64.length % 4 === 2
                        ? "=="
                        : b64.length % 4 === 3
                          ? "="
                          : "";
                const raw = atob(b64 + pad);
                const bytes = new Uint8Array(raw.length);
                for (let i = 0; i < raw.length; i++)
                    bytes[i] = raw.charCodeAt(i);
                return bytes;
            } catch (_) {
                return null;
            }
        };

        // Accept various shapes: pem string, base64/base64url DER, DER bytes, { certificate, der, pem, x5c }
        if (typeof entry === "string") {
            if (entry.includes("BEGIN CERTIFICATE")) {
                out.push({ pem: entry });
                return out;
            }
            // Try base64 and base64url
            let der = null;
            try {
                der = Uint8Array.from(atob(entry.replace(/\s+/g, "")), (c) =>
                    c.charCodeAt(0),
                );
            } catch (_) {}
            if (!der) der = b64urlToBytes(entry);
            if (der && der.length > 100) {
                out.push({ pem: derToPem(der) });
                return out;
            }
        }
        const CBOR = getCBOR();
        if (entry instanceof CBOR?.Tagged && entry.tag === 24) {
            try {
                const inner = CBOR.decode(new Uint8Array(entry.value));
                const nested = extractPemFromEntry(inner);
                if (nested && nested.length) out.push(...nested);
                return out;
            } catch (_) {}
        }
        if (entry instanceof Uint8Array) {
            out.push({ pem: derToPem(entry) });
            return out;
        }
        if (Array.isArray(entry)) {
            // Could be a byte array or an x5c array
            const der = normalizeBytesMaybeArray(entry);
            if (der && der.length > 100) {
                out.push({ pem: derToPem(der) });
                return out;
            }
            // If array of mixed cert candidates, try each
            for (const it of entry) {
                const nested = extractPemFromEntry(it);
                if (nested && nested.length) out.push(...nested);
            }
            return out;
        }
        if (entry && typeof entry === "object") {
            // Common direct keys
            if (typeof entry.pem === "string")
                out.push({
                    pem: entry.pem,
                    name: entry.name,
                    test: !!entry.test,
                });
            const der = normalizeBytesMaybeArray(
                entry.der ||
                    entry.certificate ||
                    entry.iaca ||
                    entry.bytes ||
                    entry.cert,
            );
            if (der && der.length > 100)
                out.push({
                    pem: derToPem(der),
                    name: entry.name,
                    test: !!entry.test,
                });

            // x5c chains (array of base64/base64url DER strings or byte arrays)
            if (Array.isArray(entry.x5c)) {
                for (const c of entry.x5c) {
                    if (typeof c === "string") {
                        let bytes = null;
                        try {
                            bytes = Uint8Array.from(
                                atob(c.replace(/\s+/g, "")),
                                (ch) => ch.charCodeAt(0),
                            );
                        } catch (_) {}
                        if (!bytes) bytes = b64urlToBytes(c);
                        if (bytes && bytes.length > 100)
                            out.push({ pem: derToPem(bytes) });
                    } else {
                        const b = normalizeBytesMaybeArray(c);
                        if (b && b.length > 100) out.push({ pem: derToPem(b) });
                    }
                }
            }

            // Additional known keys with arrays of certs
            const arrayKeys = [
                "certs",
                "certificates",
                "iacaList",
                "iacas",
                "list",
                "trustAnchors",
                "trustedCAs",
                "trustedCertificates",
                "x509Certificates",
                "anchors",
                "roots",
                "rootCAs",
                "root_ca_certs",
                "trusted_list",
                "pemCertificates",
                "derCertificates",
                "certChain",
                "chain",
                "rootsPEM",
                "rootsDER",
            ];
            for (const k of arrayKeys) {
                if (Array.isArray(entry[k])) {
                    for (const it of entry[k]) {
                        const nested = extractPemFromEntry(it);
                        if (nested && nested.length) out.push(...nested);
                    }
                }
            }

            if (out.length) return out;
        }
        return out;
    }

    function decodeVICALRoot(root) {
        const out = [];
        const pushMaybe = (item) => {
            const norms = extractPemFromEntry(item);
            if (Array.isArray(norms) && norms.length) {
                for (const n of norms) if (n && n.pem) out.push(n);
            }
        };
        if (!root) return out;
        const CBOR = getCBOR();
        // Unwrap tag(24, bstr .cbor ...)
        if (root instanceof CBOR?.Tagged && root.tag === 24) {
            try {
                return decodeVICALRoot(CBOR.decode(new Uint8Array(root.value)));
            } catch (_) {}
        }
        // Handle COSE_Sign1 wrapper: [protected, unprotected, payload(bstr), signature]
        if (Array.isArray(root) && root.length === 4) {
            const payload = root[2];
            if (payload instanceof Uint8Array || (payload && payload.buffer)) {
                try {
                    const inner = CBOR.decode(
                        new Uint8Array(
                            payload.buffer || payload,
                            payload.byteOffset || 0,
                            payload.byteLength || payload.length,
                        ),
                    );
                    return decodeVICALRoot(inner);
                } catch (_) {
                    // fall through to generic array handling
                }
            }
        }
        // Generic array of entries
        if (Array.isArray(root)) {
            for (const it of root) pushMaybe(it);
            return out;
        }
        // Map/object forms: search common keys that may hold arrays of certs
        const keyCandidates = [
            "certs",
            "certificates",
            "iacaList",
            "iacas",
            "list",
            "trustAnchors",
            "trustedCAs",
            "trustedCertificates",
            "x509Certificates",
            "anchors",
            "roots",
            "rootCAs",
            "root_ca_certs",
            "trusted_list",
        ];
        if (root instanceof Map) {
            for (const k of keyCandidates) {
                const v = root.get(k);
                if (Array.isArray(v)) {
                    v.forEach(pushMaybe);
                    return out;
                }
            }
            // Or values of the map might themselves be entries
            for (const v of root.values()) pushMaybe(v);
            return out;
        }
        if (typeof root === "object") {
            for (const k of keyCandidates) {
                const v = root[k];
                if (Array.isArray(v)) {
                    v.forEach(pushMaybe);
                    return out;
                }
            }
            for (const v of Object.values(root)) pushMaybe(v);
            return out;
        }
        // Fallback single entry
        pushMaybe(root);
        return out;
    }

    function countVICALCandidates(root) {
        const CBOR = getCBOR();
        // Unwrap tag(24)
        if (root instanceof CBOR?.Tagged && root.tag === 24) {
            try {
                return countVICALCandidates(
                    CBOR.decode(new Uint8Array(root.value)),
                );
            } catch (_) {}
        }
        // COSE_Sign1 wrapper
        if (Array.isArray(root) && root.length === 4) {
            const payload = root[2];
            if (payload instanceof Uint8Array || (payload && payload.buffer)) {
                try {
                    const inner = CBOR.decode(
                        new Uint8Array(
                            payload.buffer || payload,
                            payload.byteOffset || 0,
                            payload.byteLength || payload.length,
                        ),
                    );
                    return countVICALCandidates(inner);
                } catch (_) {}
            }
            // Not a recognized COSE payload: fall back to array length
            return root.length;
        }
        // Heuristic: only count items that look like cert candidates
        const looksLikeCandidate = (val) => {
            if (!val) return false;
            if (typeof val === "string") {
                if (val.includes("BEGIN CERTIFICATE")) return true;
                // base64/base64url-ish and long enough
                return (
                    /^[A-Za-z0-9_\-+=\/\s]+$/.test(val) &&
                    val.replace(/\s+/g, "").length > 80
                );
            }
            if (val instanceof Uint8Array) return val.length > 80;
            if (Array.isArray(val)) {
                if (val.length && typeof val[0] === "number")
                    return val.length > 80; // bytes
                // array of sub-entries
                return val.some(looksLikeCandidate);
            }
            if (val && typeof val === "object") {
                if (typeof val.pem === "string") return true;
                if (
                    normalizeBytesMaybeArray(
                        val.der ||
                            val.certificate ||
                            val.iaca ||
                            val.bytes ||
                            val.cert,
                    )
                )
                    return true;
                if (Array.isArray(val.x5c)) return val.x5c.length > 0;
                const keys = [
                    "certs",
                    "certificates",
                    "iacaList",
                    "iacas",
                    "list",
                    "trustAnchors",
                    "trustedCAs",
                    "trustedCertificates",
                    "x509Certificates",
                    "anchors",
                    "roots",
                    "rootCAs",
                    "root_ca_certs",
                    "trusted_list",
                    "pemCertificates",
                    "derCertificates",
                    "certChain",
                    "chain",
                    "rootsPEM",
                    "rootsDER",
                ];
                return keys.some(
                    (k) => Array.isArray(val[k]) && val[k].length > 0,
                );
            }
            return false;
        };
        if (Array.isArray(root))
            return root.filter(looksLikeCandidate).length || root.length;
        const keyCandidates = [
            "certs",
            "certificates",
            "iacaList",
            "iacas",
            "list",
            "trustAnchors",
            "trustedCAs",
            "trustedCertificates",
            "x509Certificates",
            "anchors",
            "roots",
            "rootCAs",
            "root_ca_certs",
            "trusted_list",
        ];
        if (root instanceof Map) {
            for (const k of keyCandidates) {
                const v = root.get(k);
                if (Array.isArray(v))
                    return (
                        v.reduce(
                            (acc, it) => acc + (looksLikeCandidate(it) ? 1 : 0),
                            0,
                        ) || v.length
                    );
            }
            return (
                [...root.values()].filter(looksLikeCandidate).length ||
                [...root.values()].length
            );
        }
        if (root && typeof root === "object") {
            for (const k of keyCandidates) {
                const v = root[k];
                if (Array.isArray(v))
                    return (
                        v.reduce(
                            (acc, it) => acc + (looksLikeCandidate(it) ? 1 : 0),
                            0,
                        ) || v.length
                    );
            }
            return (
                Object.values(root).filter(looksLikeCandidate).length ||
                Object.keys(root).length
            );
        }
        return 1;
    }

    async function importVICALFromBytes(bytes, opts = {}) {
        const { markTest = false } = opts || {};
        const CBOR = getCBOR();
        if (!CBOR) throw new Error("CBOR library not available");
        let root = CBOR.decode(bytes);
        if (root instanceof CBOR.Tagged && root.tag === 24) {
            try {
                root = CBOR.decode(new Uint8Array(root.value));
            } catch (_) {}
        }
        const entries = decodeVICALRoot(root);
        const candidates = countVICALCandidates(root);
        let imported = 0,
            skipped = 0,
            errors = 0;
        for (const e of entries) {
            try {
                const isTest = markTest || !!e.test;
                addIACA(e.pem, e.name || null, isTest);
                imported++;
            } catch (err) {
                if (/already installed/i.test(err.message)) skipped++;
                else errors++;
            }
        }
        localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(getIACAs()));
        const unknown = Math.max(
            0,
            (typeof candidates === "number" ? candidates : entries.length) -
                entries.length,
        );
        if (unknown > 0 && (window.DEBUG_VERBOSE || window.DEBUG_CERT)) {
            try {
                console.warn(
                    `[VICAL] Unknown entries detected: ${unknown} (candidates=${candidates}, extracted=${entries.length})`,
                );
            } catch {}
        }
        return {
            total: entries.length,
            imported,
            skipped,
            errors,
            unknown,
            candidates,
        };
    }

    // Import from an already-parsed JS object (JSON shape). Mirrors importVICALFromBytes semantics.
    async function importVICALFromObject(rootObject, opts = {}) {
        const { markTest = false } = opts || {};
        const entries = decodeVICALRoot(rootObject);
        const candidates = countVICALCandidates(rootObject);
        let imported = 0,
            skipped = 0,
            errors = 0;
        for (const e of entries) {
            try {
                const isTest = markTest || !!e.test;
                addIACA(e.pem, e.name || null, isTest);
                imported++;
            } catch (err) {
                if (/already installed/i.test(err.message)) skipped++;
                else errors++;
            }
        }
        localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(getIACAs()));
        const unknown = Math.max(
            0,
            (typeof candidates === "number" ? candidates : entries.length) -
                entries.length,
        );
        return {
            total: entries.length,
            imported,
            skipped,
            errors,
            unknown,
            candidates,
        };
    }

    async function importVICALFromUri(uri, opts = {}) {
        opts = opts || {};
        // Support data:application/cbor;base64,... or http(s) URIs
        try {
            if (/^data:application\/cbor;base64,/i.test(uri)) {
                const b64 = uri.split(",")[1] || "";
                const raw = atob(b64);
                const bytes = new Uint8Array(raw.length);
                for (let i = 0; i < raw.length; i++)
                    bytes[i] = raw.charCodeAt(i);
                return await importVICALFromBytes(bytes, opts);
            }
        } catch (_) {}

        // Helper: sleep with Promise
        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

        // Helper: parse Retry-After header (seconds or HTTP-date)
        const parseRetryAfter = (val) => {
            if (!val) return null;
            const secs = parseInt(val, 10);
            if (!Number.isNaN(secs)) return Math.max(0, secs * 1000);
            const dateMs = Date.parse(val);
            if (!Number.isNaN(dateMs)) return Math.max(0, dateMs - Date.now());
            return null;
        };

        // Helper: perform fetch with sensible Accept headers and retry on transient errors
        const doFetch = async (u, { attempts = 3, baseDelay = 800 } = {}) => {
            let lastErr = null;
            for (let i = 0; i < attempts; i++) {
                try {
                    const res = await fetch(u, {
                        headers: {
                            Accept: 'application/cbor, application/cose; cose-type="cose-sign1", application/cwt, application/octet-stream, application/json;q=0.9, */*;q=0.8',
                        },
                        redirect: "follow",
                    });
                    if (res.ok) {
                        const contentType = (
                            res.headers.get("content-type") || ""
                        ).toLowerCase();
                        if (
                            contentType.includes("application/json") ||
                            contentType.includes("text/json")
                        ) {
                            const text = await res.text();
                            try {
                                const obj = JSON.parse(text);
                                return { kind: "json", value: obj };
                            } catch (e) {
                                const ab = new TextEncoder().encode(
                                    text,
                                ).buffer;
                                return {
                                    kind: "bytes",
                                    value: new Uint8Array(ab),
                                };
                            }
                        }
                        if (
                            contentType.includes("application/cbor") ||
                            contentType.includes("application/cose") ||
                            contentType.includes("application/cwt") ||
                            contentType.includes("application/octet-stream")
                        ) {
                            const ab = await res.arrayBuffer();
                            return { kind: "bytes", value: new Uint8Array(ab) };
                        }
                        // Unknown content-type: try bytes, then text
                        try {
                            const ab = await res.arrayBuffer();
                            return { kind: "bytes", value: new Uint8Array(ab) };
                        } catch (_) {
                            const text = await res.text();
                            return { kind: "text", value: text };
                        }
                    }
                    // Not ok: maybe transient? 429 or 5xx
                    const status = res.status;
                    const retryable =
                        status === 429 || (status >= 500 && status <= 599);
                    if (retryable && i < attempts - 1) {
                        // Compute delay
                        const ra = parseRetryAfter(
                            res.headers.get("retry-after"),
                        );
                        const delay =
                            ra != null
                                ? ra
                                : Math.floor(
                                      baseDelay * Math.pow(2, i) +
                                          Math.random() * 300,
                                  );
                        if (window.DEBUG_VERBOSE) {
                            try {
                                console.warn(
                                    `[VICAL] Fetch ${status}, retrying in ${delay}ms (attempt ${
                                        i + 2
                                    }/${attempts})`,
                                );
                            } catch {}
                        }
                        await sleep(delay);
                        continue;
                    }
                    // Non-retryable or out of attempts
                    lastErr = new Error(`Fetch failed: ${status}`);
                    break;
                } catch (e) {
                    // Network/CORS errors present as TypeError in browsers; don't loop endlessly
                    lastErr = e;
                    break;
                }
            }
            throw lastErr || new Error("Fetch failed");
        };

        // First try direct fetch
        let fetched = await doFetch(uri);

        // Decode based on fetched.kind
        if (fetched.kind === "bytes") {
            return await importVICALFromBytes(fetched.value, opts);
        }
        if (fetched.kind === "json") {
            return await importVICALFromObject(fetched.value, opts);
        }
        if (fetched.kind === "text") {
            const text = fetched.value || "";
            // Heuristics: try data URI, base64, base64url, or JWT (JWS) payload
            if (/^data:application\/cbor;base64,/i.test(text.trim())) {
                return await importVICALFromUri(text.trim(), opts);
            }
            // Base64/base64url blob
            const b64ish = text.trim().replace(/\s+/g, "");
            const looksB64 =
                /^[A-Za-z0-9_\-+=\/]+$/.test(b64ish) && b64ish.length > 80;
            if (looksB64) {
                try {
                    const raw = atob(
                        b64ish.replace(/-/g, "+").replace(/_/g, "/"),
                    );
                    const bytes = new Uint8Array(raw.length);
                    for (let i = 0; i < raw.length; i++)
                        bytes[i] = raw.charCodeAt(i);
                    return await importVICALFromBytes(bytes, opts);
                } catch (_) {}
            }
            // Minimal JWS support: if it looks like a JWT, decode the payload and try JSON
            const parts = text.trim().split(".");
            if (parts.length === 3) {
                try {
                    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
                    const pad =
                        b64.length % 4 === 2
                            ? "=="
                            : b64.length % 4 === 3
                              ? "="
                              : "";
                    const payloadRaw = atob(b64 + pad);
                    const payloadText = new TextDecoder().decode(
                        new Uint8Array(
                            Array.from(payloadRaw, (c) => c.charCodeAt(0)),
                        ),
                    );
                    const obj = JSON.parse(payloadText);
                    return await importVICALFromObject(obj, opts);
                } catch (_) {}
            }
            // Give up with a helpful error
            throw new Error(
                "Unsupported VICAL content from URI: not CBOR/COSE/JSON/text we can parse",
            );
        }
        throw new Error("Unsupported VICAL response type");
    }

    async function importVICALFromFile(file, opts = {}) {
        const ab = await file.arrayBuffer();
        return await importVICALFromBytes(new Uint8Array(ab), opts);
    }

    function removeIACA(index) {
        const iacas = getIACAs();
        if (index >= 0 && index < iacas.length) {
            const removed = iacas.splice(index, 1);
            localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(iacas));
            return removed[0];
        }
        return null;
    }

    function toggleIACAStatus(index) {
        const iacas = getIACAs();
        if (index >= 0 && index < iacas.length) {
            iacas[index].active = !iacas[index].active;
            localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(iacas));
            return iacas[index];
        }
        return null;
    }

    async function updateIACAList() {
        const iacaListEl = document.getElementById("iacaList");
        const iacas = getIACAs();
        if (!iacaListEl) return;

        // Update summary counts in header, if present
        try {
            const summaryEl = document.getElementById("iacaSummaryCounts");
            if (summaryEl) {
                const live = iacas.filter((i) => i.test !== true).length;
                const test = iacas.filter((i) => i.test === true).length;
                summaryEl.textContent = `Installed: Live ${live} • Test ${test}`;
            }
        } catch {}

        if (iacas.length === 0) {
            iacaListEl.innerHTML =
                '<div class="muted" style="font-style: italic;">No certificates installed</div>';
            return;
        }

        let html = '<div style="display: grid; gap: 0.75rem;">';
        for (let index = 0; index < iacas.length; index++) {
            const iaca = iacas[index];
            const isDefault =
                Array.isArray(window.DEFAULT_IACA_CERTIFICATES) &&
                index < window.DEFAULT_IACA_CERTIFICATES.length;
            const isActive = iaca.active !== false;
            const isTest = iaca.test === true;
            const statusColor = isActive ? "#059669" : "#94a3b8";
            const statusText = isActive ? "● Active" : "○ Inactive";
            const bgOpacity = isActive ? "1" : "0.6";
            const testBadge = isTest
                ? '<div style="font-size: 0.8rem; color: #f59e0b; margin-top: 0.25rem; font-weight: 500;">⚠️ Test/Development Certificate</div>'
                : "";

            let certDetails = "";
            try {
                const certInfo = parsePEMCertificate(iaca.pem);
                if (certInfo) {
                    // const parsed = window.parseX509Certificate
                    //     ? window.parseX509Certificate(certInfo.bytes)
                    //     : null;
                    const validity = window.extractCertValidity
                        ? window.extractCertValidity(certInfo.bytes)
                        : {};
                    const sha256Hash = await crypto.subtle.digest(
                        "SHA-256",
                        certInfo.bytes,
                    );
                    const hexThumbprint = Array.from(new Uint8Array(sha256Hash))
                        .map((b) => b.toString(16).padStart(2, "0"))
                        .join(":")
                        .toUpperCase();
                    const subjectDisplay = certInfo.subjectDN || iaca.issuer;

                    let cryptoLabel = null;
                    try {
                        const pubKey = await window.extractPublicKeyFromCert(
                            certInfo.bytes,
                            true,
                        );
                        if (pubKey && pubKey.nobleCurveName) {
                            const map = {
                                p256: "ECDSA P-256 (secp256r1)",
                                p384: "ECDSA P-384 (secp384r1)",
                                p521: "ECDSA P-521 (secp521r1)",
                                brainpoolP256r1: "ECDSA brainpoolP256r1",
                                brainpoolP320r1: "ECDSA brainpoolP320r1",
                                brainpoolP384r1: "ECDSA brainpoolP384r1",
                                brainpoolP512r1: "ECDSA brainpoolP512r1",
                            };
                            cryptoLabel =
                                map[pubKey.nobleCurveName] ||
                                `ECDSA (${pubKey.nobleCurveName})`;
                        } else if (window.detectCurveFromCertOID) {
                            const detected = window.detectCurveFromCertOID(
                                certInfo.bytes,
                            );
                            if (detected) {
                                const map = {
                                    "P-256": "ECDSA P-256 (secp256r1)",
                                    "P-384": "ECDSA P-384 (secp384r1)",
                                    "P-521": "ECDSA P-521 (secp521r1)",
                                    brainpoolP256r1: "ECDSA brainpoolP256r1",
                                    brainpoolP320r1: "ECDSA brainpoolP320r1",
                                    brainpoolP384r1: "ECDSA brainpoolP384r1",
                                    brainpoolP512r1: "ECDSA brainpoolP512r1",
                                };
                                cryptoLabel =
                                    map[detected] || `ECDSA (${detected})`;
                            }
                        }
                    } catch {}
                    const defaultBadge = isDefault
                        ? '<div style="font-size: 0.8rem; color: #059669; margin: 0.25rem 0 0.5rem;">✓ Default certificate</div>'
                        : "";

                    certDetails = `
            <div id="iaca-details-${index}" style="display: none; margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid rgba(148,163,184,0.25);">
              <div style="font-size: 0.85rem; color: #475569;">
                ${defaultBadge}
                <div style="margin-bottom: 0.5rem;">
                  <strong>Subject:</strong>
                  <div style="color: #1e293b; font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.8rem; margin-top: 0.25rem; word-break: break-all; line-height: 1.4;">${
                      window.escapeHtml
                          ? window.escapeHtml(subjectDisplay)
                          : subjectDisplay
                  }</div>
                </div>
                ${
                    cryptoLabel
                        ? `<div style="margin-bottom: 0.5rem;"><strong>Crypto:</strong> <span style="color: #1e293b;">${cryptoLabel}</span></div>`
                        : ""
                }
                ${
                    validity.notBefore
                        ? `<div style="margin-bottom: 0.5rem;">
                  <strong>Valid From:</strong> <span style="color: #1e293b;">📅 ${validity.notBefore.toLocaleString()}</span>
                </div>`
                        : ""
                }
                ${
                    validity.notAfter
                        ? `<div style="margin-bottom: 0.5rem;">
                  <strong>Valid Until:</strong> <span style="color: #1e293b;">📅 ${validity.notAfter.toLocaleString()}</span>
                </div>`
                        : ""
                }
                <div style="margin-bottom: 0.5rem;">
                  <strong>SHA-256 Fingerprint:</strong> 
                  <div style="font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.75rem; color: #1e293b; margin-top: 0.25rem; word-break: break-all;">${hexThumbprint}</div>
                </div>
                <div style="margin-top: 0.75rem;">
                  <button onclick="viewIACAPEM(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #0ea5e9;">
                    📄 View PEM
                  </button>
                  <button onclick="copyIACAPEM(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #059669;">
                    📋 Copy PEM
                  </button>
                </div>
              </div>
            </div>
          `;
                }
            } catch (e) {
                console.error("Error parsing certificate details:", e);
            }

            html += `
        <div style="background: #f8fafc; border: 1px solid rgba(148,163,184,0.25); border-radius: 8px; padding: 0.75rem; opacity: ${bgOpacity};">
          <div style="display: flex; justify-content: space-between; align-items: start;">
            <div style="flex: 1;">
              <div style="display: flex; align-items: center; gap: 0.5rem;">
                <div style="font-weight: 600; color: #0f172a;">${
                    window.escapeHtml ? window.escapeHtml(iaca.name) : iaca.name
                }</div>
                <div style="font-size: 0.8rem; color: ${statusColor}; font-weight: 500;">${statusText}</div>
              </div>
              <div style="font-size: 0.85rem; color: #64748b; margin-top: 0.25rem;">${
                  window.escapeHtml
                      ? window.escapeHtml(iaca.issuer)
                      : iaca.issuer
              }</div>
              ${testBadge}
            </div>
            <div style="display: flex; gap: 0.5rem; align-items: center;">
              ${
                  certDetails
                      ? `<button onclick="toggleIACADetails(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #64748b; display: inline-flex; align-items: center; gap: 0.35rem;">
                <span id="iaca-details-icon-${index}">▶</span> Details
              </button>`
                      : ""
              }
              <button onclick="toggleIACACert(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: ${
                  isActive ? "#64748b" : "#059669"
              };">
                ${isActive ? "Deactivate" : "Activate"}
              </button>
              ${
                  !isDefault
                      ? `<button onclick="removeIACACert(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #dc2626;">Remove</button>`
                      : ""
              }
            </div>
          </div>
          ${certDetails}
        </div>
      `;
        }
        html += "</div>";
        iacaListEl.innerHTML = html;
    }

    // Reset IACAs to defaults (removes all non-default certificates)
    function resetToDefaults() {
        try {
            const defaults = Array.isArray(window.DEFAULT_IACA_CERTIFICATES)
                ? window.DEFAULT_IACA_CERTIFICATES
                : [];
            localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(defaults));
            localStorage.setItem(IACA_VERSION_KEY, String(IACA_DATA_VERSION));
            (window.log || console.log)(
                `♻️ IACA list reset to defaults (${defaults.length} certificate(s))`,
            );
            updateIACAList();
            return { count: defaults.length };
        } catch (e) {
            console.error("Failed to reset IACA list to defaults:", e);
            return { error: e?.message || String(e) };
        }
    }

    // Global handlers used by HTML
    window.toggleIACACert = function (index) {
        const toggled = toggleIACAStatus(index);
        if (toggled) {
            const status = toggled.active ? "activated" : "deactivated";
            (window.log || console.log)(
                `${toggled.active ? "✅" : "⏸️"} ${
                    status.charAt(0).toUpperCase() + status.slice(1)
                } IACA: ${toggled.name}`,
            );
            updateIACAList();
        }
    };
    window.removeIACACert = function (index) {
        if (confirm("Are you sure you want to remove this certificate?")) {
            const removed = removeIACA(index);
            if (removed) {
                (window.log || console.log)(`🗑️ Removed IACA: ${removed.name}`);
                updateIACAList();
            }
        }
    };
    window.toggleIACADetails = function (index) {
        const detailsDiv = document.getElementById(`iaca-details-${index}`);
        const icon = document.getElementById(`iaca-details-icon-${index}`);
        if (!detailsDiv || !icon) return;
        if (detailsDiv.style.display === "none") {
            detailsDiv.style.display = "block";
            icon.textContent = "▼";
        } else {
            detailsDiv.style.display = "none";
            icon.textContent = "▶";
        }
    };
    window.viewIACAPEM = function (index) {
        const iacas = getIACAs();
        if (index >= 0 && index < iacas.length) {
            const iaca = iacas[index];
            const modal = document.createElement("div");
            modal.style.cssText =
                "position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; display: flex; align-items: center; justify-content: center; padding: 2rem;";
            modal.onclick = (e) => {
                if (e.target === modal) modal.remove();
            };
            const content = document.createElement("div");
            content.style.cssText =
                "background: white; border-radius: 12px; padding: 1.5rem; max-width: 800px; max-height: 80vh; overflow: auto; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.3);";
            content.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <h3 style="margin: 0; color: #0f172a;">${
              window.escapeHtml ? window.escapeHtml(iaca.name) : iaca.name
          }</h3>
          <button onclick="this.closest('div').parentElement.parentElement.remove()" style="background: #dc2626; padding: 0.5rem 1rem; border-radius: 6px; border: none; color: white; cursor: pointer;">Close</button>
        </div>
        <pre style="background: #f8fafc; padding: 1rem; border-radius: 8px; overflow-x: auto; font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.85rem; color: #1e293b; white-space: pre-wrap; word-break: break-all;">${
            window.escapeHtml ? window.escapeHtml(iaca.pem) : iaca.pem
        }</pre>
        <div style="margin-top: 1rem;">
          <button onclick="copyIACAPEM(${index}); this.textContent='✅ Copied!'; setTimeout(() => this.textContent='📋 Copy to Clipboard', 2000);" style="background: #059669; padding: 0.5rem 1rem; border-radius: 6px; border: none; color: white; cursor: pointer;">📋 Copy to Clipboard</button>
        </div>
      `;
            modal.appendChild(content);
            document.body.appendChild(modal);
        }
    };
    window.copyIACAPEM = async function (index) {
        const iacas = getIACAs();
        if (index >= 0 && index < iacas.length) {
            try {
                await navigator.clipboard.writeText(iacas[index].pem);
                (window.log || console.log)(
                    `📋 Copied IACA PEM to clipboard: ${iacas[index].name}`,
                );
            } catch (err) {
                console.error("Copy failed:", err);
                (window.log || console.log)(
                    "❌ Failed to copy PEM: " + err.message,
                );
            }
        }
    };

    // Expose public API if needed
    window.IacaManager = {
        initializeIACAs,
        getIACAs,
        getActiveIACAs,
        addIACA,
        removeIACA,
        toggleIACAStatus,
        parsePEMCertificate,
        pemToCryptoKey,
        updateIACAList,
        importVICALFromBytes,
        importVICALFromUri,
        importVICALFromFile,
        resetToDefaults,
    };
})();
