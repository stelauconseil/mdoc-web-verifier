/*
  Copyright (c) 2026 Stelau
  Author: Nicolas Chalanset

  Reader Authentication (ISO 18013-5)
  - Manage reader private key (PKCS#8 EC) and certificate chain (PEM)
  - Build ReaderAuthentication structure and COSE_Sign1 with x5chain
  - Expose minimal UI helpers via window.ReaderAuth
*/

(function () {
    function getCBOR() {
        return window.CBOR || self.CBOR || self.cbor;
    }
    const LS_ENABLED = "mdoc_reader_auth_enabled";
    const LS_KEY_PEM = "mdoc_reader_auth_key_pem";
    const LS_CHAIN_PEM = "mdoc_reader_auth_chain_pem";
    const LS_ORG = "mdoc_reader_auth_org";

    function saveEnabled(enabled) {
        localStorage.setItem(LS_ENABLED, enabled ? "1" : "0");
    }
    function loadEnabled() {
        return localStorage.getItem(LS_ENABLED) === "1";
    }
    function saveKeyPem(pem) {
        localStorage.setItem(LS_KEY_PEM, pem || "");
    }
    function loadKeyPem() {
        return localStorage.getItem(LS_KEY_PEM) || "";
    }
    function saveChainPem(pem) {
        localStorage.setItem(LS_CHAIN_PEM, pem || "");
    }
    function loadChainPem() {
        return localStorage.getItem(LS_CHAIN_PEM) || "";
    }

    function saveOrg(name) {
        localStorage.setItem(LS_ORG, name || "");
    }
    function loadOrg() {
        return localStorage.getItem(LS_ORG) || "";
    }

    function parsePemBlocks(allPem) {
        if (!allPem) return [];
        const blocks = [];
        const re = /-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/g;
        let m;
        // let last = 0;
        while ((m = re.exec(allPem))) {
            const type = m[1];
            const b64 = m[2]
                .replace(/[^A-Za-z0-9+/=\-_]/g, "")
                .replace(/-/g, "+")
                .replace(/_/g, "/");
            try {
                const raw = atob(b64);
                const bytes = new Uint8Array(raw.length);
                for (let i = 0; i < raw.length; i++)
                    bytes[i] = raw.charCodeAt(i);
                blocks.push({ type, bytes, pem: m[0] });
            } catch (_) {
                /* ignore bad block */
            }
            // last = re.lastIndex;
        }
        return blocks;
    }

    async function importPkcs8EcPrivateKey(pem, namedCurve) {
        const blocks = parsePemBlocks(pem);
        const pkcs8 = blocks.find((b) => b.type.includes("PRIVATE KEY"));
        if (!pkcs8) throw new Error("No PKCS#8 private key found");
        if (!namedCurve)
            throw new Error("namedCurve required (P-256 or P-384)");
        return await crypto.subtle.importKey(
            "pkcs8",
            pkcs8.bytes,
            { name: "ECDSA", namedCurve },
            false,
            ["sign"],
        );
    }

    // Try importing the key by auto-detecting the curve (P-256 or P-384)
    async function importPkcs8EcPrivateKeyAuto(pem) {
        try {
            const key = await importPkcs8EcPrivateKey(pem, "P-256");
            return { key, namedCurve: "P-256" };
        } catch (_) {
            // fallthrough
        }
        const key = await importPkcs8EcPrivateKey(pem, "P-384");
        return { key, namedCurve: "P-384" };
    }

    function derToRawEcdsa(sig, sizeBytes) {
        // Accept both DER (ASN.1 SEQUENCE) and raw P1363 (r||s)
        const u8 = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
        const len = u8.length;
        if (window.DEBUG_VERBOSE) {
            const first = len > 0 ? u8[0] : 0;
            console.log(
                `[ReaderAuth] sig len=${len}, first=0x${first
                    .toString(16)
                    .padStart(2, "0")}, target=${sizeBytes || "auto"}`,
            );
        }
        // If already the exact expected raw size
        if (sizeBytes && len === sizeBytes * 2) return u8;
        // Common raw lengths (P-256:64, P-384:96)
        if (len === 64 || len === 96) {
            const rawSize = len / 2;
            if (!sizeBytes || sizeBytes === rawSize) return u8;
            // Mismatch: coerce to requested size by trim/left-pad
            const out = new Uint8Array(sizeBytes * 2);
            const take = Math.min(len, out.length);
            out.set(u8.slice(len - take));
            return out;
        }
        // If not DER (0x30) but even-length and within plausible bounds, treat as raw and coerce
        if (u8[0] !== 0x30 && len % 2 === 0 && len <= 132) {
            const target = sizeBytes || (len / 2 <= 48 ? 32 : 48);
            if (len === target * 2) return u8;
            const out = new Uint8Array(target * 2);
            const take = Math.min(len, out.length);
            out.set(u8.slice(len - take));
            return out;
        }
        // Attempt robust DER decoding
        let p = 0;
        const expect = (val, msg) => {
            if (u8[p++] !== val) throw new Error(msg);
        };
        const readLen = () => {
            let lenByte = u8[p++];
            if (lenByte < 0x80) return lenByte;
            const n = lenByte & 0x7f;
            let l = 0;
            for (let i = 0; i < n; i++) l = (l << 8) | u8[p++];
            return l;
        };
        if (u8[0] !== 0x30) {
            // Final fallback: don't throw, return as-is to avoid breaking the flow
            console.warn(
                "[ReaderAuth] Unexpected signature format; passing through as-is",
            );
            return u8;
        }
        expect(0x30, "Bad DER: not SEQ");
        /* const seqLen = */ readLen();
        expect(0x02, "Bad DER: r tag");
        const rLen = readLen();
        let r = u8.slice(p, p + rLen);
        p += rLen;
        expect(0x02, "Bad DER: s tag");
        const sLen = readLen();
        let s = u8.slice(p, p + sLen);
        p += sLen;
        const target = sizeBytes || (rLen > 33 || sLen > 33 ? 48 : 32);
        // Strip leading zeros and left-pad to fixed size
        while (r.length > 0 && r[0] === 0) r = r.slice(1);
        while (s.length > 0 && s[0] === 0) s = s.slice(1);
        if (r.length > target) r = r.slice(r.length - target);
        if (s.length > target) s = s.slice(s.length - target);
        const out = new Uint8Array(target * 2);
        out.set(r, target - r.length);
        out.set(s, target * 2 - s.length);
        return out;
    }

    function detectCurveFromCertPem(pem) {
        try {
            const blocks = parsePemBlocks(pem);
            const cert = blocks.find((b) => b.type === "CERTIFICATE");
            if (!cert) return null;
            if (window.detectCurveFromCertOID)
                return window.detectCurveFromCertOID(cert.bytes);
        } catch (_) {}
        return null;
    }

    function firstCertDerArray(chainPem) {
        const blocks = parsePemBlocks(chainPem);
        return blocks
            .filter((b) => b.type === "CERTIFICATE")
            .map((b) => b.bytes);
    }

    // Ensure CBOR encodes as a plain bstr (no typed array tag 64)
    function toBstrBytes(data) {
        if (data == null) return new ArrayBuffer(0);
        if (data instanceof ArrayBuffer) return data;
        if (data.buffer instanceof ArrayBuffer) {
            return data.buffer.slice(
                data.byteOffset || 0,
                (data.byteOffset || 0) + (data.byteLength || data.length || 0),
            );
        }
        const u8 = data instanceof Uint8Array ? data : new Uint8Array(data);
        return u8.buffer.slice(0);
    }

    function coseAlgForCurve(curve) {
        // COSE alg values: -7 ES256, -35 ES384
        if (!curve) return null;
        const c = ("" + curve).toUpperCase();
        if (c.includes("384")) return -35;
        return -7; // default P-256
    }

    function webcryptoParamsForAlg(alg) {
        switch (alg) {
            case -7:
                return { hash: "SHA-256", size: 32, namedCurve: "P-256" };
            case -35:
                return { hash: "SHA-384", size: 48, namedCurve: "P-384" };
            default:
                throw new Error("Unsupported COSE alg: " + alg);
        }
    }

    async function buildReaderAuthenticationBytes(
        sessionTranscriptCbor,
        itemsRequestCbor,
    ) {
        const CBOR = getCBOR();
        if (!CBOR) throw new Error("CBOR library not available");
        // ReaderAuthentication = ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]
        // ItemsRequestBytes = tag(24, bstr .cbor ItemsRequest)
        const sessionTranscript = CBOR.decode(sessionTranscriptCbor);
        const itemsBytesTagged = new CBOR.Tagged(24, itemsRequestCbor);
        const ra = [
            "ReaderAuthentication",
            sessionTranscript,
            itemsBytesTagged,
        ];
        const raBytes = CBOR.encode(ra);
        // ReaderAuthenticationBytes = tag(24, bstr .cbor ReaderAuthentication)
        const raBytesTagged = CBOR.encode(new CBOR.Tagged(24, raBytes));
        return raBytesTagged; // bytes to use as detached payload
    }

    async function signReaderAuthentication(itemsRequestCbor) {
        if (!loadEnabled()) throw new Error("Reader authentication disabled");
        const CBOR = getCBOR();
        if (!CBOR) throw new Error("CBOR library not available");
        // SessionTranscript bytes were prepared earlier during session setup
        const st = window.sessionDebug && window.sessionDebug.sessionTranscript;
        if (!st || !(st instanceof Uint8Array))
            throw new Error("SessionTranscript not available yet");

        // Determine curve/alg from first certificate if possible; fallback to key autodetect
        const chainPem = loadChainPem();
        const curveHint = detectCurveFromCertPem(chainPem);

        // Import private key with proper namedCurve
        const keyPem = loadKeyPem();
        if (!keyPem) throw new Error("No private key configured");
        let privKey, namedCurve;
        if (curveHint) {
            const algTmp = coseAlgForCurve(curveHint);
            const params = webcryptoParamsForAlg(algTmp);
            namedCurve = params.namedCurve;
            privKey = await importPkcs8EcPrivateKey(keyPem, namedCurve);
        } else {
            const res = await importPkcs8EcPrivateKeyAuto(keyPem);
            privKey = res.key;
            namedCurve = res.namedCurve;
        }

        // Finalize alg/hash/size from the actual imported key
        const alg = coseAlgForCurve(namedCurve);
        const { hash, size } = webcryptoParamsForAlg(alg);

        // Build detached content: ReaderAuthenticationBytes
        const raDetached = await buildReaderAuthenticationBytes(
            st,
            itemsRequestCbor,
        );

        // Build Sig_structure = ["Signature1", protected, external_aad, payload]
        const prot = CBOR.encode(new Map([[1, alg]])); // {1: alg}
        const ext = new Uint8Array(0); // empty bstr
        // Use ArrayBuffer for all bstrs to prevent typed array tag(64)
        const sigStructure = [
            "Signature1",
            toBstrBytes(prot),
            toBstrBytes(ext),
            toBstrBytes(raDetached),
        ];
        const tbs = CBOR.encode(sigStructure);

        // Sign via WebCrypto; browsers may return DER or raw P1363, normalize to raw r||s
        const sigBytes = new Uint8Array(
            await crypto.subtle.sign({ name: "ECDSA", hash }, privKey, tbs),
        );
        const sig = derToRawEcdsa(sigBytes, size);
        if (window.DEBUG_VERBOSE) {
            console.log(`[ReaderAuth] normalized sig len=${sig.length}`);
        }

        // Build unprotected header with x5chain
        const x5 = firstCertDerArray(chainPem);
        if (!x5.length)
            throw new Error("No certificate(s) configured for x5chain");
        // Match common wallet examples: single bstr when exactly one cert; array-of-bstr otherwise
        const x5val =
            x5.length === 1 ? toBstrBytes(x5[0]) : x5.map(toBstrBytes);
        const unprot = new Map([[33, x5val]]); // 33: x5chain

        // COSE_Sign1 = [ protected (bstr), unprotected (map), payload (nil), signature (bstr) ]
        // Keep untagged to match common examples and wallet expectations
        const cose = [toBstrBytes(prot), unprot, null, toBstrBytes(sig)];
        try {
            if (window.DEBUG_VERBOSE) {
                const COSE = getCBOR().encode(cose);
                const hex = (buf) =>
                    [...new Uint8Array(buf)]
                        .map((b) => b.toString(16).padStart(2, "0"))
                        .join("");
                console.log("[ReaderAuth] COSE_Sign1 :", hex(COSE));
            }
        } catch {}
        return cose; // return structure (not encoded) so caller can embed in CBOR
    }

    function isEnabled() {
        return loadEnabled();
    }
    function setEnabled(v) {
        saveEnabled(!!v);
    }
    function setKeyPem(pem) {
        saveKeyPem(pem || "");
    }
    function setCertsPem(pem) {
        saveChainPem(pem || "");
    }
    function setOrgName(name) {
        saveOrg(name || "");
    }
    function getConfig() {
        return {
            enabled: isEnabled(),
            keyPem: loadKeyPem(),
            certsPem: loadChainPem(),
            orgName: loadOrg(),
        };
    }

    window.ReaderAuth = {
        isEnabled,
        setEnabled,
        setKeyPem,
        setCertsPem,
        setOrgName,
        getConfig,
        signReaderAuthentication,
    };
})();
