// ICAO 9303 passive authentication of DTC / eMRTD data groups (ISO 23220 Photo ID datagroups namespace):
// data group hashes against the LDS security object (EF.SOD), SOD signature by the Document Signer (DSC),
// DSC signature by a trusted CSCA. WebCrypto for hashes and RSA, noble-curves for ECDSA (brainpool included).
(function (root) {
    const subtle = root.crypto.subtle;
    const curves = () => root.nobleCurves;

    // ── DER ────────────────────────────────────────────
    function tlv(buf, off = 0) {
        let p = off;
        let tag = buf[p++];
        if ((tag & 0x1f) === 0x1f) {
            do tag = tag * 256 + buf[p];
            while (buf[p++] & 0x80);
        }
        let len = buf[p++];
        if (len & 0x80) {
            const n = len & 0x7f;
            len = 0;
            for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
        }
        if (p + len > buf.length) throw new Error("DER: truncated");
        return { tag, body: buf.subarray(p, p + len), raw: buf.subarray(off, p + len), end: p + len };
    }
    function kids(node) {
        const out = [];
        for (let p = 0; p < node.body.length; ) {
            const k = tlv(node.body, p);
            out.push(k);
            p = k.end;
        }
        return out;
    }
    function oid(node) {
        const b = node.body;
        const parts = [Math.floor(b[0] / 40), b[0] % 40];
        for (let i = 1, v = 0; i < b.length; i++) {
            v = v * 128 + (b[i] & 0x7f);
            if (!(b[i] & 0x80)) parts.push(v), (v = 0);
        }
        return parts.join(".");
    }
    function encode(tag, body) {
        const n = body.length;
        const len = n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255];
        return concat(Uint8Array.of(tag, ...len), body);
    }
    const concat = (...parts) => {
        const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let o = 0;
        for (const p of parts) out.set(p, o), (o += p.length);
        return out;
    };
    const equal = (a, b) => !!a && !!b && a.length === b.length && a.every((v, i) => v === b[i]);
    const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
    const big = (u8) => BigInt("0x" + (hex(u8) || "0"));
    const text = (u8) => new TextDecoder().decode(u8);
    const toBytes = (v) => (v instanceof Uint8Array ? v : ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : new Uint8Array(v));

    // ── Hashes ─────────────────────────────────────────
    const HASHES = {
        "1.3.14.3.2.26": "SHA-1",
        "2.16.840.1.101.3.4.2.4": "SHA-224",
        "2.16.840.1.101.3.4.2.1": "SHA-256",
        "2.16.840.1.101.3.4.2.2": "SHA-384",
        "2.16.840.1.101.3.4.2.3": "SHA-512",
    };

    // WebCrypto has no SHA-224 (still used by older German passports): SHA-256 core with the SHA-224 IV
    const K256 = Uint32Array.from(
        "428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2"
            .split(" ")
            .map((x) => parseInt(x, 16)),
    );
    function sha224(data) {
        const H = Uint32Array.of(0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4);
        const padded = new Uint8Array(Math.ceil((data.length + 9) / 64) * 64);
        padded.set(data);
        padded[data.length] = 0x80;
        const view = new DataView(padded.buffer);
        view.setUint32(padded.length - 4, data.length * 8);
        view.setUint32(padded.length - 8, Math.floor(data.length / 0x20000000));
        const W = new Uint32Array(64);
        const rotr = (x, n) => (x >>> n) | (x << (32 - n));
        for (let off = 0; off < padded.length; off += 64) {
            for (let t = 0; t < 64; t++) {
                if (t < 16) W[t] = view.getUint32(off + t * 4);
                else {
                    const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
                    const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
                    W[t] = W[t - 16] + s0 + W[t - 7] + s1;
                }
            }
            let [a, b, c, d, e, f, g, h] = H;
            for (let t = 0; t < 64; t++) {
                const t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[t] + W[t];
                const t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
                [h, g, f, e, d, c, b, a] = [g, f, e, (d + t1) >>> 0, c, b, a, (t1 + t2) >>> 0];
            }
            [a, b, c, d, e, f, g, h].forEach((v, i) => (H[i] = (H[i] + v) >>> 0));
        }
        const out = new Uint8Array(28);
        const ov = new DataView(out.buffer);
        for (let i = 0; i < 7; i++) ov.setUint32(i * 4, H[i]);
        return out;
    }
    async function digest(hash, data) {
        if (hash === "SHA-224") return sha224(data);
        return new Uint8Array(await subtle.digest(hash, data));
    }

    // ── Signatures ─────────────────────────────────────
    // signature OID → [key type, hash (null: from the digest algorithm), ECDSA signature encoding]
    const SIG_ALGS = {
        "1.2.840.10045.4.1": ["ec", "SHA-1", "der"],
        "1.2.840.10045.4.3.1": ["ec", "SHA-224", "der"],
        "1.2.840.10045.4.3.2": ["ec", "SHA-256", "der"],
        "1.2.840.10045.4.3.3": ["ec", "SHA-384", "der"],
        "1.2.840.10045.4.3.4": ["ec", "SHA-512", "der"],
        "1.2.840.10045.2.1": ["ec", null, "der"],
        // BSI TR-03111 ecdsa-plain-* (r||s), used by German documents
        "0.4.0.127.0.7.1.1.4.1.1": ["ec", "SHA-1", "compact"],
        "0.4.0.127.0.7.1.1.4.1.2": ["ec", "SHA-224", "compact"],
        "0.4.0.127.0.7.1.1.4.1.3": ["ec", "SHA-256", "compact"],
        "0.4.0.127.0.7.1.1.4.1.4": ["ec", "SHA-384", "compact"],
        "0.4.0.127.0.7.1.1.4.1.5": ["ec", "SHA-512", "compact"],
        "1.2.840.113549.1.1.1": ["rsa", null],
        "1.2.840.113549.1.1.5": ["rsa", "SHA-1"],
        "1.2.840.113549.1.1.11": ["rsa", "SHA-256"],
        "1.2.840.113549.1.1.12": ["rsa", "SHA-384"],
        "1.2.840.113549.1.1.13": ["rsa", "SHA-512"],
        "1.2.840.113549.1.1.14": ["rsa", "SHA-224"],
        "1.2.840.113549.1.1.10": ["pss", null],
    };
    const NAMED_CURVES = {
        "1.2.840.10045.3.1.7": "p256",
        "1.3.132.0.34": "p384",
        "1.3.132.0.35": "p521",
        "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
    };
    // Curves missing from noble-curves, as [p, a, b, Gx, Gy, n] (RFC 5639)
    const EXTRA_CURVES = {
        "1.3.36.3.3.2.8.1.1.9": [
            "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
            "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4",
            "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6",
            "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611",
            "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
            "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
        ].map((h) => BigInt("0x" + h)), // brainpoolP320r1
    };
    const RSA_SPKI_ALG = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);

    function ecCurve(paramsNode) {
        if (paramsNode.tag === 0x06) {
            const params = EXTRA_CURVES[oid(paramsNode)];
            return curves()[NAMED_CURVES[oid(paramsNode)]] ?? (params && genericCurve(...params));
        }
        // Explicit domain parameters (common in passport PKI): match on the prime and generator
        const [, fieldId, curve, base, order] = kids(paramsNode);
        const p = big(kids(fieldId)[1].body);
        const [a, b] = kids(curve).map((n) => big(n.body));
        const G = decodePoint(base.body, p, a, b);
        if (!G) return undefined;
        return (
            Object.values(NAMED_CURVES)
                .map((n) => curves()[n])
                .find((c) => c.Point.CURVE().p === p && c.Point.CURVE().Gx === G[0]) ??
            genericCurve(p, a, b, G[0], G[1], big(order.body))
        );
    }

    // ── Generic ECDSA verification (curves noble-curves doesn't ship) ──
    // Verification only handles public data, so plain BigInt (not constant time) is fine.
    const mod = (x, m) => ((x % m) + m) % m;
    function modPow(b, e, m) {
        let r = 1n;
        for (b = mod(b, m); e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
        return r;
    }
    function modInv(x, m) {
        let [a, b, u, v] = [mod(x, m), m, 1n, 0n];
        while (a) [a, b, u, v] = [b % a, a, v - (b / a) * u, u];
        return mod(v, m);
    }
    // SEC1 point (uncompressed, or compressed when p ≡ 3 mod 4) → [x, y], checked to be on the curve
    function decodePoint(u8, p, a, b) {
        const n = (u8.length - 1) / (u8[0] === 4 ? 2 : 1);
        const x = big(u8.subarray(1, 1 + n));
        const rhs = mod(x * x * x + a * x + b, p);
        let y;
        if (u8[0] === 4) y = big(u8.subarray(1 + n));
        else if ((u8[0] === 2 || u8[0] === 3) && p % 4n === 3n) {
            y = modPow(rhs, (p + 1n) / 4n, p);
            if ((y & 1n) !== BigInt(u8[0] & 1)) y = p - y;
        } else return null;
        return mod(y * y, p) === rhs ? [x, y] : null;
    }
    function genericCurve(p, a, b, gx, gy, n) {
        const add = (P, Q) => {
            if (!P) return Q;
            if (!Q) return P;
            if (P[0] === Q[0] && mod(P[1] + Q[1], p) === 0n) return null;
            const l = P[0] === Q[0] ? mod((3n * P[0] * P[0] + a) * modInv(2n * P[1], p), p) : mod((Q[1] - P[1]) * modInv(Q[0] - P[0], p), p);
            const x = mod(l * l - P[0] - Q[0], p);
            return [x, mod(l * (P[0] - x) - P[1], p)];
        };
        const mul = (k, P) => {
            let R = null;
            for (; k > 0n; k >>= 1n, P = add(P, P)) if (k & 1n) R = add(R, P);
            return R;
        };
        return {
            verify(signature, hash, pubKey, { format }) {
                let r, s;
                if (format === "compact") {
                    const h = signature.length / 2;
                    [r, s] = [big(signature.subarray(0, h)), big(signature.subarray(h))];
                } else [r, s] = kids(tlv(signature)).map((i) => big(i.body));
                const Q = decodePoint(pubKey, p, a, b);
                if (!Q || r <= 0n || r >= n || s <= 0n || s >= n) return false;
                // Leftmost bits of the hash, as many as the order has
                let z = big(hash);
                const excess = hash.length * 8 - n.toString(2).length;
                if (excess > 0) z >>= BigInt(excess);
                const w = modInv(s, n);
                const X = add(mul(mod(z * w, n), [gx, gy]), mul(mod(r * w, n), Q));
                return !!X && mod(X[0], n) === r;
            },
        };
    }

    // RSASSA-PKCS1-v1_5 by hand, for SHA-224 (WebCrypto has no SHA-224)
    const SHA224_DIGEST_INFO = Uint8Array.from([0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]);
    async function verifyRsaSha224(keyBits, data, signature) {
        const [nNode, eNode] = kids(tlv(keyBits.body.subarray(1)));
        const n = big(nNode.body);
        const k = (n.toString(16).length + 1) >> 1;
        const s = big(signature);
        if (signature.length !== k || s >= n) return false;
        const em = modPow(s, big(eNode.body), n).toString(16).padStart(k * 2, "0");
        const t = hex(concat(SHA224_DIGEST_INFO, await digest("SHA-224", data)));
        return em === "0001" + "f".repeat(k * 2 - t.length - 6) + "00" + t;
    }

    // spki: SubjectPublicKeyInfo node; sigAlg: AlgorithmIdentifier node
    async function verifySignature(spki, sigAlg, data, signature, defaultHash) {
        const [algOid, params] = kids(sigAlg);
        const alg = SIG_ALGS[oid(algOid)];
        if (!alg) return false;
        let [type, hash, encoding] = alg;
        hash ??= defaultHash;
        try {
            const [keyAlg, keyBits] = kids(spki);
            if (type === "ec") {
                const curve = ecCurve(kids(keyAlg)[1]);
                if (!curve) return false;
                const opts = { prehash: false, lowS: false, format: encoding };
                return curve.verify(signature, await digest(hash, data), keyBits.body.subarray(1), opts);
            }
            if (type === "rsa" && hash === "SHA-224") return await verifyRsaSha224(keyBits, data, signature);
            let algorithm = { name: "RSASSA-PKCS1-v1_5" };
            if (type === "pss") {
                // RSASSA-PSS-params: [0] hash, [1] MGF, [2] salt length (defaults SHA-1, 20)
                hash = "SHA-1";
                algorithm = { name: "RSA-PSS", saltLength: 20 };
                for (const p of params ? kids(params) : []) {
                    if (p.tag === 0xa0) hash = HASHES[oid(kids(kids(p)[0])[0])];
                    if (p.tag === 0xa2) algorithm.saltLength = Number(big(kids(p)[0].body));
                }
            }
            // Re-wrap as plain rsaEncryption: WebCrypto rejects id-RSASSA-PSS keys
            const der = encode(0x30, concat(RSA_SPKI_ALG, keyBits.raw));
            const key = await subtle.importKey("spki", der, { name: algorithm.name, hash }, false, ["verify"]);
            return await subtle.verify(algorithm, key, signature, data);
        } catch {
            return false;
        }
    }

    // ── Certificates ───────────────────────────────────
    const DN_NAMES = { "2.5.4.3": "CN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.10": "O", "2.5.4.11": "OU" };
    function dnAttrs(nameNode) {
        return kids(nameNode).flatMap((rdn) => kids(rdn).map((atv) => kids(atv))).map(([id, v]) => [oid(id), text(v.body)]);
    }
    const dnString = (nameNode) =>
        dnAttrs(nameNode)
            .map(([id, v]) => `${DN_NAMES[id] || id}=${v}`)
            .join(", ");

    function parseCert(der) {
        const cert = tlv(toBytes(der));
        const [tbs, sigAlg, sig] = kids(cert);
        const f = kids(tbs);
        const i = f[0].tag === 0xa0 ? 1 : 0; // optional [0] version
        const ext = {};
        const exts = f.find((n) => n.tag === 0xa3);
        for (const e of exts ? kids(kids(exts)[0]) : []) {
            const [id, ...rest] = kids(e);
            ext[oid(id)] = rest[rest.length - 1].body; // OCTET STRING value (skip critical flag)
        }
        const issuer = f[i + 2];
        const subject = f[i + 4];
        return {
            der: cert.raw,
            tbs: tbs.raw,
            sigAlg,
            signature: sig.body.subarray(1), // BIT STRING: skip unused-bits byte
            issuer: issuer.raw,
            subject: subject.raw,
            issuerName: dnString(issuer),
            subjectName: dnString(subject),
            country: dnAttrs(subject).find(([id]) => id === "2.5.4.6")?.[1] || null,
            spki: f[i + 5],
            ski: ext["2.5.29.14"] && tlv(ext["2.5.29.14"]).body,
            aki: ext["2.5.29.35"] && kids(tlv(ext["2.5.29.35"])).find((n) => n.tag === 0x80)?.body,
        };
    }

    // DSC → trusted CSCA: candidates by key identifier or issuer name, then the signature decides
    async function findCsca(dsc, cscas) {
        for (const ca of cscas) {
            const candidate = dsc.aki && ca.ski ? equal(dsc.aki, ca.ski) : equal(dsc.issuer, ca.subject);
            if (candidate && (await verifySignature(ca.spki, dsc.sigAlg, dsc.tbs, dsc.signature))) return ca;
        }
        return null;
    }

    // ── CMS SignedData (EF.SOD, CSCA master list) ──────
    const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
    const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

    function parseSignedData(der) {
        const [type, content] = kids(tlv(der));
        if (oid(type) !== OID_SIGNED_DATA) throw new Error("Not a CMS SignedData");
        const sd = kids(kids(content)[0]);
        const certs = sd.find((n) => n.tag === 0xa0);
        return {
            eContent: kids(kids(sd[2])[1])[0].body,
            certs: certs ? kids(certs).map((c) => parseCert(c.raw)) : [],
            signerInfo: kids(sd[sd.length - 1])[0],
        };
    }

    // Certificates from PEM, DER, or an ICAO CSCA master list (.ml)
    function readTrustFile(bytes) {
        bytes = toBytes(bytes);
        const pem = new TextDecoder("latin1").decode(bytes).match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g);
        if (pem) return pem.map((b) => parseCert(Uint8Array.from(atob(b.replace(/-----[A-Z ]+-----|\s/g, "")), (c) => c.charCodeAt(0))));
        const first = kids(tlv(bytes))[0];
        if (first.tag === 0x06 && oid(first) === OID_SIGNED_DATA) {
            // The master list's own signature isn't checked: trust comes from whoever imports the file
            const [, list] = kids(tlv(parseSignedData(bytes).eContent));
            return kids(list).map((c) => parseCert(c.raw));
        }
        return [parseCert(bytes)];
    }

    // ── Passive authentication ─────────────────────────
    // dataGroups: { 1: bytes, 2: bytes, … }; sod: EF.SOD (with or without the 0x77 wrapper); cscas: parsed certs
    // → integrity: all provided DGs match the SOD; documentSigner: SOD signed by its DSC;
    //   csca: DSC signed by a trusted CSCA ("unknown" when none matches)
    async function passiveAuth({ dataGroups, sod }, cscas = []) {
        const result = { integrity: "fail", dataGroups: [], documentSigner: "fail", csca: "fail", dsc: null, cscaCert: null, hashAlgorithm: null, error: null };
        try {
            sod = toBytes(sod);
            const signed = parseSignedData(sod[0] === 0x77 ? tlv(sod).body : sod);

            // LDSSecurityObject: version, hashAlgorithm, dataGroupHashValues
            const [, hashAlg, hashes] = kids(tlv(signed.eContent));
            const hash = HASHES[oid(kids(hashAlg)[0])];
            result.hashAlgorithm = hash || null;
            const expected = new Map(kids(hashes).map((n) => kids(n)).map(([num, h]) => [Number(big(num.body)), h.body]));
            for (const [n, v] of Object.entries(dataGroups)) {
                if (!v?.length) continue;
                const ok = !!hash && equal(await digest(hash, toBytes(v)), expected.get(Number(n)));
                result.dataGroups.push({ number: Number(n), ok });
            }
            result.integrity = result.dataGroups.length && result.dataGroups.every((d) => d.ok) ? "ok" : "fail";

            // SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
            const si = kids(signed.signerInfo);
            const attrs = si.find((n) => n.tag === 0xa0);
            const sigAlg = si[si.indexOf(attrs) + 1];
            const signature = si[si.indexOf(attrs) + 2].body;
            const siHash = HASHES[oid(kids(si[2])[0])];
            const md = kids(attrs)
                .map((a) => kids(a))
                .find(([id]) => oid(id) === OID_MESSAGE_DIGEST)?.[1];
            if (!md || !equal(await digest(siHash, signed.eContent), kids(md)[0].body)) {
                result.error = "SOD message digest mismatch";
                return result;
            }
            // Signed attributes are signed as a SET (tag 0x31), not as the [0] they're stored under
            const toSign = Uint8Array.from(attrs.raw);
            toSign[0] = 0x31;
            let dsc = null;
            for (const c of signed.certs) {
                if (await verifySignature(c.spki, sigAlg, toSign, signature, siHash)) {
                    dsc = c;
                    break;
                }
            }
            if (!dsc) {
                result.error = signed.certs.length ? "SOD signature invalid" : "No Document Signer certificate in the SOD";
                return result;
            }
            result.documentSigner = "ok";
            result.dsc = { subject: dsc.subjectName, issuer: dsc.issuerName, country: dsc.country };
            const ca = await findCsca(dsc, cscas);
            result.csca = ca ? "ok" : "unknown";
            result.cscaCert = ca ? { subject: ca.subjectName } : null;
        } catch (e) {
            result.error = e.message || String(e);
        }
        return result;
    }

    // Data groups and SOD from a wallet-response document model (org.iso.23220.datagroups.1)
    const DG_IDS = { dg1: 1, dg2: 2, dg3: 3, dg4: 4, dg5: 5, dg7: 7, dg11: 11, dg12: 12, dg13: 13, dg14: 14, dg15: 15, dg16: 16 };
    function extractFromDocument(doc) {
        const dataGroups = {};
        let sod = null;
        for (const items of Object.values(doc?.issuerSigned?.nameSpaces || {})) {
            for (const it of Array.isArray(items) ? items : []) {
                const id = String(it?.elementIdentifier || "").toLowerCase();
                const b64 = it?.raw?._base64;
                if (!b64 || !(id === "sod" || id in DG_IDS)) continue;
                const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
                if (id === "sod") sod = bytes;
                else dataGroups[DG_IDS[id]] = bytes;
            }
        }
        return sod ? { dataGroups, sod } : null;
    }

    // Web app trust list: imported CSCA certificates, kept as base64 DER in localStorage
    const STORE_KEY = "icao_cscaCertificates";
    const b64 = (u8) => btoa(Array.from(u8, (c) => String.fromCharCode(c)).join(""));
    const trustStore = {
        list() {
            try {
                return JSON.parse(root.localStorage.getItem(STORE_KEY) || "[]").map((d) => parseCert(Uint8Array.from(atob(d), (c) => c.charCodeAt(0))));
            } catch {
                return [];
            }
        },
        add(certs) {
            const known = new Set(this.list().map((c) => b64(c.der)));
            certs.forEach((c) => known.add(b64(c.der)));
            root.localStorage.setItem(STORE_KEY, JSON.stringify([...known]));
            return known.size;
        },
        clear() {
            root.localStorage.removeItem(STORE_KEY);
        },
    };

    const api = { readTrustFile, passiveAuth, extractFromDocument, trustStore };
    root.IcaoPassiveAuth = api;
    if (typeof module !== "undefined") module.exports = api;
})(globalThis);
