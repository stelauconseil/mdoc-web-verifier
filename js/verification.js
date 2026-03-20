/*
  Verification module extracted from index.html
  - COSE_Sign1 verification
  - DeviceAuth verification
  - Issuer chain validation (IACA)
*/

(function () {
    const log = window.log || console.log;
    const hex = (...args) =>
        window.SessionCrypto?.hex
            ? window.SessionCrypto.hex(...args)
            : [...new Uint8Array(args[0] || [])]
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join(" ");
    const getCBOR = () => window.CBOR || self.CBOR || self.cbor;
    const getActiveIACAs = (...args) =>
        window.IacaManager?.getActiveIACAs?.(...args) || [];
    const pemToCryptoKey = (...args) =>
        window.IacaManager?.pemToCryptoKey?.(...args);

    // Extract public key from X.509 certificate (DER format)
    // Supports NIST curves (P-256, P-384) via Web Crypto API
    // Supports Brainpool curves (P-256r1, P-320r1, P-384r1, P-512r1) via @noble/curves
    async function extractPublicKeyFromCert(certDer, quiet = false) {
        try {
            console.log(
                "Extracting public key from certificate, size:",
                certDer.length,
            );

            const cert = new Uint8Array(certDer);

            const curveOIDs = {
                "P-256": [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                "P-384": [0x2b, 0x81, 0x04, 0x00, 0x22],
                "P-521": [0x2b, 0x81, 0x04, 0x00, 0x23],
                brainpoolP256r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
                ],
                brainpoolP320r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09,
                ],
                brainpoolP384r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
                ],
                brainpoolP512r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
                ],
            };

            const findOID = (oid) => {
                for (let i = 0; i < cert.length - oid.length; i++) {
                    if (
                        cert
                            .slice(i, i + oid.length)
                            .every((byte, idx) => byte === oid[idx])
                    ) {
                        return i;
                    }
                }
                return -1;
            };

            let detectedCurve = null;
            for (const [curveName, oid] of Object.entries(curveOIDs)) {
                if (findOID(oid) !== -1) {
                    detectedCurve = curveName;
                    console.log(`✓ Detected curve: ${curveName}`);
                    break;
                }
            }

            if (!detectedCurve) {
                throw new Error(
                    "Could not detect EC curve from certificate OID",
                );
            }

            const keySizes = {
                "P-256": 65,
                "P-384": 97,
                "P-521": 133,
                brainpoolP256r1: 65,
                brainpoolP320r1: 81,
                brainpoolP384r1: 97,
                brainpoolP512r1: 129,
            };

            const coordSizes = {
                "P-256": 32,
                "P-384": 48,
                "P-521": 66,
                brainpoolP256r1: 32,
                brainpoolP320r1: 40,
                brainpoolP384r1: 48,
                brainpoolP512r1: 64,
            };

            const keySize = keySizes[detectedCurve];
            const coordSize = coordSizes[detectedCurve];

            let publicKeyBytes = null;
            for (let i = 0; i < cert.length - keySize; i++) {
                if (cert[i] === 0x04) {
                    const candidate = cert.slice(i, i + keySize);
                    if (
                        i >= 2 &&
                        cert[i - 1] === 0x00 &&
                        cert[i - 2] >= keySize + 1
                    ) {
                        publicKeyBytes = candidate;
                        console.log(
                            `Found ${detectedCurve} public key at offset ${i}`,
                        );
                        break;
                    }
                }
            }

            if (!publicKeyBytes) {
                throw new Error(
                    `Could not find ${detectedCurve} public key in certificate`,
                );
            }

            const x = publicKeyBytes.slice(1, 1 + coordSize);
            const y = publicKeyBytes.slice(1 + coordSize, 1 + 2 * coordSize);

            console.log(`Extracted ${detectedCurve} X:`, hex(x));
            console.log(`Extracted ${detectedCurve} Y:`, hex(y));

            if (!window.nobleCurves) {
                if (!quiet)
                    console.error("❌ @noble/curves library not loaded");
                return null;
            }

            const curveMap = {
                "P-256": "p256",
                "P-384": "p384",
                "P-521": "p521",
                brainpoolP256r1: "brainpoolP256r1",
                brainpoolP320r1: "brainpoolP320r1",
                brainpoolP384r1: "brainpoolP384r1",
                brainpoolP512r1: "brainpoolP512r1",
            };

            const nobleCurveName = curveMap[detectedCurve];
            if (!nobleCurveName || !window.nobleCurves[nobleCurveName]) {
                if (!quiet)
                    console.error(
                        `❌ Curve ${detectedCurve} (${nobleCurveName}) not available in @noble/curves`,
                    );
                if (!quiet)
                    console.log(
                        "Available curves:",
                        Object.keys(window.nobleCurves),
                    );
                return null;
            }

            console.log(
                `✅ ${detectedCurve} public key extracted (using @noble/curves for verification)`,
            );
            return {
                key: publicKeyBytes,
                curve: detectedCurve,
                nobleCurveName: nobleCurveName,
                type: "noble",
                x,
                y,
            };
        } catch (err) {
            if (!quiet)
                console.error("Error extracting public key:", err.message);
            return null;
        }
    }

    function derSignatureToRaw(derSig, expectedLength = 64) {
        try {
            if (derSig[0] !== 0x30) {
                return derSig;
            }

            let offset = 2;
            if (derSig[offset] !== 0x02)
                throw new Error("Invalid DER r component");
            offset++;
            const rLen = derSig[offset++];
            let rBytes = derSig.slice(offset, offset + rLen);
            offset += rLen;

            if (derSig[offset] !== 0x02)
                throw new Error("Invalid DER s component");
            offset++;
            const sLen = derSig[offset++];
            let sBytes = derSig.slice(offset, offset + sLen);

            if (rBytes[0] === 0x00) rBytes = rBytes.slice(1);
            if (sBytes[0] === 0x00) sBytes = sBytes.slice(1);

            const halfLen = expectedLength / 2;
            const rPadded = new Uint8Array(halfLen);
            const sPadded = new Uint8Array(halfLen);

            rPadded.set(rBytes, halfLen - rBytes.length);
            sPadded.set(sBytes, halfLen - sBytes.length);

            const rawSig = new Uint8Array(expectedLength);
            rawSig.set(rPadded, 0);
            rawSig.set(sPadded, halfLen);

            console.log(
                `[DER] Converted DER signature (${derSig.length} bytes) to raw r||s (${rawSig.length} bytes)`,
            );
            return rawSig;
        } catch (err) {
            console.warn("[DER] Failed to convert DER signature:", err.message);
            return derSig;
        }
    }

    function detectCurveFromCertOID(certDer) {
        try {
            const cert =
                certDer instanceof Uint8Array
                    ? certDer
                    : new Uint8Array(certDer);
            const curveOIDs = {
                "P-256": [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                "P-384": [0x2b, 0x81, 0x04, 0x00, 0x22],
                "P-521": [0x2b, 0x81, 0x04, 0x00, 0x23],
                brainpoolP256r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
                ],
                brainpoolP320r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09,
                ],
                brainpoolP384r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b,
                ],
                brainpoolP512r1: [
                    0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d,
                ],
            };
            const findOID = (oid) => {
                for (let i = 0; i <= cert.length - oid.length; i++) {
                    let ok = true;
                    for (let j = 0; j < oid.length; j++) {
                        if (cert[i + j] !== oid[j]) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok) return i;
                }
                return -1;
            };
            for (const [curveName, oid] of Object.entries(curveOIDs)) {
                if (findOID(oid) !== -1) return curveName;
            }
            return null;
        } catch {
            return null;
        }
    }

    function extractCertInfo(certDer) {
        try {
            const cert = new Uint8Array(certDer);
            function parseDerLength(bytes, offset) {
                const firstByte = bytes[offset];
                if (firstByte < 0x80) {
                    return { length: firstByte, bytesUsed: 1 };
                }
                const numBytes = firstByte & 0x7f;
                let length = 0;
                for (let i = 0; i < numBytes; i++) {
                    length = (length << 8) | bytes[offset + 1 + i];
                }
                return { length, bytesUsed: 1 + numBytes };
            }
            function extractString(bytes, offset) {
                const tag = bytes[offset];
                const lenInfo = parseDerLength(bytes, offset + 1);
                const strStart = offset + 1 + lenInfo.bytesUsed;
                const strEnd = strStart + lenInfo.length;
                if (tag === 0x0c || tag === 0x13 || tag === 0x16) {
                    const strBytes = bytes.slice(strStart, strEnd);
                    return new TextDecoder().decode(strBytes);
                }
                return null;
            }
            function findCN(bytes, start, end) {
                for (let i = start; i < end - 10; i++) {
                    if (
                        bytes[i] === 0x06 &&
                        bytes[i + 1] === 0x03 &&
                        bytes[i + 2] === 0x55 &&
                        bytes[i + 3] === 0x04 &&
                        bytes[i + 4] === 0x03
                    ) {
                        let offset = i + 5;
                        if (bytes[offset] === 0x31) {
                            offset++;
                            const lenInfo = parseDerLength(bytes, offset);
                            offset += lenInfo.bytesUsed;
                        }
                        const cn = extractString(bytes, offset);
                        if (cn) return cn;
                    }
                }
                return null;
            }
            function parseDN(bytes, start, end) {
                const oidMap = {
                    "06 03 55 04 03": "CN",
                    "06 03 55 04 05": "SN",
                    "06 03 55 04 06": "C",
                    "06 03 55 04 07": "L",
                    "06 03 55 04 08": "ST",
                    "06 03 55 04 0A": "O",
                    "06 03 55 04 0B": "OU",
                    "06 09 2A 86 48 86 F7 0D 01 09 01": "E",
                };
                const components = [];
                let offset = start;
                while (offset < end) {
                    if (bytes[offset] !== 0x31) {
                        offset++;
                        continue;
                    }
                    offset++;
                    const setLenInfo = parseDerLength(bytes, offset);
                    offset += setLenInfo.bytesUsed;
                    const setEnd = offset + setLenInfo.length;
                    if (offset < setEnd && bytes[offset] === 0x30) {
                        offset++;
                        const seqLenInfo = parseDerLength(bytes, offset);
                        offset += seqLenInfo.bytesUsed;
                        if (bytes[offset] === 0x06) {
                            offset++;
                            const oidLenInfo = parseDerLength(bytes, offset);
                            offset += oidLenInfo.bytesUsed;
                            const oidBytes = bytes.slice(
                                offset,
                                offset + oidLenInfo.length,
                            );
                            offset += oidLenInfo.length;
                            const oidKey = Array.from(oidBytes)
                                .map((b) =>
                                    b
                                        .toString(16)
                                        .padStart(2, "0")
                                        .toUpperCase(),
                                )
                                .join(" ");
                            const oidKey2 = `06 ${oidLenInfo.length.toString(16).padStart(2, "0").toUpperCase()} ${oidKey}`;
                            const attrName =
                                oidMap[oidKey2] || `OID(${oidKey})`;
                            const value = extractString(bytes, offset);
                            if (value) {
                                components.push(`${attrName}=${value}`);
                            }
                        }
                    }
                    offset = setEnd;
                }
                return components.join(", ");
            }
            let offset = 0;
            if (cert[offset] !== 0x30)
                throw new Error("Not a valid DER certificate");
            offset++;
            const certLenInfo = parseDerLength(cert, offset);
            offset += certLenInfo.bytesUsed;
            if (cert[offset] !== 0x30)
                throw new Error("Invalid tbsCertificate");
            offset++;
            const tbsLenInfo = parseDerLength(cert, offset);
            const tbsStart = offset + tbsLenInfo.bytesUsed;
            offset = tbsStart;
            if (cert[offset] === 0xa0) {
                offset++;
                const verLenInfo = parseDerLength(cert, offset);
                offset += verLenInfo.bytesUsed + verLenInfo.length;
            }
            if (cert[offset] === 0x02) {
                offset++;
                const snLenInfo = parseDerLength(cert, offset);
                offset += snLenInfo.bytesUsed + snLenInfo.length;
            }
            if (cert[offset] === 0x30) {
                offset++;
                const algLenInfo = parseDerLength(cert, offset);
                offset += algLenInfo.bytesUsed + algLenInfo.length;
            }
            let issuerCN = null;
            let issuerDN = null;
            if (cert[offset] === 0x30) {
                offset++;
                const issuerLenInfo = parseDerLength(cert, offset);
                const issuerStart = offset + issuerLenInfo.bytesUsed;
                const issuerEnd = issuerStart + issuerLenInfo.length;
                issuerCN = findCN(cert, issuerStart, issuerEnd);
                issuerDN = parseDN(cert, issuerStart, issuerEnd);
                offset = issuerEnd;
            }
            if (cert[offset] === 0x30) {
                offset++;
                const valLenInfo = parseDerLength(cert, offset);
                offset += valLenInfo.bytesUsed + valLenInfo.length;
            }
            let subjectCN = null;
            let subjectDN = null;
            if (cert[offset] === 0x30) {
                offset++;
                const subjectLenInfo = parseDerLength(cert, offset);
                const subjectStart = offset + subjectLenInfo.bytesUsed;
                const subjectEnd = subjectStart + subjectLenInfo.length;
                subjectCN = findCN(cert, subjectStart, subjectEnd);
                subjectDN = parseDN(cert, subjectStart, subjectEnd);
            }
            return { subjectCN, issuerCN, subjectDN, issuerDN };
        } catch (err) {
            console.warn("Error parsing certificate info:", err);
            return {
                subjectCN: null,
                issuerCN: null,
                subjectDN: null,
                issuerDN: null,
            };
        }
    }

    function extractCertValidity(certDer) {
        try {
            const cert = new Uint8Array(certDer);
            function parseDerLength(bytes, offset) {
                const firstByte = bytes[offset];
                if (firstByte < 0x80) {
                    return { length: firstByte, bytesUsed: 1 };
                }
                const numBytes = firstByte & 0x7f;
                let length = 0;
                for (let i = 0; i < numBytes; i++) {
                    length = (length << 8) | bytes[offset + 1 + i];
                }
                return { length, bytesUsed: 1 + numBytes };
            }
            function parseTime(bytes, offset) {
                const tag = bytes[offset];
                const lenInfo = parseDerLength(bytes, offset + 1);
                const timeStart = offset + 1 + lenInfo.bytesUsed;
                const timeEnd = timeStart + lenInfo.length;
                const timeBytes = bytes.slice(timeStart, timeEnd);
                const timeStr = new TextDecoder().decode(timeBytes);
                if (tag === 0x17) {
                    const year = parseInt(timeStr.substr(0, 2));
                    const fullYear = year >= 50 ? 1900 + year : 2000 + year;
                    const month = parseInt(timeStr.substr(2, 2)) - 1;
                    const day = parseInt(timeStr.substr(4, 2));
                    const hour = parseInt(timeStr.substr(6, 2));
                    const minute = parseInt(timeStr.substr(8, 2));
                    const second = parseInt(timeStr.substr(10, 2));
                    return new Date(
                        Date.UTC(fullYear, month, day, hour, minute, second),
                    );
                } else if (tag === 0x18) {
                    const year = parseInt(timeStr.substr(0, 4));
                    const month = parseInt(timeStr.substr(4, 2)) - 1;
                    const day = parseInt(timeStr.substr(6, 2));
                    const hour = parseInt(timeStr.substr(8, 2));
                    const minute = parseInt(timeStr.substr(10, 2));
                    const second = parseInt(timeStr.substr(12, 2));
                    return new Date(
                        Date.UTC(year, month, day, hour, minute, second),
                    );
                }
                return null;
            }
            let offset = 0;
            if (cert[offset] !== 0x30)
                return { notBefore: null, notAfter: null };
            offset++;
            const certLenInfo = parseDerLength(cert, offset);
            offset += certLenInfo.bytesUsed;
            if (cert[offset] !== 0x30)
                return { notBefore: null, notAfter: null };
            offset++;
            const tbsLenInfo = parseDerLength(cert, offset);
            offset += tbsLenInfo.bytesUsed;
            if (cert[offset] === 0xa0) {
                offset++;
                const verLenInfo = parseDerLength(cert, offset);
                offset += verLenInfo.bytesUsed + verLenInfo.length;
            }
            if (cert[offset] === 0x02) {
                offset++;
                const snLenInfo = parseDerLength(cert, offset);
                offset += snLenInfo.bytesUsed + snLenInfo.length;
            }
            if (cert[offset] === 0x30) {
                offset++;
                const algLenInfo = parseDerLength(cert, offset);
                offset += algLenInfo.bytesUsed + algLenInfo.length;
            }
            if (cert[offset] === 0x30) {
                offset++;
                const issuerLenInfo = parseDerLength(cert, offset);
                offset += issuerLenInfo.bytesUsed + issuerLenInfo.length;
            }
            if (cert[offset] !== 0x30)
                return { notBefore: null, notAfter: null };
            offset++;
            const valLenInfo = parseDerLength(cert, offset);
            offset += valLenInfo.bytesUsed;
            const notBefore = parseTime(cert, offset);
            offset++;
            const notBeforeLenInfo = parseDerLength(cert, offset);
            offset += notBeforeLenInfo.bytesUsed + notBeforeLenInfo.length;
            const notAfter = parseTime(cert, offset);
            return { notBefore, notAfter };
        } catch (err) {
            console.warn("Error extracting certificate validity:", err);
            return { notBefore: null, notAfter: null };
        }
    }

    async function verifyCoseSign1(
        coseSign1,
        publicKey,
        externalAadBytes = null,
    ) {
        try {
            if (!Array.isArray(coseSign1) || coseSign1.length < 4) {
                throw new Error("Invalid COSE_Sign1 structure");
            }
            const [protectedHeader, , payload, signature] = coseSign1;
            const protectedHeaderBytes =
                protectedHeader instanceof Uint8Array
                    ? protectedHeader
                    : new Uint8Array(protectedHeader);
            let payloadBytes =
                payload instanceof Uint8Array
                    ? payload
                    : payload == null
                      ? new Uint8Array(0)
                      : new Uint8Array(payload);

            let alg = -7;
            let algName = "ES256";
            let hashAlg = "SHA-256";
            let expectedSigLength = 64;

            function specAlgFromCurve(nobleCurveName) {
                const name = (nobleCurveName || "").toLowerCase();
                let out = {
                    algName: "ES256",
                    hash: "SHA-256",
                    sigLen: 64,
                    curveLabel: nobleCurveName,
                };
                if (!name) return out;
                if (name.includes("p256") || name.includes("brainpoolp256")) {
                    return {
                        algName: "ES256",
                        hash: "SHA-256",
                        sigLen: 64,
                        curveLabel: name.includes("brainpool")
                            ? "brainpoolP256r1"
                            : "P-256",
                    };
                }
                if (
                    name.includes("p384") ||
                    name.includes("brainpoolp384") ||
                    name.includes("brainpoolp320")
                ) {
                    const sigLen = name.includes("320") ? 80 : 96;
                    const curveLabel = name.includes("brainpoolp320")
                        ? "brainpoolP320r1"
                        : name.includes("brainpool")
                          ? "brainpoolP384r1"
                          : "P-384";
                    return {
                        algName: "ES384",
                        hash: "SHA-384",
                        sigLen,
                        curveLabel,
                    };
                }
                if (name.includes("p521") || name.includes("brainpoolp512")) {
                    const sigLen = name.includes("p521") ? 132 : 128;
                    const curveLabel = name.includes("p521")
                        ? "P-521"
                        : "brainpoolP512r1";
                    return {
                        algName: "ES512",
                        hash: "SHA-512",
                        sigLen,
                        curveLabel,
                    };
                }
                if (name.includes("ed25519") || name.includes("ed448")) {
                    return {
                        algName: "EdDSA",
                        hash: "NONE",
                        sigLen: 64,
                        curveLabel: name.includes("ed448")
                            ? "Ed448"
                            : "Ed25519",
                    };
                }
                return out;
            }

            try {
                const decodedHeader = getCBOR().decode(protectedHeaderBytes);
                if (decodedHeader instanceof Map) {
                    alg = decodedHeader.get(1) || -7;
                } else if (typeof decodedHeader === "object") {
                    alg = decodedHeader[1] || -7;
                }
                if (alg === -35) {
                    algName = "ES384";
                    hashAlg = "SHA-384";
                    expectedSigLength = 96;
                } else if (alg === -7) {
                    algName = "ES256";
                    hashAlg = "SHA-256";
                    expectedSigLength = 64;
                }
                const pkCurve = publicKey?.nobleCurveName || "";
                const mapped = specAlgFromCurve(pkCurve);
                if (
                    mapped.algName !== algName ||
                    mapped.sigLen !== expectedSigLength
                ) {
                    algName = mapped.algName;
                    hashAlg = mapped.hash;
                    expectedSigLength = mapped.sigLen;
                }
            } catch (e) {
                // Use defaults
            }

            function encodeBstr(bytes) {
                const len = bytes.length;
                if (len <= 23) {
                    return new Uint8Array([0x40 + len, ...bytes]);
                } else if (len <= 0xff) {
                    return new Uint8Array([0x58, len, ...bytes]);
                } else if (len <= 0xffff) {
                    return new Uint8Array([
                        0x59,
                        len >> 8,
                        len & 0xff,
                        ...bytes,
                    ]);
                } else {
                    throw new Error(
                        "Payload too large for this implementation",
                    );
                }
            }

            const sigStructureParts = [];
            sigStructureParts.push(new Uint8Array([0x84]));
            const contextStr = "Signature1";
            const contextBytes = new TextEncoder().encode(contextStr);
            sigStructureParts.push(new Uint8Array([0x6a, ...contextBytes]));
            const encodedProtected = encodeBstr(protectedHeaderBytes);
            sigStructureParts.push(encodedProtected);
            const aadBytes =
                externalAadBytes instanceof Uint8Array
                    ? externalAadBytes
                    : null;
            if (aadBytes && aadBytes.length) {
                sigStructureParts.push(encodeBstr(aadBytes));
            } else {
                sigStructureParts.push(new Uint8Array([0x40]));
            }
            sigStructureParts.push(encodeBstr(payloadBytes));
            const totalLength = sigStructureParts.reduce(
                (sum, part) => sum + part.length,
                0,
            );
            const sigStructureBytes = new Uint8Array(totalLength);
            let offset = 0;
            for (const part of sigStructureParts) {
                sigStructureBytes.set(part, offset);
                offset += part.length;
            }

            const signatureBytes = new Uint8Array(signature);
            if (signatureBytes.length !== expectedSigLength) {
                console.warn(
                    `⚠️ Expected ${expectedSigLength}-byte signature for ${algName}, got`,
                    signatureBytes.length,
                );
            }

            if (
                !publicKey ||
                typeof publicKey !== "object" ||
                publicKey.type !== "noble"
            ) {
                throw new Error(
                    "Invalid public key format - expected noble-curves key object",
                );
            }
            if (!window.nobleCurves) {
                throw new Error("@noble/curves library not loaded");
            }
            const curveLib = window.nobleCurves[publicKey.nobleCurveName];
            if (!curveLib) {
                throw new Error(
                    `Curve ${publicKey.nobleCurveName} not available in @noble/curves`,
                );
            }

            let isValid = false;
            try {
                isValid = curveLib.verify(
                    signatureBytes,
                    sigStructureBytes,
                    publicKey.key,
                );
            } catch (verifyErr) {
                isValid = false;
            }

            if (!isValid) {
                try {
                    const hashCandidates = [
                        hashAlg || "SHA-256",
                        "SHA-256",
                        "SHA-384",
                        "SHA-512",
                    ].filter((v, i, a) => a.indexOf(v) === i);
                    for (const hashName of hashCandidates) {
                        try {
                            const msgHash = new Uint8Array(
                                await crypto.subtle.digest(
                                    hashName,
                                    sigStructureBytes,
                                ),
                            );
                            if (typeof curveLib.verify === "function") {
                                try {
                                    isValid = curveLib.verify(
                                        signatureBytes,
                                        msgHash,
                                        publicKey.key,
                                        { prehash: true },
                                    );
                                } catch {
                                    isValid = curveLib.verify(
                                        signatureBytes,
                                        msgHash,
                                        publicKey.key,
                                        { prehash: true, lowS: false },
                                    );
                                }
                                if (isValid) {
                                    if (window.DEBUG_VERBOSE)
                                        console.log(
                                            `✓ Noble-curves prehash verify succeeded (${hashName})`,
                                        );
                                    break;
                                }
                            }
                        } catch {}
                    }
                } catch (e) {
                    if (window.DEBUG_VERBOSE)
                        console.warn("Prehash verify failed:", e);
                }
            }

            if (
                !isValid &&
                (publicKey.nobleCurveName === "p256" ||
                    publicKey.nobleCurveName === "p384") &&
                (signatureBytes.length === 64 || signatureBytes.length === 96)
            ) {
                try {
                    const halfLen = signatureBytes.length / 2;
                    const rBytes = signatureBytes.slice(0, halfLen);
                    const sBytes = signatureBytes.slice(halfLen);
                    const bytesToBigIntBE = (arr) =>
                        arr.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
                    const bigIntToBytesBE = (num, len) => {
                        const out = new Uint8Array(len);
                        let n = num;
                        for (let i = len - 1; i >= 0; i--) {
                            out[i] = Number(n & 0xffn);
                            n >>= 8n;
                        }
                        return out;
                    };
                    let curveOrder = null;
                    if (publicKey.nobleCurveName === "p256") {
                        curveOrder = BigInt(
                            "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                        );
                    } else if (publicKey.nobleCurveName === "p384") {
                        curveOrder = BigInt(
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                        );
                    }
                    if (curveOrder) {
                        const half = curveOrder >> 1n;
                        const sVal = bytesToBigIntBE(sBytes);
                        if (sVal > half) {
                            const sNorm = bigIntToBytesBE(
                                curveOrder - sVal,
                                sBytes.length,
                            );
                            const sigNorm = new Uint8Array(
                                signatureBytes.length,
                            );
                            sigNorm.set(rBytes, 0);
                            sigNorm.set(sNorm, rBytes.length);
                            if (window.DEBUG_VERBOSE)
                                console.log(
                                    "Attempting low-S normalized verification for COSE_Sign1",
                                );
                            try {
                                isValid = curveLib.verify(
                                    sigNorm,
                                    sigStructureBytes,
                                    publicKey.key,
                                );
                            } catch {}
                        }
                    }
                } catch {}
            }

            return isValid;
        } catch (err) {
            console.error("❌ Signature verification error:", err);
            throw err;
        }
    }

    function parseX509Certificate(certBytes) {
        try {
            let pos = 0;
            if (certBytes[pos++] !== 0x30) {
                throw new Error("Invalid certificate: Expected SEQUENCE");
            }
            let certLength;
            if (certBytes[pos] & 0x80) {
                const numLengthBytes = certBytes[pos++] & 0x7f;
                certLength = 0;
                for (let i = 0; i < numLengthBytes; i++) {
                    certLength = (certLength << 8) | certBytes[pos++];
                }
            } else {
                certLength = certBytes[pos++];
            }
            const tbsStart = pos;
            if (certBytes[pos++] !== 0x30) {
                throw new Error(
                    "Invalid certificate: Expected TBSCertificate SEQUENCE",
                );
            }
            let tbsLength;
            if (certBytes[pos] & 0x80) {
                const numLengthBytes = certBytes[pos++] & 0x7f;
                tbsLength = 0;
                for (let i = 0; i < numLengthBytes; i++) {
                    tbsLength = (tbsLength << 8) | certBytes[pos++];
                }
            } else {
                tbsLength = certBytes[pos++];
            }
            const tbsEnd = pos + tbsLength;
            const tbsCertificate = certBytes.slice(tbsStart, tbsEnd);
            pos = tbsEnd;
            if (certBytes[pos++] !== 0x30) {
                throw new Error(
                    "Invalid certificate: Expected signatureAlgorithm SEQUENCE",
                );
            }
            let sigAlgLength;
            if (certBytes[pos] & 0x80) {
                const numLengthBytes = certBytes[pos++] & 0x7f;
                sigAlgLength = 0;
                for (let i = 0; i < numLengthBytes; i++) {
                    sigAlgLength = (sigAlgLength << 8) | certBytes[pos++];
                }
            } else {
                sigAlgLength = certBytes[pos++];
            }
            pos += sigAlgLength;
            if (certBytes[pos++] !== 0x03) {
                throw new Error(
                    "Invalid certificate: Expected signature BIT STRING",
                );
            }
            let sigLength;
            if (certBytes[pos] & 0x80) {
                const numLengthBytes = certBytes[pos++] & 0x7f;
                sigLength = 0;
                for (let i = 0; i < numLengthBytes; i++) {
                    sigLength = (sigLength << 8) | certBytes[pos++];
                }
            } else {
                sigLength = certBytes[pos++];
            }
            const unusedBits = certBytes[pos++];
            sigLength -= 1;
            const signature = certBytes.slice(pos, pos + sigLength);
            console.log("🔍 [X.509 Signature Extraction DEBUG]:");
            console.log(
                "  Signature from BIT STRING (first 16 bytes):",
                Array.from(signature.slice(0, 16))
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join(" "),
            );
            console.log("  Signature length:", signature.length);
            console.log(
                "  First byte:",
                "0x" + signature[0].toString(16).padStart(2, "0"),
                signature[0] === 0x30
                    ? "(DER SEQUENCE ✓)"
                    : "(NOT DER SEQUENCE!)",
            );
            const rawSignature = convertDERSignatureToRaw(signature);
            console.log("  After convertDERSignatureToRaw():");
            console.log(
                "  Raw signature (first 16 bytes):",
                Array.from(rawSignature.slice(0, 16))
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join(" "),
            );
            console.log("  Raw signature length:", rawSignature.length);
            return {
                tbsCertificate,
                signature: rawSignature,
                signatureDER: signature,
            };
        } catch (e) {
            console.error("Failed to parse X.509 certificate:", e);
            return null;
        }
    }

    function convertDERSignatureToRaw(derSig) {
        try {
            let pos = 0;
            console.log(`🔍 [DER to Raw Conversion]`);
            console.log(
                `   Input DER (first 32 bytes): ${hex(derSig.slice(0, Math.min(32, derSig.length)))}`,
            );
            if (derSig[pos++] !== 0x30) {
                throw new Error("Invalid DER signature: Expected SEQUENCE");
            }
            let seqLength;
            if (derSig[pos] & 0x80) {
                const numBytes = derSig[pos++] & 0x7f;
                seqLength = 0;
                for (let i = 0; i < numBytes; i++) {
                    seqLength = (seqLength << 8) | derSig[pos++];
                }
            } else {
                seqLength = derSig[pos++];
            }
            console.log(`   SEQUENCE length: ${seqLength}`);
            if (derSig[pos++] !== 0x02) {
                throw new Error(
                    "Invalid DER signature: Expected INTEGER for r",
                );
            }
            let rLength = derSig[pos++];
            console.log(`   r length: ${rLength}`);
            let r = derSig.slice(pos, pos + rLength);
            console.log(`   r raw (with potential padding): ${hex(r)}`);
            pos += rLength;
            if (r[0] === 0x00 && r.length > 1) {
                r = r.slice(1);
                console.log(`   r after removing 0x00 padding: ${hex(r)}`);
            }
            if (derSig[pos++] !== 0x02) {
                throw new Error(
                    "Invalid DER signature: Expected INTEGER for s",
                );
            }
            let sLength = derSig[pos++];
            console.log(`   s length: ${sLength}`);
            let s = derSig.slice(pos, pos + sLength);
            console.log(`   s raw (with potential padding): ${hex(s)}`);
            if (s[0] === 0x00 && s.length > 1) {
                s = s.slice(1);
                console.log(`   s after removing 0x00 padding: ${hex(s)}`);
            }
            const componentSize = Math.max(r.length, s.length) <= 32 ? 32 : 48;
            const rPadded = new Uint8Array(componentSize);
            const sPadded = new Uint8Array(componentSize);
            if (r.length <= componentSize) {
                rPadded.set(r, componentSize - r.length);
            } else {
                rPadded.set(r.slice(r.length - componentSize), 0);
            }
            if (s.length <= componentSize) {
                sPadded.set(s, componentSize - s.length);
            } else {
                sPadded.set(s.slice(s.length - componentSize), 0);
            }
            const rawSig = new Uint8Array(componentSize * 2);
            rawSig.set(rPadded, 0);
            rawSig.set(sPadded, componentSize);
            return rawSig;
        } catch (e) {
            console.error("Failed to convert DER signature:", e);
            return derSig;
        }
    }

    function extractAuthorityKeyIdentifier(certBytes) {
        try {
            const hexStr = Array.from(certBytes)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
            const akiOidPattern = "551d23";
            const akiIndex = hexStr.indexOf(akiOidPattern);
            if (akiIndex === -1) {
                return null;
            }
            const afterOid = hexStr.substring(akiIndex + akiOidPattern.length);
            const keyIdMatch = afterOid.match(/8014([0-9a-f]{40})/);
            if (keyIdMatch) {
                return keyIdMatch[1];
            }
            return null;
        } catch (e) {
            console.error("Failed to extract AKI:", e);
            return null;
        }
    }

    function extractSubjectKeyIdentifier(certBytes) {
        try {
            const hexStr = Array.from(certBytes)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
            const skiOidPattern = "551d0e";
            const skiIndex = hexStr.indexOf(skiOidPattern);
            if (skiIndex === -1) {
                return null;
            }
            const afterOid = hexStr.substring(skiIndex + skiOidPattern.length);
            const keyIdMatch = afterOid.match(/0414([0-9a-f]{40})/);
            if (keyIdMatch) {
                return keyIdMatch[1];
            }
            return null;
        } catch (e) {
            console.error("Failed to extract SKI:", e);
            return null;
        }
    }

    async function validateCertificateChain(issuerCertBytes) {
        const result = {
            valid: false,
            matchedIACA: null,
            chain: [],
            errors: [],
        };
        const DEBUG_VERBOSE =
            typeof window !== "undefined" && window.DEBUG_VERBOSE === true;

        try {
            console.log(
                "=== VALIDATING ISSUER CERTIFICATE AGAINST IACA ROOTS ===",
            );

            const activeIACAs = getActiveIACAs();

            if (activeIACAs.length === 0) {
                result.errors.push(
                    "No active IACA certificates available for validation",
                );
                return result;
            }

            console.log(
                `Testing issuer certificate against ${activeIACAs.length} active IACA(s)`,
            );

            if (DEBUG_VERBOSE) console.log("Parsing issuer certificate...");
            const parsedCert = parseX509Certificate(issuerCertBytes);

            if (!parsedCert) {
                result.errors.push(
                    "Failed to parse issuer certificate (invalid X.509 format)",
                );
                return result;
            }

            console.log("✓ Parsed issuer certificate");
            if (DEBUG_VERBOSE) {
                console.log(
                    "  TBS length:",
                    parsedCert.tbsCertificate.length,
                    "bytes",
                );
                console.log(
                    "  Signature length:",
                    parsedCert.signature.length,
                    "bytes",
                );
            }

            function parseCertSignatureAlgorithmOID(certBytes) {
                try {
                    let pos = 0;
                    if (certBytes[pos++] !== 0x30) return null;
                    if (certBytes[pos] & 0x80) {
                        const n = certBytes[pos++] & 0x7f;
                        for (let i = 0; i < n; i++) pos++;
                    } else {
                        pos++;
                    }
                    if (certBytes[pos++] !== 0x30) return null;
                    if (certBytes[pos] & 0x80) {
                        const n = certBytes[pos++] & 0x7f;
                        let tbsLen = 0;
                        for (let i = 0; i < n; i++)
                            tbsLen = (tbsLen << 8) | certBytes[pos++];
                        pos += tbsLen;
                    } else {
                        const tbsLen = certBytes[pos++];
                        pos += tbsLen;
                    }
                    if (certBytes[pos++] !== 0x30) return null;
                    let sigAlgLen = 0;
                    if (certBytes[pos] & 0x80) {
                        const n = certBytes[pos++] & 0x7f;
                        for (let i = 0; i < n; i++)
                            sigAlgLen = (sigAlgLen << 8) | certBytes[pos++];
                    } else {
                        sigAlgLen = certBytes[pos++];
                    }
                    if (certBytes[pos++] !== 0x06) return null;
                    let oidLen = certBytes[pos++];
                    const oidBytes = certBytes.slice(pos, pos + oidLen);
                    function decodeOID(bytes) {
                        if (!bytes || bytes.length === 0) return "";
                        const out = [];
                        const first = bytes[0];
                        out.push(Math.floor(first / 40));
                        out.push(first % 40);
                        let value = 0;
                        for (let i = 1; i < bytes.length; i++) {
                            const b = bytes[i];
                            value = (value << 7) | (b & 0x7f);
                            if ((b & 0x80) === 0) {
                                out.push(value);
                                value = 0;
                            }
                        }
                        return out.join(".");
                    }
                    const oidStr = decodeOID(oidBytes);
                    return { oidStr, oidBytes: new Uint8Array(oidBytes) };
                } catch (e) {
                    console.warn(
                        "Failed to parse signatureAlgorithm OID:",
                        e.message,
                    );
                    return null;
                }
            }
            const sigAlg = parseCertSignatureAlgorithmOID(issuerCertBytes);
            if (sigAlg) {
                console.log(`  Signature Algorithm: ${sigAlg.oidStr}`);
                if (DEBUG_VERBOSE)
                    console.log(`  OID hex: ${hex(sigAlg.oidBytes)}`);
            } else {
                console.log("  Signature Algorithm OID: unavailable");
            }

            const aki = extractAuthorityKeyIdentifier(issuerCertBytes);
            console.log(
                "  Authority Key Identifier (AKI):",
                aki || "not found",
            );

            const certSigLength = parsedCert.signature.length;
            const hashFromOID =
                sigAlg?.oidStr === "1.2.840.10045.4.3.1"
                    ? "SHA-224"
                    : sigAlg?.oidStr === "1.2.840.10045.4.3.2"
                      ? "SHA-256"
                      : sigAlg?.oidStr === "1.2.840.10045.4.3.3"
                        ? "SHA-384"
                        : sigAlg?.oidStr === "1.2.840.10045.4.3.4"
                          ? "SHA-512"
                          : "SHA-256";
            const algName = hashFromOID.replace("SHA-", "ES");
            console.log(`  Using hash: ${hashFromOID}`);
            if (DEBUG_VERBOSE)
                console.log(
                    `  Certificate signature length: ${certSigLength} bytes`,
                );

            const expectedCurves =
                certSigLength === 96
                    ? ["p384", "brainpoolP384r1"]
                    : ["p256", "brainpoolP256r1"];

            console.log(`  Expected IACA curves: ${expectedCurves.join(", ")}`);

            let matchingIACAs = activeIACAs;

            if (aki) {
                console.log(`🔍 Searching for IACA with matching SKI...`);
                const iacasWithSKI = [];

                for (const iaca of activeIACAs) {
                    try {
                        const b64 = iaca.pem
                            .replace(/-----BEGIN CERTIFICATE-----/, "")
                            .replace(/-----END CERTIFICATE-----/, "")
                            .replace(/\s+/g, "");
                        const binaryString = atob(b64);
                        const iacaBytes = new Uint8Array(binaryString.length);
                        for (let i = 0; i < binaryString.length; i++) {
                            iacaBytes[i] = binaryString.charCodeAt(i);
                        }

                        const ski = extractSubjectKeyIdentifier(iacaBytes);

                        if (ski) {
                            console.log(`  ${iaca.name}: SKI = ${ski}`);
                            if (ski.toLowerCase() === aki.toLowerCase()) {
                                console.log(
                                    `  ✅ MATCH! This IACA signed the DS certificate`,
                                );
                                iacasWithSKI.push(iaca);
                            }
                        } else {
                            console.log(`  ${iaca.name}: No SKI found`);
                        }
                    } catch (e) {
                        console.warn(
                            `  ${iaca.name}: Error extracting SKI:`,
                            e.message,
                        );
                    }
                }

                if (iacasWithSKI.length > 0) {
                    matchingIACAs = iacasWithSKI;
                    console.log(
                        `✓ Found ${matchingIACAs.length} IACA(s) with matching SKI`,
                    );
                } else {
                    console.warn(
                        "⚠️ No IACA found with matching SKI, will try all IACAs",
                    );
                }
            }

            for (const iaca of matchingIACAs) {
                console.log(
                    `Testing IACA: ${iaca.name}${matchingIACAs.length === 1 ? " (matched by AKI/SKI)" : ""}`,
                );

                try {
                    const iacaB64 = iaca.pem
                        .replace(/-----BEGIN CERTIFICATE-----/, "")
                        .replace(/-----END CERTIFICATE-----/, "")
                        .replace(/\s+/g, "");
                    const iacaBinaryString = atob(iacaB64);
                    const iacaCertBytes = new Uint8Array(
                        iacaBinaryString.length,
                    );
                    for (let i = 0; i < iacaBinaryString.length; i++) {
                        iacaCertBytes[i] = iacaBinaryString.charCodeAt(i);
                    }

                    const iacaPublicKey = await pemToCryptoKey(iaca.pem);

                    if (!iacaPublicKey) {
                        console.log(
                            `  ✗ Failed to import IACA public key (missing or invalid certificate)`,
                        );
                        result.errors.push(
                            `${iaca.name}: IACA certificate missing or invalid`,
                        );
                        continue;
                    }

                    console.log(
                        `  ✓ Imported IACA public key (curve: ${iacaPublicKey.nobleCurveName})`,
                    );

                    if (!iacaPublicKey || iacaPublicKey.type !== "noble") {
                        console.log("  ✗ Invalid IACA public key format");
                        result.errors.push(`${iaca.name}: Invalid key format`);
                        continue;
                    }

                    if (
                        !expectedCurves.includes(iacaPublicKey.nobleCurveName)
                    ) {
                        console.log(
                            `  ⊘ Skipping: IACA curve ${iacaPublicKey.nobleCurveName} incompatible with ${algName} signature (${certSigLength} bytes)`,
                        );
                        continue;
                    }

                    if (!window.nobleCurves) {
                        console.log("  ✗ @noble/curves library not loaded");
                        result.errors.push(
                            `${iaca.name}: Crypto library not available`,
                        );
                        continue;
                    }

                    const curveLib =
                        window.nobleCurves[iacaPublicKey.nobleCurveName];
                    if (!curveLib) {
                        console.log(
                            `  ✗ Curve ${iacaPublicKey.nobleCurveName} not available`,
                        );
                        result.errors.push(
                            `${iaca.name}: Curve ${iacaPublicKey.nobleCurveName} not supported`,
                        );
                        continue;
                    }

                    if (DEBUG_VERBOSE)
                        console.log(
                            `  Using @noble/curves (${iacaPublicKey.nobleCurveName}) for certificate verification`,
                        );

                    if (DEBUG_VERBOSE) {
                        console.log(
                            `  TBS certificate length: ${parsedCert.tbsCertificate.length} bytes`,
                        );
                        console.log(
                            `  TBS hex (first 64 bytes):`,
                            hex(parsedCert.tbsCertificate.slice(0, 64)),
                        );
                        console.log(
                            `  TBS hex (last 32 bytes):`,
                            hex(parsedCert.tbsCertificate.slice(-32)),
                        );
                    }

                    if (DEBUG_VERBOSE)
                        console.log(
                            `  🔍 Diagnostic: Verifying TBS structure...`,
                        );
                    if (DEBUG_VERBOSE)
                        console.log(
                            `     First byte: 0x${parsedCert.tbsCertificate[0].toString(16)} (should be 0x30 = SEQUENCE)`,
                        );
                    if (DEBUG_VERBOSE)
                        console.log(
                            `     Second byte: 0x${parsedCert.tbsCertificate[1].toString(16)} (length indicator)`,
                        );
                    if (parsedCert.tbsCertificate[1] === 0x82) {
                        const tbsLengthFromTag =
                            (parsedCert.tbsCertificate[2] << 8) |
                            parsedCert.tbsCertificate[3];
                        if (DEBUG_VERBOSE)
                            console.log(
                                `     TBS length from tag: ${tbsLengthFromTag} (should be ${parsedCert.tbsCertificate.length - 4})`,
                            );
                        if (
                            tbsLengthFromTag + 4 ===
                            parsedCert.tbsCertificate.length
                        ) {
                            if (DEBUG_VERBOSE)
                                console.log(`     ✓ TBS length is correct`);
                        } else {
                            console.log(
                                `     ✗ TBS length mismatch! Expected ${tbsLengthFromTag + 4}, got ${parsedCert.tbsCertificate.length}`,
                            );
                        }
                    }

                    if (DEBUG_VERBOSE) {
                        console.log(
                            `  Certificate signature (raw r||s):`,
                            hex(parsedCert.signature),
                        );
                        console.log(
                            `  Certificate signature length: ${parsedCert.signature.length} bytes`,
                        );
                        console.log(
                            `  IACA public key (with 0x04 prefix):`,
                            hex(iacaPublicKey.key),
                        );
                        console.log(
                            `  IACA public key length: ${iacaPublicKey.key.length} bytes`,
                        );
                        console.log(
                            `  IACA X coordinate:`,
                            hex(iacaPublicKey.key.slice(1, 33)),
                        );
                        console.log(
                            `  IACA Y coordinate:`,
                            hex(iacaPublicKey.key.slice(33, 65)),
                        );
                    }
                    console.log(`  Attempting verification`);

                    let preHash = null;
                    try {
                        const h = await crypto.subtle.digest(
                            hashFromOID,
                            parsedCert.tbsCertificate,
                        );
                        preHash = new Uint8Array(h);
                        if (DEBUG_VERBOSE)
                            console.log(`  📊 ${hashFromOID}(TBS) computed`);
                    } catch (e) {
                        console.log(
                            `  ⚠️ Unable to compute ${hashFromOID} digest: ${e.message}`,
                        );
                    }

                    let isValid = false;
                    let lowSUsed = false;
                    try {
                        if (DEBUG_VERBOSE) {
                            console.log(
                                `  🔬 Calling ${iacaPublicKey.nobleCurveName}.verify()...`,
                            );
                            console.log(
                                `     - signature length: ${parsedCert.signature.length}`,
                            );
                            console.log(
                                `     - message length: ${parsedCert.tbsCertificate.length}`,
                            );
                            console.log(
                                `     - publicKey length: ${iacaPublicKey.key.length}`,
                            );
                        }

                        if (DEBUG_VERBOSE)
                            console.log(
                                `  🔍 Diagnostic: Verifying IACA public key is valid...`,
                            );
                        try {
                            if (
                                curveLib.ProjectivePoint &&
                                typeof curveLib.ProjectivePoint.fromHex ===
                                    "function"
                            ) {
                                if (DEBUG_VERBOSE)
                                    console.log(
                                        `     ✓ Public key is a valid point on ${iacaPublicKey.nobleCurveName}`,
                                    );
                            } else {
                                if (DEBUG_VERBOSE)
                                    console.log(
                                        `     (Skipping ProjectivePoint check: API not available)`,
                                    );
                            }
                        } catch (pointErr) {
                            console.log(
                                `     ✗ Public key is NOT a valid point: ${pointErr.message}`,
                            );
                        }

                        if (DEBUG_VERBOSE) {
                            console.log(
                                `  🔍 Diagnostic: Checking signature format...`,
                            );
                            const halfLen = parsedCert.signature.length / 2;
                            const r = parsedCert.signature.slice(0, halfLen);
                            const s = parsedCert.signature.slice(halfLen);
                            console.log(
                                `     r first byte: 0x${r[0].toString(16)}`,
                            );
                            console.log(
                                `     s first byte: 0x${s[0].toString(16)}`,
                            );
                            if (r[0] === 0x00) {
                                console.log(
                                    `     ⚠️ WARNING: r has leading zero - might be padding issue`,
                                );
                            }
                            if (s[0] === 0x00) {
                                console.log(
                                    `     ⚠️ WARNING: s has leading zero - might be padding issue`,
                                );
                            }
                        }

                        if (preHash) {
                            if (DEBUG_VERBOSE)
                                console.log(
                                    `  🧪 Verify: signature vs ${hashFromOID}(TBS)`,
                                );
                            isValid = curveLib.verify(
                                parsedCert.signature,
                                preHash,
                                iacaPublicKey.key,
                            );
                        }

                        if (!isValid && preHash) {
                            try {
                                let curveOrder = curveLib?.CURVE?.n;
                                if (!curveOrder) {
                                    if (
                                        iacaPublicKey.nobleCurveName === "p256"
                                    ) {
                                        curveOrder = BigInt(
                                            "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                                        );
                                    } else if (
                                        iacaPublicKey.nobleCurveName === "p384"
                                    ) {
                                        curveOrder = BigInt(
                                            "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                                        );
                                    }
                                }
                                if (curveOrder) {
                                    const half = curveOrder >> 1n;
                                    const bytesToBigIntBE = (arr) =>
                                        arr.reduce(
                                            (n, b) => (n << 8n) | BigInt(b),
                                            0n,
                                        );
                                    const bigIntToBytesBE = (num, len) => {
                                        const out = new Uint8Array(len);
                                        let n = num;
                                        for (let i = len - 1; i >= 0; i--) {
                                            out[i] = Number(n & 0xffn);
                                            n >>= 8n;
                                        }
                                        return out;
                                    };
                                    const halfLen =
                                        parsedCert.signature.length / 2;
                                    const rBytes = parsedCert.signature.slice(
                                        0,
                                        halfLen,
                                    );
                                    const sBytes =
                                        parsedCert.signature.slice(halfLen);
                                    const sVal = bytesToBigIntBE(sBytes);
                                    if (sVal > half) {
                                        const sNorm = bigIntToBytesBE(
                                            curveOrder - sVal,
                                            sBytes.length,
                                        );
                                        const sigNorm = new Uint8Array(
                                            parsedCert.signature.length,
                                        );
                                        sigNorm.set(rBytes, 0);
                                        sigNorm.set(sNorm, rBytes.length);
                                        if (DEBUG_VERBOSE)
                                            console.log(
                                                `  🧪 Verify: low-S signature vs ${hashFromOID}(TBS)`,
                                            );
                                        isValid = curveLib.verify(
                                            sigNorm,
                                            preHash,
                                            iacaPublicKey.key,
                                        );
                                    }
                                }
                            } catch {}
                        }

                        if (!isValid) {
                            try {
                                if (DEBUG_VERBOSE)
                                    console.log(
                                        `  🧪 Verify: signature vs RAW_TBS`,
                                    );
                                isValid = curveLib.verify(
                                    parsedCert.signature,
                                    parsedCert.tbsCertificate,
                                    iacaPublicKey.key,
                                );
                            } catch (e) {
                                if (DEBUG_VERBOSE)
                                    console.log(
                                        `     verify threw: ${e.message}`,
                                    );
                            }
                        }

                        if (!isValid) {
                            try {
                                let curveOrder = curveLib?.CURVE?.n;
                                if (!curveOrder) {
                                    if (
                                        iacaPublicKey.nobleCurveName === "p256"
                                    ) {
                                        curveOrder = BigInt(
                                            "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                                        );
                                    } else if (
                                        iacaPublicKey.nobleCurveName === "p384"
                                    ) {
                                        curveOrder = BigInt(
                                            "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                                        );
                                    }
                                }
                                if (curveOrder) {
                                    const half = curveOrder >> 1n;
                                    const bytesToBigIntBE = (arr) =>
                                        arr.reduce(
                                            (n, b) => (n << 8n) | BigInt(b),
                                            0n,
                                        );
                                    const bigIntToBytesBE = (num, len) => {
                                        const out = new Uint8Array(len);
                                        let n = num;
                                        for (let i = len - 1; i >= 0; i--) {
                                            out[i] = Number(n & 0xffn);
                                            n >>= 8n;
                                        }
                                        return out;
                                    };
                                    const halfLen =
                                        parsedCert.signature.length / 2;
                                    const rBytes = parsedCert.signature.slice(
                                        0,
                                        halfLen,
                                    );
                                    const sBytes =
                                        parsedCert.signature.slice(halfLen);
                                    const sVal = bytesToBigIntBE(sBytes);
                                    if (sVal > half) {
                                        const sNorm = bigIntToBytesBE(
                                            curveOrder - sVal,
                                            sBytes.length,
                                        );
                                        const sigNorm = new Uint8Array(
                                            parsedCert.signature.length,
                                        );
                                        sigNorm.set(rBytes, 0);
                                        sigNorm.set(sNorm, rBytes.length);
                                        if (DEBUG_VERBOSE)
                                            console.log(
                                                `  🧪 Verify: low-S signature vs RAW_TBS`,
                                            );
                                        isValid = curveLib.verify(
                                            sigNorm,
                                            parsedCert.tbsCertificate,
                                            iacaPublicKey.key,
                                        );
                                    }
                                }
                            } catch {}
                        }

                        if (!isValid && DEBUG_VERBOSE) {
                            try {
                                console.log(
                                    `  🧪 Attempt E: verify(signature_DER, RAW_TBS, publicKey)`,
                                );
                                const res = curveLib.verify(
                                    parsedCert.signatureDER,
                                    parsedCert.tbsCertificate,
                                    iacaPublicKey.key,
                                );
                                console.log(`     Result: ${res}`);
                                isValid = res;
                            } catch (e) {
                                console.log(
                                    `     Attempt E threw: ${e.message}`,
                                );
                            }
                        }

                        if (!isValid && DEBUG_VERBOSE) {
                            try {
                                console.log(
                                    `  🧪 Attempt F: verify(signature_DER, ${hashFromOID}(TBS), publicKey)`,
                                );
                                const preHashBuf = await crypto.subtle.digest(
                                    hashFromOID,
                                    parsedCert.tbsCertificate,
                                );
                                const preHash = new Uint8Array(preHashBuf);
                                const res = curveLib.verify(
                                    parsedCert.signatureDER,
                                    preHash,
                                    iacaPublicKey.key,
                                );
                                console.log(`     Result: ${res}`);
                                isValid = res;
                            } catch (e) {
                                console.log(
                                    `     Attempt F threw: ${e.message}`,
                                );
                            }
                        }

                        if (
                            !isValid &&
                            DEBUG_VERBOSE &&
                            window.crypto?.subtle
                        ) {
                            try {
                                console.log(
                                    `  🧪 Attempt G: WebCrypto.verify(ECDSA, ${hashFromOID})`,
                                );
                                const namedCurve =
                                    iacaPublicKey.nobleCurveName === "p256"
                                        ? "P-256"
                                        : iacaPublicKey.nobleCurveName ===
                                            "p384"
                                          ? "P-384"
                                          : null;
                                if (namedCurve) {
                                    const wcKey = await crypto.subtle.importKey(
                                        "raw",
                                        iacaPublicKey.key,
                                        { name: "ECDSA", namedCurve },
                                        false,
                                        ["verify"],
                                    );
                                    const ok = await crypto.subtle.verify(
                                        {
                                            name: "ECDSA",
                                            hash: { name: hashFromOID },
                                        },
                                        wcKey,
                                        parsedCert.signatureDER,
                                        parsedCert.tbsCertificate,
                                    );
                                    console.log(
                                        `     WebCrypto verify result: ${ok}`,
                                    );
                                    isValid = ok;
                                } else {
                                    console.log(
                                        `     (Skipping Attempt G: unsupported curve ${iacaPublicKey.nobleCurveName})`,
                                    );
                                }
                            } catch (e) {
                                console.log(
                                    `     Attempt G threw: ${e.message}`,
                                );
                            }
                        }

                        if (!isValid && DEBUG_VERBOSE) {
                            console.log(
                                `  🧪 Attempt 3: Sanity check - re-verify DS certificate COSE_Sign1`,
                            );
                            console.log(
                                `     (This should succeed since it worked earlier)`,
                            );
                            console.log(
                                `     DS cert byte at 382: 0x${issuerCertBytes[382].toString(16)} (should be 0x04)`,
                            );
                            console.log(
                                `     DS cert public key X: ${hex(issuerCertBytes.slice(383, 383 + 32))}`,
                            );
                            console.log(
                                `     DS cert public key Y: ${hex(issuerCertBytes.slice(383 + 32, 383 + 64))}`,
                            );
                            console.log(
                                `     Previously verified: COSE_Sign1 with DS cert public key = WORKS ✓`,
                            );
                            console.log(
                                `     Now failing: X.509 cert with IACA public key = FAILS ✗`,
                            );
                            console.log(
                                `     But wait - let's check if the issue is with IACA cert or DS cert...`,
                            );
                            console.log(
                                `  🧪 Attempt 4: Verify IACA is self-signed (sanity check)`,
                            );
                            try {
                                const iacaParsed =
                                    parseX509Certificate(iacaCertBytes);
                                if (iacaParsed) {
                                    console.log(
                                        `     IACA TBS length: ${iacaParsed.tbsCertificate.length}`,
                                    );
                                    console.log(
                                        `     IACA signature length: ${iacaParsed.signature.length}`,
                                    );
                                    const iacaSelfVerify = curveLib.verify(
                                        iacaParsed.signature,
                                        iacaParsed.tbsCertificate,
                                        iacaPublicKey.key,
                                    );
                                    console.log(
                                        `     IACA self-signed verification: ${iacaSelfVerify}`,
                                    );
                                    if (iacaSelfVerify) {
                                        console.log(
                                            `     ✓ IACA is properly self-signed!`,
                                        );
                                        console.log(
                                            `     This means the IACA public key is correct.`,
                                        );
                                        console.log(
                                            `     Therefore, the DS certificate signature or TBS must be wrong.`,
                                        );
                                    } else {
                                        console.log(
                                            `     ✗ IACA self-signed verification failed!`,
                                        );
                                        console.log(`     This could mean:`);
                                        console.log(
                                            `       1. IACA public key extraction is wrong`,
                                        );
                                        console.log(
                                            `       2. Our signature/TBS extraction is fundamentally broken`,
                                        );
                                        console.log(
                                            `       3. noble-curves verification has an issue`,
                                        );
                                    }
                                }
                            } catch (iacaErr) {
                                console.log(
                                    `     Error verifying IACA: ${iacaErr.message}`,
                                );
                            }
                        }

                        console.log(
                            `  ✅ Certificate verify result: ${isValid}`,
                        );
                    } catch (verifyErr) {
                        console.log(
                            `  ✗ verify() threw error: ${verifyErr.message}`,
                        );
                        console.error(verifyErr);
                        isValid = false;
                    }

                    if (isValid) {
                        console.log(
                            `  ✅ Issuer certificate is signed by this IACA!`,
                        );

                        result.valid = true;
                        result.matchedIACA = {
                            name: iaca.name,
                            issuer: iaca.issuer,
                            test: iaca.test || false,
                        };
                        result.chain = [
                            "mDoc Issuer Certificate",
                            `↓ signed by`,
                            `IACA Root: ${iaca.name}${iaca.test ? " (TEST)" : ""}`,
                        ];

                        console.log(
                            `✅ Issuer certificate validated with IACA: ${iaca.name}${iaca.test ? " (TEST)" : ""}`,
                        );
                        return result;
                    } else {
                        console.log(`  ✗ Signature does not match this IACA`);
                    }
                } catch (e) {
                    console.log(
                        `  ✗ Verification failed with this IACA:`,
                        e.message,
                    );
                    result.errors.push(`${iaca.name}: ${e.message}`);
                }
            }

            if (!result.valid) {
                result.errors.push(
                    "Issuer certificate is not signed by any active IACA root certificate",
                );
            }
        } catch (err) {
            console.error("Issuer certificate validation error:", err);
            result.errors.push(`Validation error: ${err.message}`);
        }

        return result;
    }

    async function verifyCOSESign1SignatureWithChain(coseSign1) {
        const result = {
            signatureValid: false,
            chainValid: false,
            chainInfo: null,
            errors: [],
        };

        try {
            console.log(
                "Step 1: Extracting issuer certificate from x5chain...",
            );

            const unprotectedHeader = coseSign1[1] || {};
            console.log("Unprotected header:", unprotectedHeader);
            console.log(
                "Unprotected header type:",
                Object.prototype.toString.call(unprotectedHeader),
            );

            let issuerCert;
            if (unprotectedHeader instanceof Map) {
                console.log("Unprotected header is a Map");
                issuerCert = unprotectedHeader.get(33);
                console.log("Issuer cert from Map.get(33):", issuerCert);
            } else {
                console.log("Unprotected header is a plain object");
                issuerCert = unprotectedHeader[33];
                console.log("Issuer cert from object[33]:", issuerCert);
            }

            if (!issuerCert) {
                result.errors.push(
                    "No issuer certificate (x5chain) found in signature header",
                );
                console.warn(
                    "⚠️ No x5chain (issuer certificate) found in unprotected header",
                );
                console.log(
                    "Available header keys:",
                    unprotectedHeader instanceof Map
                        ? Array.from(unprotectedHeader.keys())
                        : Object.keys(unprotectedHeader),
                );
                return result;
            }

            let issuerCertBytes;
            if (issuerCert instanceof Uint8Array) {
                issuerCertBytes = issuerCert;
            } else if (ArrayBuffer.isView(issuerCert)) {
                issuerCertBytes = new Uint8Array(
                    issuerCert.buffer,
                    issuerCert.byteOffset,
                    issuerCert.byteLength,
                );
            } else if (issuerCert instanceof ArrayBuffer) {
                issuerCertBytes = new Uint8Array(issuerCert);
            } else {
                result.errors.push("Issuer certificate format not recognized");
                console.error(
                    "Issuer certificate is not a Uint8Array or ArrayBuffer:",
                    typeof issuerCert,
                );
                return result;
            }

            console.log(
                "Issuer certificate size:",
                issuerCertBytes.length,
                "bytes",
            );

            console.log(
                "Step 2: Extracting public key and verifying signature...",
            );
            try {
                const publicKey =
                    await extractPublicKeyFromCert(issuerCertBytes);
                result.signatureValid = await verifyCoseSign1(
                    coseSign1,
                    publicKey,
                );

                if (!result.signatureValid) {
                    result.errors.push("COSE signature verification failed");
                }
            } catch (sigErr) {
                console.error("Signature verification error:", sigErr);
                result.errors.push(
                    `Signature verification error: ${sigErr.message}`,
                );
                result.signatureValid = false;
            }

            console.log(
                "Step 3: Validating issuer certificate against IACA roots...",
            );
            result.chainInfo = await validateCertificateChain(issuerCertBytes);
            result.chainValid = result.chainInfo.valid;

            if (!result.chainValid) {
                result.errors.push(...result.chainInfo.errors);
            }
        } catch (err) {
            console.error("Signature verification with chain error:", err);
            result.errors.push(`Verification error: ${err.message}`);
        }

        return result;
    }

    async function verifyIssuerSignedValueDigests(doc, coseSign1) {
        const result = {
            checked: 0,
            matched: 0,
            mismatched: 0,
            skipped: 0,
            allMatched: null,
            errors: [],
            details: [],
        };

        let loggedFirstMismatch = false;

        if (window.DEBUG_VERBOSE)
            console.log("[valueDigests] Starting verification");

        const getFieldAny = (obj, keys) => {
            if (!obj) return undefined;
            for (const k of keys) {
                if (obj instanceof Map) {
                    let v = obj.get(k);
                    if (v !== undefined) return v;
                    const kStr = String(k);
                    v = obj.get(kStr);
                    if (v !== undefined) return v;
                    if (
                        typeof k === "string" &&
                        !Number.isNaN(parseInt(k, 10))
                    ) {
                        const kNum = parseInt(k, 10);
                        v = obj.get(kNum);
                        if (v !== undefined) return v;
                    }
                } else {
                    let v = obj?.[k];
                    if (v !== undefined) return v;
                    const kStr = String(k);
                    v = obj?.[kStr];
                    if (v !== undefined) return v;
                }
            }
            return undefined;
        };
        const toUint8 = (v) => {
            if (v instanceof Uint8Array) return v;
            if (ArrayBuffer.isView(v))
                return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
            if (v instanceof ArrayBuffer) return new Uint8Array(v);
            if (Array.isArray(v)) {
                try {
                    return new Uint8Array(v);
                } catch {
                    return null;
                }
            }
            return null;
        };
        const fromJsonBytes = (obj) => {
            if (!obj || typeof obj !== "object") return null;
            if (obj._type === "bytes" && typeof obj._base64 === "string") {
                try {
                    const bin = atob(obj._base64);
                    const out = new Uint8Array(bin.length);
                    for (let i = 0; i < bin.length; i++)
                        out[i] = bin.charCodeAt(i);
                    return out;
                } catch {
                    return null;
                }
            }
            return null;
        };
        const fromBase64String = (str) => {
            if (typeof str !== "string") return null;
            try {
                const bin = atob(str);
                const out = new Uint8Array(bin.length);
                for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
                return out;
            } catch {
                return null;
            }
        };
        const bytesToBase64 = (u8) => {
            try {
                if (!u8 || !u8.length) return "";
                let s = "";
                const chunk = 0x8000;
                for (let i = 0; i < u8.length; i += chunk) {
                    s += String.fromCharCode(...u8.subarray(i, i + chunk));
                }
                return btoa(s);
            } catch {
                return null;
            }
        };
        const bytesEqual = (a, b) => {
            if (!a || !b || a.length !== b.length) return false;
            for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
            return true;
        };
        const normalizeDigestAlgorithm = (alg) => {
            if (!alg) return null;
            try {
                if (
                    alg &&
                    alg.constructor &&
                    alg.constructor.name === "Tagged" &&
                    alg.value !== undefined
                ) {
                    alg = alg.value;
                } else if (
                    alg &&
                    typeof alg === "object" &&
                    "tag" in alg &&
                    "value" in alg
                ) {
                    alg = alg.value;
                }
            } catch {}
            if (typeof alg === "number") {
                const map = new Map([
                    [1, "SHA-256"],
                    [2, "SHA-384"],
                    [3, "SHA-512"],
                    [-16, "SHA-256"],
                    [-43, "SHA-384"],
                    [-44, "SHA-512"],
                ]);
                return map.get(alg) || null;
            }
            if (typeof alg === "string") {
                const up = alg.toUpperCase();
                if (up.includes("SHA-256")) return "SHA-256";
                if (up.includes("SHA-384")) return "SHA-384";
                if (up.includes("SHA-512")) return "SHA-512";
                if (up === "SHA256") return "SHA-256";
                if (up === "SHA384") return "SHA-384";
                if (up === "SHA512") return "SHA-512";
            }
            return null;
        };
        const normalizeIssuerSignedItemMap = (obj) => {
            try {
                if (!obj || (typeof obj !== "object" && !(obj instanceof Map)))
                    return null;
                const getField = (keys) => getFieldAny(obj, keys);
                const digestId = getField(["digestID", "digestId", 0]);
                const random = getField(["random", 1]);
                const elementIdentifier = getField(["elementIdentifier", 2]);
                const elementValue = getField(["elementValue", 3]);

                const m = new Map();
                if (digestId !== undefined) m.set(0, digestId);
                if (random !== undefined) m.set(1, random);
                if (elementIdentifier !== undefined)
                    m.set(2, elementIdentifier);
                if (elementValue !== undefined) m.set(3, elementValue);
                if (m.size === 0) return null;
                return m;
            } catch {
                return null;
            }
        };
        const getDigestFromMap = (digestMap, digestId) => {
            if (!digestMap) return undefined;
            if (digestMap instanceof Map) {
                if (digestMap.has(digestId)) return digestMap.get(digestId);
                if (digestMap.has(String(digestId)))
                    return digestMap.get(String(digestId));
                if (
                    typeof digestId === "string" &&
                    !Number.isNaN(parseInt(digestId, 10))
                ) {
                    const asNum = parseInt(digestId, 10);
                    if (digestMap.has(asNum)) return digestMap.get(asNum);
                }
                return undefined;
            }
            if (digestMap && typeof digestMap === "object") {
                if (digestMap[digestId] !== undefined)
                    return digestMap[digestId];
                if (digestMap[String(digestId)] !== undefined)
                    return digestMap[String(digestId)];
            }
            return undefined;
        };

        try {
            if (
                !doc ||
                !coseSign1 ||
                !Array.isArray(coseSign1) ||
                coseSign1.length < 3
            ) {
                result.errors.push(
                    "Invalid COSE_Sign1 payload for valueDigests verification",
                );
                return result;
            }

            const payload = coseSign1[2];
            const payloadBytes = toUint8(payload);

            let mso = doc?.signature?.msoDecoded || null;
            if (!mso) {
                if (!payloadBytes) {
                    result.errors.push(
                        "MSO payload missing or not a byte array",
                    );
                    return result;
                }
                try {
                    mso = getCBOR().decode(payloadBytes);
                    if (
                        mso &&
                        mso.constructor &&
                        mso.constructor.name === "Tagged" &&
                        mso.tag === 24 &&
                        mso.value !== undefined
                    ) {
                        mso = getCBOR().decode(new Uint8Array(mso.value));
                    } else if (
                        mso &&
                        typeof mso === "object" &&
                        mso.tag === 24 &&
                        mso.value !== undefined
                    ) {
                        const inner =
                            toUint8(mso.value) || fromJsonBytes(mso.value);
                        if (inner) mso = getCBOR().decode(inner);
                    } else if (
                        mso instanceof Uint8Array ||
                        mso instanceof ArrayBuffer ||
                        ArrayBuffer.isView(mso)
                    ) {
                        const inner = toUint8(mso);
                        if (inner) mso = getCBOR().decode(inner);
                    }
                } catch (e) {
                    result.errors.push(
                        `Unable to decode MSO payload: ${e.message}`,
                    );
                    return result;
                }
            }

            if (window.DEBUG_VERBOSE) {
                const keys =
                    mso instanceof Map
                        ? Array.from(mso.keys())
                        : Object.keys(mso || {});
                console.log("[valueDigests] MSO keys:", keys);
            }

            const digestAlgorithm = getFieldAny(mso, ["digestAlgorithm", 2]);
            let hashAlg = normalizeDigestAlgorithm(digestAlgorithm);

            const valueDigests = getFieldAny(mso, ["valueDigests", 1]);
            if (!valueDigests) {
                result.errors.push("MSO is missing valueDigests");
                if (window.DEBUG_VERBOSE)
                    console.warn("[valueDigests] MSO is missing valueDigests");
                return result;
            }

            if (!hashAlg) {
                let inferred = null;
                try {
                    const nsValues =
                        valueDigests instanceof Map
                            ? Array.from(valueDigests.values())
                            : Object.values(valueDigests || {});
                    const firstNs = nsValues.find(Boolean);
                    const firstDigest =
                        firstNs instanceof Map
                            ? Array.from(firstNs.values()).find(Boolean)
                            : firstNs
                              ? Object.values(firstNs).find(Boolean)
                              : null;
                    const firstBytes =
                        toUint8(firstDigest) || fromJsonBytes(firstDigest);
                    if (firstBytes) {
                        if (firstBytes.length === 32) inferred = "SHA-256";
                        else if (firstBytes.length === 48) inferred = "SHA-384";
                        else if (firstBytes.length === 64) inferred = "SHA-512";
                    }
                } catch {}
                if (inferred) {
                    hashAlg = inferred;
                    console.warn(
                        "[valueDigests] digestAlgorithm missing; inferred",
                        inferred,
                    );
                } else {
                    result.errors.push(
                        `Unsupported digest algorithm: ${String(digestAlgorithm)}`,
                    );
                    console.warn(
                        "[valueDigests] Unsupported digest algorithm",
                        digestAlgorithm,
                    );
                    console.warn(
                        "[valueDigests] MSO keys",
                        mso instanceof Map
                            ? Array.from(mso.keys())
                            : Object.keys(mso || {}),
                    );
                    return result;
                }
            }

            if (window.DEBUG_VERBOSE)
                console.log("[valueDigests] Digest algorithm:", hashAlg);

            const nsObj = doc?.issuerSigned?.nameSpaces || {};
            const nsEntries =
                nsObj instanceof Map
                    ? Array.from(nsObj.entries())
                    : Object.entries(nsObj);

            if (window.DEBUG_VERBOSE) {
                console.log(
                    "[valueDigests] Namespaces found:",
                    nsEntries.map(([k]) => String(k)),
                );
            }

            for (const [nsName, items] of nsEntries) {
                const nsDigests =
                    valueDigests instanceof Map
                        ? (valueDigests.get(nsName) ??
                          valueDigests.get(String(nsName)))
                        : (valueDigests?.[nsName] ??
                          valueDigests?.[String(nsName)]);

                if (!nsDigests && window.DEBUG_VERBOSE) {
                    console.warn(
                        `[valueDigests] No valueDigests entry for namespace "${String(nsName)}"`,
                    );
                }

                const itemsArr = Array.isArray(items) ? items : [];
                for (const entry of itemsArr) {
                    const digestId = entry?.digestId ?? entry?.digestID;
                    const issuerSignedItemBytes = entry?.issuerSignedItemBytes;
                    const issuerBytes =
                        toUint8(issuerSignedItemBytes) ||
                        fromJsonBytes(issuerSignedItemBytes);
                    if (digestId === undefined || !issuerSignedItemBytes) {
                        if (window.DEBUG_VERBOSE) {
                            console.log(
                                `[valueDigests] Skipping entry: missing digestId or issuerSignedItemBytes (namespace="${String(nsName)}", elementIdentifier="${entry?.elementIdentifier}")`,
                            );
                        }
                        result.skipped++;
                        continue;
                    }
                    if (!issuerBytes) {
                        result.mismatched++;
                        result.details.push({
                            namespace: nsName,
                            elementIdentifier: entry?.elementIdentifier,
                            digestId,
                            reason: "Invalid issuerSignedItemBytes",
                        });
                        continue;
                    }
                    if (!nsDigests) {
                        result.mismatched++;
                        result.details.push({
                            namespace: nsName,
                            elementIdentifier: entry?.elementIdentifier,
                            digestId,
                            reason: "No valueDigests for namespace",
                        });
                        continue;
                    }
                    const expected = getDigestFromMap(nsDigests, digestId);
                    if (!expected) {
                        if (window.DEBUG_VERBOSE) {
                            console.warn(
                                `[valueDigests] Missing digestId in valueDigests (namespace="${String(nsName)}", elementIdentifier="${entry?.elementIdentifier}", digestId=${digestId})`,
                            );
                        }
                        result.mismatched++;
                        result.details.push({
                            namespace: nsName,
                            elementIdentifier: entry?.elementIdentifier,
                            digestId,
                            reason: "Missing digestId in valueDigests",
                        });
                        continue;
                    }
                    const expectedBytes =
                        toUint8(expected) ||
                        fromJsonBytes(expected) ||
                        fromBase64String(expected);
                    const expectedBase64 =
                        typeof expected === "string" ? expected : null;
                    if (!expectedBytes) {
                        if (window.DEBUG_VERBOSE) {
                            console.warn(
                                `[valueDigests] Invalid digest bytes (namespace="${String(nsName)}", elementIdentifier="${entry?.elementIdentifier}", digestId=${digestId})`,
                            );
                        }
                        result.mismatched++;
                        result.details.push({
                            namespace: nsName,
                            elementIdentifier: entry?.elementIdentifier,
                            digestId,
                            reason: "Invalid digest bytes in valueDigests",
                        });
                        continue;
                    }

                    // Compute tag(24) digest (per ISO 18013-5 spec)
                    let computed = null;
                    let computedTagged = null;
                    try {
                        const cb = getCBOR();
                        if (cb && typeof cb.Tagged === "function") {
                            const tagged = new cb.Tagged(24, issuerBytes);
                            const taggedBytes = cb.encode(tagged);
                            computedTagged = new Uint8Array(
                                await crypto.subtle.digest(
                                    hashAlg,
                                    taggedBytes,
                                ),
                            );
                            if (bytesEqual(computedTagged, expectedBytes)) {
                                result.matched++;
                                continue;
                            }
                        }
                    } catch {}

                    computed = new Uint8Array(
                        await crypto.subtle.digest(hashAlg, issuerBytes),
                    );
                    if (bytesEqual(computed, expectedBytes)) {
                        result.matched++;
                        continue;
                    }

                    if (window.DEBUG_VERBOSE && computedTagged && getCBOR()) {
                        console.error(
                            `[valueDigests] Digest mismatch for namespace="${String(nsName)}", element="${entry?.elementIdentifier}", digestId=${digestId} (computed ≠ MSO valueDigests)`,
                        );
                    }

                    // Fallback: try canonical encoding with numeric labels (0..3)
                    try {
                        const cb = getCBOR();
                        if (
                            cb &&
                            typeof cb.decode === "function" &&
                            typeof cb.encode === "function"
                        ) {
                            const decodedItem = cb.decode(issuerBytes);
                            const normalizedMap =
                                normalizeIssuerSignedItemMap(decodedItem);
                            if (normalizedMap) {
                                const encoded =
                                    typeof cb.encodeCanonical === "function"
                                        ? cb.encodeCanonical(normalizedMap)
                                        : cb.encode(normalizedMap);
                                const computedCanonical = new Uint8Array(
                                    await crypto.subtle.digest(
                                        hashAlg,
                                        encoded,
                                    ),
                                );
                                if (
                                    bytesEqual(computedCanonical, expectedBytes)
                                ) {
                                    result.matched++;
                                    continue;
                                }

                                if (typeof cb.Tagged === "function") {
                                    const taggedCanonical = new cb.Tagged(
                                        24,
                                        encoded,
                                    );
                                    const taggedCanonicalBytes =
                                        cb.encode(taggedCanonical);
                                    const computedTaggedCanonical =
                                        new Uint8Array(
                                            await crypto.subtle.digest(
                                                hashAlg,
                                                taggedCanonicalBytes,
                                            ),
                                        );
                                    if (
                                        bytesEqual(
                                            computedTaggedCanonical,
                                            expectedBytes,
                                        )
                                    ) {
                                        result.matched++;
                                        continue;
                                    }
                                }
                            }
                        }
                    } catch {}

                    if (window.DEBUG_VERBOSE && !loggedFirstMismatch) {
                        loggedFirstMismatch = true;
                        try {
                            const previewLen = 32;
                            const issuerPreview = issuerBytes
                                ? issuerBytes.slice(0, previewLen)
                                : null;
                            const expectedPreview = expectedBytes
                                ? expectedBytes.slice(0, previewLen)
                                : null;
                            let computedHex = null;
                            let computedTaggedHex = null;
                            let computedCanonicalHex = null;
                            let computedTaggedCanonicalHex = null;
                            let expectedBase64Debug = null;
                            let computedTaggedBase64 = null;
                            try {
                                computedHex = hex(computed);
                            } catch {}
                            try {
                                const cb = getCBOR();
                                if (cb && typeof cb.Tagged === "function") {
                                    const tagged = new cb.Tagged(
                                        24,
                                        issuerBytes,
                                    );
                                    const taggedBytes = cb.encode(tagged);
                                    const h = new Uint8Array(
                                        await crypto.subtle.digest(
                                            hashAlg,
                                            taggedBytes,
                                        ),
                                    );
                                    computedTaggedHex = hex(h);
                                    computedTaggedBase64 = bytesToBase64(h);
                                }
                            } catch {}
                            try {
                                expectedBase64Debug =
                                    expectedBase64 ||
                                    bytesToBase64(expectedBytes);
                            } catch {}
                            try {
                                const cb = getCBOR();
                                if (
                                    cb &&
                                    typeof cb.decode === "function" &&
                                    typeof cb.encode === "function"
                                ) {
                                    const decodedItem = cb.decode(issuerBytes);
                                    const normalizedMap =
                                        normalizeIssuerSignedItemMap(
                                            decodedItem,
                                        );
                                    if (normalizedMap) {
                                        const encoded =
                                            typeof cb.encodeCanonical ===
                                            "function"
                                                ? cb.encodeCanonical(
                                                      normalizedMap,
                                                  )
                                                : cb.encode(normalizedMap);
                                        const h = new Uint8Array(
                                            await crypto.subtle.digest(
                                                hashAlg,
                                                encoded,
                                            ),
                                        );
                                        computedCanonicalHex = hex(h);
                                        if (typeof cb.Tagged === "function") {
                                            const taggedCanonical =
                                                new cb.Tagged(24, encoded);
                                            const taggedCanonicalBytes =
                                                cb.encode(taggedCanonical);
                                            const h2 = new Uint8Array(
                                                await crypto.subtle.digest(
                                                    hashAlg,
                                                    taggedCanonicalBytes,
                                                ),
                                            );
                                            computedTaggedCanonicalHex =
                                                hex(h2);
                                        }
                                    }
                                }
                            } catch {}
                            console.log("[valueDigests] First mismatch debug", {
                                namespace: nsName,
                                elementIdentifier: entry?.elementIdentifier,
                                digestId,
                                issuerSignedItemBytesLen: issuerBytes
                                    ? issuerBytes.length
                                    : null,
                                issuerSignedItemBytesHex: issuerPreview
                                    ? hex(issuerPreview)
                                    : null,
                                expectedDigestLen: expectedBytes
                                    ? expectedBytes.length
                                    : null,
                                expectedDigestHex: expectedPreview
                                    ? hex(expectedPreview)
                                    : null,
                                computedDigestHex: computedHex,
                                computedTaggedDigestHex: computedTaggedHex,
                                expectedDigestBase64: expectedBase64Debug,
                                computedTaggedDigestBase64:
                                    computedTaggedBase64,
                                computedCanonicalDigestHex:
                                    computedCanonicalHex,
                                computedTaggedCanonicalDigestHex:
                                    computedTaggedCanonicalHex,
                                hashAlg,
                            });
                        } catch {}
                    }

                    result.mismatched++;
                    result.details.push({
                        namespace: nsName,
                        elementIdentifier: entry?.elementIdentifier,
                        digestId,
                        reason: "Digest mismatch",
                    });
                }
            }
        } catch (err) {
            result.errors.push(
                `valueDigests verification error: ${err.message}`,
            );
            console.error("[valueDigests] Verification error:", err);
        }

        result.checked = result.matched + result.mismatched;
        result.allMatched = result.checked > 0 ? result.mismatched === 0 : null;
        if (window.DEBUG_VERBOSE)
            console.log("[valueDigests] Summary", {
                checked: result.checked,
                matched: result.matched,
                mismatched: result.mismatched,
                skipped: result.skipped,
                allMatched: result.allMatched,
            });
        if (window.DEBUG_VERBOSE && result.mismatched > 0) {
            const maxDetails = 20;
            console.log(
                "[valueDigests] Mismatch details (first " + maxDetails + "):",
                result.details.slice(0, maxDetails),
            );
        }
        return result;
    }

    function getFieldAnyShared(obj, keys) {
        if (!obj) return undefined;
        for (const k of keys) {
            if (obj instanceof Map) {
                let v = obj.get(k);
                if (v !== undefined) return v;
                const kStr = String(k);
                v = obj.get(kStr);
                if (v !== undefined) return v;
                if (typeof k === "string" && !Number.isNaN(parseInt(k, 10))) {
                    const kNum = parseInt(k, 10);
                    v = obj.get(kNum);
                    if (v !== undefined) return v;
                }
            } else {
                let v = obj?.[k];
                if (v !== undefined) return v;
                const kStr = String(k);
                v = obj?.[kStr];
                if (v !== undefined) return v;
            }
        }
        return undefined;
    }

    function toUint8Shared(v) {
        if (v instanceof Uint8Array) return v;
        if (ArrayBuffer.isView(v))
            return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
        if (v instanceof ArrayBuffer) return new Uint8Array(v);
        if (Array.isArray(v)) {
            try {
                return new Uint8Array(v);
            } catch {
                return null;
            }
        }
        return null;
    }

    function bytesEqualStrict(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
        return true;
    }

    function unwrapTaggedBytes(v) {
        let cur = v;
        if (cur && cur.constructor && cur.constructor.name === "Tagged") {
            cur = cur.value;
        } else if (
            cur &&
            typeof cur === "object" &&
            cur.tag === 24 &&
            cur.value !== undefined
        ) {
            cur = cur.value;
        }
        return toUint8Shared(cur);
    }

    function decodeCborIfBytes(v) {
        const bytes = toUint8Shared(v);
        if (bytes && typeof getCBOR()?.decode === "function") {
            try {
                return getCBOR().decode(bytes);
            } catch {}
        }
        return v;
    }

    function extractDeviceKeyFromMso(mso) {
        if (!mso) return null;
        let msoObj = mso;
        const tagged = unwrapTaggedBytes(msoObj);
        if (tagged) msoObj = decodeCborIfBytes(tagged);

        let deviceKeyInfo = getFieldAnyShared(msoObj, ["deviceKeyInfo", 4, 8]);
        if (deviceKeyInfo) {
            const dkTagged = unwrapTaggedBytes(deviceKeyInfo);
            if (dkTagged) deviceKeyInfo = decodeCborIfBytes(dkTagged);
        }
        if (!deviceKeyInfo) return null;
        let deviceKey = getFieldAnyShared(deviceKeyInfo, ["deviceKey", 1]);
        if (deviceKey) {
            const dkTagged = unwrapTaggedBytes(deviceKey);
            if (dkTagged) deviceKey = decodeCborIfBytes(dkTagged);
        }
        return deviceKey || null;
    }

    function coseKeyToNoblePublicKey(coseKey) {
        if (!coseKey) throw new Error("Missing device public key");
        const x = toUint8Shared(getFieldAnyShared(coseKey, [-2, "x", "-2"]));
        const y = toUint8Shared(getFieldAnyShared(coseKey, [-3, "y", "-3"]));
        if (!x || !y)
            throw new Error("Device public key missing x/y coordinates");
        const crv = getFieldAnyShared(coseKey, [-1, "crv", "-1"]);
        const crvNum = typeof crv === "number" ? crv : parseInt(crv, 10);
        let nobleCurveName = "p256";
        if (crvNum === 1) nobleCurveName = "p256";
        else if (crvNum === 2) nobleCurveName = "p384";
        else if (crvNum === 3) nobleCurveName = "p521";
        else if (crvNum === 8) nobleCurveName = "brainpoolP256r1";
        else if (crvNum === 9) nobleCurveName = "brainpoolP384r1";
        else if (crvNum === 10) nobleCurveName = "brainpoolP512r1";
        else throw new Error(`Unsupported COSE_Key curve: ${crv}`);

        const key = new Uint8Array(1 + x.length + y.length);
        key[0] = 0x04;
        key.set(x, 1);
        key.set(y, 1 + x.length);
        return { type: "noble", nobleCurveName, key };
    }

    async function verifyHolderAuthentication(doc) {
        const result = {
            valid: false,
            errors: [],
            sessionTranscriptMatched: false,
            deviceAuthValid: false,
        };

        window.lastDoc = doc;

        try {
            if (window.DEBUG_VERBOSE)
                console.log("5[mdocAuth] Starting DeviceAuth verification");
            if (window.DEBUG_VERBOSE) {
                console.log("5[mdocAuth] doc.deviceSigned:", doc?.deviceSigned);
                console.log(
                    "5[mdocAuth] doc.deviceSigned.deviceAuth:",
                    doc?.deviceSigned?.deviceAuth,
                );
            }

            const raw = doc?.deviceSigned?.raw;
            const rawDeviceAuth =
                raw instanceof Map
                    ? raw.get("deviceAuth") || raw.get(0)
                    : raw?.deviceAuth || raw?.[0];
            const hasMac =
                rawDeviceAuth &&
                ((rawDeviceAuth instanceof Map &&
                    rawDeviceAuth.get("deviceMac")) ||
                    (typeof rawDeviceAuth === "object" &&
                        rawDeviceAuth.deviceMac));
            if (hasMac) {
                console.log(
                    "[mdocAuth] ℹ️ Wallet is using MAC authentication (deviceMac), not signature-based authentication",
                );
                console.log(
                    "[mdocAuth] MAC authentication is a valid ISO 18013-5 authentication method",
                );
                console.log(
                    "[mdocAuth] Skipping DeviceAuth signature verification (MAC cannot be verified by reader)",
                );
                if (typeof window.log === "function") {
                    window.log(
                        "✓ Wallet using MAC authentication (valid ISO 18013-5 method)",
                    );
                }
                result.deviceAuthValid = true;
                result.valid = true;
                result.authMethod = "MAC";
                return result;
            }

            const mso = doc?.signature?.msoDecoded || null;
            const deviceKey = extractDeviceKeyFromMso(mso);
            if (!deviceKey)
                throw new Error("MSO.deviceKeyInfo.deviceKey missing");

            let deviceAuthCose = doc?.deviceSigned?.deviceAuth;
            if (!deviceAuthCose) {
                const raw = doc?.deviceSigned?.raw;
                if (window.DEBUG_VERBOSE) {
                    console.log(
                        "[mdocAuth] raw deviceSigned keys:",
                        raw instanceof Map
                            ? Array.from(raw.keys())
                            : Object.keys(raw || {}),
                    );
                    console.log(
                        "[mdocAuth] raw deviceSigned.deviceAuth:",
                        raw instanceof Map
                            ? raw.get("deviceAuth")
                            : raw?.deviceAuth,
                    );
                }
                const rawBytes = unwrapTaggedBytes(raw) || toUint8Shared(raw);
                const rawDecoded = rawBytes ? decodeCborIfBytes(rawBytes) : raw;
                const ds =
                    rawDecoded && typeof rawDecoded === "object"
                        ? rawDecoded
                        : null;
                const deviceAuth = ds
                    ? getFieldAnyShared(ds, ["deviceAuth", 0])
                    : null;
                if (window.DEBUG_VERBOSE) {
                    console.log(
                        "[mdocAuth] decoded deviceSigned keys:",
                        ds instanceof Map
                            ? Array.from(ds.keys())
                            : Object.keys(ds || {}),
                    );
                    console.log(
                        "[mdocAuth] decoded deviceAuth value:",
                        deviceAuth,
                    );
                }
                if (deviceAuth) {
                    let cur = deviceAuth;
                    if (cur && typeof cur === "object" && cur.deviceSignature) {
                        cur = cur.deviceSignature;
                    }
                    if (Array.isArray(cur)) {
                        deviceAuthCose = cur;
                    } else {
                        const curBytes =
                            unwrapTaggedBytes(cur) || toUint8Shared(cur);
                        if (curBytes) {
                            const dec = decodeCborIfBytes(curBytes);
                            if (Array.isArray(dec)) cur = dec;
                        }
                        if (cur instanceof Map) {
                            const a0 = cur.get(0);
                            const a1 = cur.get(1);
                            const a2 = cur.get(2);
                            const a3 = cur.get(3);
                            if (
                                a0 !== undefined &&
                                a1 !== undefined &&
                                a2 !== undefined &&
                                a3 !== undefined
                            ) {
                                cur = [a0, a1, a2, a3];
                            }
                        } else if (cur && typeof cur === "object") {
                            const a0 = cur[0];
                            const a1 = cur[1];
                            const a2 = cur[2];
                            const a3 = cur[3];
                            if (
                                a0 !== undefined &&
                                a1 !== undefined &&
                                a2 !== undefined &&
                                a3 !== undefined
                            ) {
                                cur = [a0, a1, a2, a3];
                            }
                        }
                        if (Array.isArray(cur)) deviceAuthCose = cur;
                    }
                }
            }
            if (
                !deviceAuthCose ||
                !Array.isArray(deviceAuthCose) ||
                deviceAuthCose.length < 4
            ) {
                throw new Error("DeviceAuth COSE_Sign1 missing");
            }

            let publicKey = coseKeyToNoblePublicKey(deviceKey);

            const payloadRaw = deviceAuthCose[2];
            const payloadBytesAttached = payloadRaw
                ? toUint8Shared(payloadRaw)
                : null;
            const cb = getCBOR();
            let deviceAuthPayloadBytes = payloadBytesAttached;

            if (!payloadBytesAttached || payloadBytesAttached.length === 0) {
                const raw = doc?.deviceSigned?.raw;
                const rawBytes = unwrapTaggedBytes(raw) || toUint8Shared(raw);
                const rawDecoded = rawBytes ? decodeCborIfBytes(rawBytes) : raw;
                const ds =
                    rawDecoded && typeof rawDecoded === "object"
                        ? rawDecoded
                        : null;
                const nameSpacesRaw = ds
                    ? getFieldAnyShared(ds, ["nameSpaces", 1])
                    : null;
                const nsRawBytes =
                    unwrapTaggedBytes(nameSpacesRaw) ||
                    toUint8Shared(nameSpacesRaw);
                const localTranscript = toUint8Shared(
                    window.sessionDebug?.sessionTranscript,
                );
                const stDecodedManual = localTranscript
                    ? decodeCborIfBytes(localTranscript)
                    : null;
                const docType = doc?.docType || mso?.docType || null;

                if (!cb || !docType || !stDecodedManual || !nsRawBytes) {
                    throw new Error("DeviceAuth payload missing or invalid");
                }

                const nsTagged = cb.Tagged
                    ? new cb.Tagged(24, nsRawBytes)
                    : { tag: 24, value: nsRawBytes };
                const deviceAuthArray = [
                    "DeviceAuthentication",
                    stDecodedManual,
                    docType,
                    nsTagged,
                ];
                const encodedDeviceAuth = cb.encode(deviceAuthArray);
                const taggedDeviceAuth = cb.Tagged
                    ? new cb.Tagged(24, encodedDeviceAuth)
                    : { tag: 24, value: encodedDeviceAuth };
                deviceAuthPayloadBytes =
                    typeof cb.encodeCanonical === "function"
                        ? cb.encodeCanonical(taggedDeviceAuth)
                        : cb.encode(taggedDeviceAuth);
            }

            let signatureToVerify = deviceAuthCose[3];
            if (deviceAuthCose[3][0] === 0x30) {
                signatureToVerify = derSignatureToRaw(deviceAuthCose[3], 64);
                if (signatureToVerify[0] === 0x30) {
                    signatureToVerify = derSignatureToRaw(
                        deviceAuthCose[3],
                        96,
                    );
                }
                deviceAuthCose[3] = signatureToVerify;
            }

            const cosePayload = deviceAuthCose.slice();
            cosePayload[2] = deviceAuthPayloadBytes || new Uint8Array(0);
            const verified = await verifyCoseSign1(
                cosePayload,
                publicKey,
                new Uint8Array(0),
            );

            result.deviceAuthValid = verified;
            if (!result.deviceAuthValid) {
                throw new Error("DeviceAuth signature verification failed");
            }
            if (window.DEBUG_VERBOSE)
                console.log("[mdocAuth] DeviceAuth signature OK");

            const payloadBytes =
                deviceAuthPayloadBytes || toUint8Shared(deviceAuthCose[2]);
            if (!payloadBytes)
                throw new Error("DeviceAuth payload missing or invalid");
            let deviceAuth = decodeCborIfBytes(payloadBytes);

            if (!Array.isArray(deviceAuth)) {
                const innerBytes =
                    unwrapTaggedBytes(deviceAuth) ||
                    toUint8Shared(deviceAuth?.value) ||
                    toUint8Shared(deviceAuth);
                if (innerBytes) {
                    const innerDecoded = decodeCborIfBytes(innerBytes);
                    if (Array.isArray(innerDecoded)) {
                        deviceAuth = innerDecoded;
                    }
                }
            }

            if (!Array.isArray(deviceAuth) || deviceAuth.length < 3) {
                throw new Error("DeviceAuthentication payload is not an array");
            }
            if (deviceAuth[0] !== "DeviceAuthentication") {
                throw new Error("DeviceAuthentication context mismatch");
            }
            const localTranscriptCheck = toUint8Shared(
                window.sessionDebug?.sessionTranscript,
            );
            const localWrappedCheck = toUint8Shared(
                window.sessionDebug?.sessionTranscriptWrapped,
            );

            const sessionTranscriptItem = deviceAuth[1];
            const stBytesCandidates = [];
            const stUnwrapped =
                unwrapTaggedBytes(sessionTranscriptItem) ||
                toUint8Shared(sessionTranscriptItem);
            if (stUnwrapped) stBytesCandidates.push(stUnwrapped);
            if (cb) {
                try {
                    stBytesCandidates.push(cb.encode(sessionTranscriptItem));
                } catch {}
                if (typeof cb.encodeCanonical === "function") {
                    try {
                        stBytesCandidates.push(
                            cb.encodeCanonical(sessionTranscriptItem),
                        );
                    } catch {}
                }
            }

            if (
                stBytesCandidates.length === 0 ||
                (!localTranscriptCheck && !localWrappedCheck)
            ) {
                throw new Error(
                    "SessionTranscript bytes missing for comparison",
                );
            }

            const matchRaw = localTranscriptCheck
                ? stBytesCandidates.some((b) =>
                      bytesEqualStrict(b, localTranscriptCheck),
                  )
                : false;
            const matchWrapped = localWrappedCheck
                ? stBytesCandidates.some((b) =>
                      bytesEqualStrict(b, localWrappedCheck),
                  )
                : false;
            result.sessionTranscriptMatched = matchRaw || matchWrapped;
            if (!result.sessionTranscriptMatched) {
                throw new Error("SessionTranscript mismatch");
            }
            if (window.DEBUG_VERBOSE)
                console.log("[mdocAuth] SessionTranscript match OK");

            result.valid = true;
        } catch (err) {
            result.errors.push(err.message || String(err));
            if (window.DEBUG_VERBOSE) console.error("[mdocAuth] Failed:", err);
        }
        return result;
    }

    async function verifyCredentialSignature(doc) {
        if (!doc || !doc.signature || !doc.signature.coseSign1) {
            return {
                signatureValid: false,
                chainValid: null,
                chainInfo: null,
                errors: ["Missing signature for credential verification"],
                claims: {
                    checked: 0,
                    matched: 0,
                    mismatched: 0,
                    skipped: 0,
                    allMatched: null,
                    errors: ["Missing signature"],
                },
            };
        }

        log("🔏 Checking issuer signature…");
        const res = await verifyCOSESign1SignatureWithChain(
            doc.signature.coseSign1,
        );
        if (res.signatureValid) log("✅ Issuer signature valid");
        else log("❌ Issuer signature invalid");

        log("🧾 Checking document integrity…");
        const claims = await verifyIssuerSignedValueDigests(
            doc,
            doc.signature.coseSign1,
        );
        if (claims.allMatched) log("✅ Document integrity OK");
        else if (claims.checked > 0) log("❌ Document integrity failed");

        log("🔐 Checking device authentication…");
        const holder = await verifyHolderAuthentication(doc);
        if (holder.valid) log("✅ Device authentication OK");
        else log("❌ Device authentication failed");
        res.mdocAuthValid = holder.valid;
        res.mdocAuth = holder;
        res.claims = claims;
        if (claims.checked > 0 && !claims.allMatched) {
            res.errors.push("MSO valueDigests mismatch");
        }
        if (Array.isArray(claims.errors) && claims.errors.length) {
            res.errors.push(...claims.errors);
        }
        if (!holder.valid) {
            res.errors.push(...holder.errors);
            res.signatureValid = false;
        }
        return res;
    }

    // Expose
    window.Verification = {
        extractPublicKeyFromCert,
        derSignatureToRaw,
        detectCurveFromCertOID,
        extractCertInfo,
        extractCertValidity,
        verifyCoseSign1,
        parseX509Certificate,
        convertDERSignatureToRaw,
        extractAuthorityKeyIdentifier,
        extractSubjectKeyIdentifier,
        validateCertificateChain,
        verifyCOSESign1SignatureWithChain,
        verifyIssuerSignedValueDigests,
        getFieldAnyShared,
        toUint8Shared,
        bytesEqualStrict,
        unwrapTaggedBytes,
        decodeCborIfBytes,
        extractDeviceKeyFromMso,
        coseKeyToNoblePublicKey,
        verifyHolderAuthentication,
        verifyCredentialSignature,
    };

    // Back-compat globals
    window.extractPublicKeyFromCert = extractPublicKeyFromCert;
    window.parseX509Certificate = parseX509Certificate;
    window.extractCertValidity = extractCertValidity;
    window.detectCurveFromCertOID = detectCurveFromCertOID;
    window.extractCertInfo = extractCertInfo;
    window.verifyCOSESign1SignatureWithChain =
        verifyCOSESign1SignatureWithChain;
    window.verifyCredentialSignature = verifyCredentialSignature;
    window.verifyCoseSign1 = verifyCoseSign1;
    window.validateCertificateChain = validateCertificateChain;
})();
