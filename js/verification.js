/*
  Verification module
  - Strict verification delegated to iso18013-security through Iso18013Bridge
  - Lightweight certificate metadata helpers kept for UI rendering
*/

(function () {
    const log = window.log || console.log;

    function getBridge() {
        if (!window.Iso18013Bridge) {
            throw new Error("Iso18013Bridge is not available");
        }
        return window.Iso18013Bridge;
    }

    function toUint8Shared(value) {
        if (value instanceof Uint8Array) return value;
        if (ArrayBuffer.isView(value)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (value instanceof ArrayBuffer) return new Uint8Array(value);
        if (Array.isArray(value)) {
            try {
                return new Uint8Array(value);
            } catch {
                return null;
            }
        }
        return null;
    }

    function getFieldAnyShared(obj, keys) {
        if (!obj) return undefined;
        for (const key of keys) {
            if (obj instanceof Map) {
                let v = obj.get(key);
                if (v !== undefined) return v;
                const keyAsString = String(key);
                v = obj.get(keyAsString);
                if (v !== undefined) return v;
                if (typeof key === "string" && !Number.isNaN(parseInt(key, 10))) {
                    v = obj.get(parseInt(key, 10));
                    if (v !== undefined) return v;
                }
            } else {
                let v = obj[key];
                if (v !== undefined) return v;
                v = obj[String(key)];
                if (v !== undefined) return v;
            }
        }
        return undefined;
    }

    function bytesEqualStrict(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        for (let i = 0; i < a.length; i += 1) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    function unwrapTaggedBytes(value) {
        let cur = value;
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

    function decodeCborIfBytes(value) {
        const bytes = toUint8Shared(value);
        if (!bytes || !window.CBOR || typeof window.CBOR.decode !== "function") {
            return value;
        }
        try {
            return window.CBOR.decode(bytes);
        } catch {
            return value;
        }
    }

    function detectCurveFromCertOID(certDer) {
        try {
            const cert =
                certDer instanceof Uint8Array
                    ? certDer
                    : new Uint8Array(certDer);
            const curveOids = {
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

            for (const [curve, oid] of Object.entries(curveOids)) {
                for (let i = 0; i <= cert.length - oid.length; i += 1) {
                    let match = true;
                    for (let j = 0; j < oid.length; j += 1) {
                        if (cert[i + j] !== oid[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) return curve;
                }
            }
            return null;
        } catch {
            return null;
        }
    }

    function parseDerLength(bytes, offset) {
        const firstByte = bytes[offset];
        if (firstByte < 0x80) {
            return { length: firstByte, bytesUsed: 1 };
        }
        const numBytes = firstByte & 0x7f;
        let length = 0;
        for (let i = 0; i < numBytes; i += 1) {
            length = (length << 8) | bytes[offset + 1 + i];
        }
        return { length, bytesUsed: 1 + numBytes };
    }

    function extractString(bytes, offset) {
        const tag = bytes[offset];
        const lenInfo = parseDerLength(bytes, offset + 1);
        const start = offset + 1 + lenInfo.bytesUsed;
        const end = start + lenInfo.length;
        if (tag === 0x0c || tag === 0x13 || tag === 0x16) {
            return new TextDecoder().decode(bytes.slice(start, end));
        }
        return null;
    }

    function extractCertInfo(certDer) {
        try {
            const cert = new Uint8Array(certDer);
            let offset = 0;
            if (cert[offset] !== 0x30) {
                return {
                    subjectCN: null,
                    issuerCN: null,
                    subjectDN: null,
                    issuerDN: null,
                };
            }
            offset += 1;
            const certLen = parseDerLength(cert, offset);
            offset += certLen.bytesUsed;
            if (cert[offset] !== 0x30) {
                return {
                    subjectCN: null,
                    issuerCN: null,
                    subjectDN: null,
                    issuerDN: null,
                };
            }
            offset += 1;
            const tbsLen = parseDerLength(cert, offset);
            offset += tbsLen.bytesUsed;
            if (cert[offset] === 0xa0) {
                offset += 1;
                const verLen = parseDerLength(cert, offset);
                offset += verLen.bytesUsed + verLen.length;
            }
            if (cert[offset] === 0x02) {
                offset += 1;
                const snLen = parseDerLength(cert, offset);
                offset += snLen.bytesUsed + snLen.length;
            }
            if (cert[offset] === 0x30) {
                offset += 1;
                const algLen = parseDerLength(cert, offset);
                offset += algLen.bytesUsed + algLen.length;
            }

            const readDn = (startOffset) => {
                if (cert[startOffset] !== 0x30) {
                    return {
                        endOffset: startOffset,
                        cn: null,
                        dn: null,
                    };
                }
                const lenInfo = parseDerLength(cert, startOffset + 1);
                const bodyStart = startOffset + 1 + lenInfo.bytesUsed;
                const bodyEnd = bodyStart + lenInfo.length;
                let pos = bodyStart;
                let cn = null;
                const parts = [];

                while (pos < bodyEnd) {
                    if (cert[pos] !== 0x31) {
                        pos += 1;
                        continue;
                    }
                    const setLen = parseDerLength(cert, pos + 1);
                    const setStart = pos + 1 + setLen.bytesUsed;
                    const setEnd = setStart + setLen.length;
                    if (cert[setStart] === 0x30) {
                        const seqLen = parseDerLength(cert, setStart + 1);
                        let seqPos = setStart + 1 + seqLen.bytesUsed;
                        if (cert[seqPos] === 0x06) {
                            const oidLen = parseDerLength(cert, seqPos + 1);
                            const oidStart = seqPos + 1 + oidLen.bytesUsed;
                            const oidBytes = cert.slice(oidStart, oidStart + oidLen.length);
                            seqPos = oidStart + oidLen.length;
                            const value = extractString(cert, seqPos);
                            const oidHex = Array.from(oidBytes)
                                .map((b) => b.toString(16).padStart(2, "0"))
                                .join(" ");
                            if (value) {
                                if (oidHex === "55 04 03" && !cn) cn = value;
                                const attr =
                                    oidHex === "55 04 03"
                                        ? "CN"
                                        : oidHex === "55 04 0a"
                                          ? "O"
                                          : oidHex === "55 04 06"
                                            ? "C"
                                            : oidHex === "55 04 0b"
                                              ? "OU"
                                              : oidHex === "55 04 07"
                                                ? "L"
                                                : oidHex === "55 04 08"
                                                  ? "ST"
                                                  : `OID(${oidHex})`;
                                parts.push(`${attr}=${value}`);
                            }
                        }
                    }
                    pos = setEnd;
                }

                return {
                    endOffset: bodyEnd,
                    cn,
                    dn: parts.join(", "),
                };
            };

            const issuer = readDn(offset);
            offset = issuer.endOffset;

            if (cert[offset] === 0x30) {
                offset += 1;
                const validityLen = parseDerLength(cert, offset);
                offset += validityLen.bytesUsed + validityLen.length;
            }

            const subject = readDn(offset);

            return {
                subjectCN: subject.cn || null,
                issuerCN: issuer.cn || null,
                subjectDN: subject.dn || null,
                issuerDN: issuer.dn || null,
            };
        } catch {
            return {
                subjectCN: null,
                issuerCN: null,
                subjectDN: null,
                issuerDN: null,
            };
        }
    }

    function parseDerTime(bytes, offset) {
        const tag = bytes[offset];
        const lenInfo = parseDerLength(bytes, offset + 1);
        const start = offset + 1 + lenInfo.bytesUsed;
        const end = start + lenInfo.length;
        const timeString = new TextDecoder().decode(bytes.slice(start, end));
        if (tag === 0x17) {
            const yy = parseInt(timeString.slice(0, 2), 10);
            const year = yy >= 50 ? 1900 + yy : 2000 + yy;
            const month = parseInt(timeString.slice(2, 4), 10) - 1;
            const day = parseInt(timeString.slice(4, 6), 10);
            const hour = parseInt(timeString.slice(6, 8), 10);
            const minute = parseInt(timeString.slice(8, 10), 10);
            const second = parseInt(timeString.slice(10, 12), 10);
            return new Date(Date.UTC(year, month, day, hour, minute, second));
        }
        if (tag === 0x18) {
            const year = parseInt(timeString.slice(0, 4), 10);
            const month = parseInt(timeString.slice(4, 6), 10) - 1;
            const day = parseInt(timeString.slice(6, 8), 10);
            const hour = parseInt(timeString.slice(8, 10), 10);
            const minute = parseInt(timeString.slice(10, 12), 10);
            const second = parseInt(timeString.slice(12, 14), 10);
            return new Date(Date.UTC(year, month, day, hour, minute, second));
        }
        return null;
    }

    function extractCertValidity(certDer) {
        try {
            const cert = new Uint8Array(certDer);
            let offset = 0;
            if (cert[offset] !== 0x30) return { notBefore: null, notAfter: null };
            offset += 1;
            const certLen = parseDerLength(cert, offset);
            offset += certLen.bytesUsed;
            if (cert[offset] !== 0x30) return { notBefore: null, notAfter: null };
            offset += 1;
            const tbsLen = parseDerLength(cert, offset);
            offset += tbsLen.bytesUsed;
            if (cert[offset] === 0xa0) {
                offset += 1;
                const verLen = parseDerLength(cert, offset);
                offset += verLen.bytesUsed + verLen.length;
            }
            if (cert[offset] === 0x02) {
                offset += 1;
                const snLen = parseDerLength(cert, offset);
                offset += snLen.bytesUsed + snLen.length;
            }
            if (cert[offset] === 0x30) {
                offset += 1;
                const algLen = parseDerLength(cert, offset);
                offset += algLen.bytesUsed + algLen.length;
            }
            if (cert[offset] === 0x30) {
                offset += 1;
                const issuerLen = parseDerLength(cert, offset);
                offset += issuerLen.bytesUsed + issuerLen.length;
            }
            if (cert[offset] !== 0x30) return { notBefore: null, notAfter: null };
            offset += 1;
            const validityLen = parseDerLength(cert, offset);
            offset += validityLen.bytesUsed;
            const notBefore = parseDerTime(cert, offset);
            offset += 1;
            const notBeforeLen = parseDerLength(cert, offset);
            offset += notBeforeLen.bytesUsed + notBeforeLen.length;
            const notAfter = parseDerTime(cert, offset);
            return { notBefore, notAfter };
        } catch {
            return { notBefore: null, notAfter: null };
        }
    }

    async function extractPublicKeyFromCert(certDer, quiet = false) {
        try {
            const cert = toUint8Shared(certDer);
            if (!cert) throw new Error("certificate bytes are required");
            const curve = detectCurveFromCertOID(cert);
            if (!curve) throw new Error("Unsupported or undetected certificate curve");

            const coordinateLengthByCurve = {
                "P-256": 32,
                "P-384": 48,
                "P-521": 66,
                brainpoolP256r1: 32,
                brainpoolP320r1: 40,
                brainpoolP384r1: 48,
                brainpoolP512r1: 64,
            };
            const nobleCurveByCurve = {
                "P-256": "p256",
                "P-384": "p384",
                "P-521": "p521",
                brainpoolP256r1: "brainpoolP256r1",
                brainpoolP320r1: "brainpoolP320r1",
                brainpoolP384r1: "brainpoolP384r1",
                brainpoolP512r1: "brainpoolP512r1",
            };

            const coordinateLength = coordinateLengthByCurve[curve];
            const expectedLength = 1 + coordinateLength * 2;
            let key = null;
            for (let i = 0; i <= cert.length - expectedLength; i += 1) {
                if (cert[i] !== 0x04) continue;
                const candidate = cert.slice(i, i + expectedLength);
                const x = candidate.slice(1, 1 + coordinateLength);
                const y = candidate.slice(1 + coordinateLength, 1 + 2 * coordinateLength);
                if (x.length === coordinateLength && y.length === coordinateLength) {
                    key = candidate;
                    break;
                }
            }
            if (!key) throw new Error("Could not locate an uncompressed EC public key");

            return {
                type: "noble",
                curve,
                nobleCurveName: nobleCurveByCurve[curve] || null,
                key,
                x: key.slice(1, 1 + coordinateLength),
                y: key.slice(1 + coordinateLength),
            };
        } catch (error) {
            if (!quiet) console.error("Failed to extract public key from certificate:", error);
            return null;
        }
    }

    function extractDeviceKeyFromMso(mso) {
        if (!mso) return null;
        let msoObject = mso;
        const taggedMso = unwrapTaggedBytes(msoObject);
        if (taggedMso) msoObject = decodeCborIfBytes(taggedMso);

        let deviceKeyInfo = getFieldAnyShared(msoObject, ["deviceKeyInfo", 4, 8]);
        if (deviceKeyInfo) {
            const taggedKeyInfo = unwrapTaggedBytes(deviceKeyInfo);
            if (taggedKeyInfo) deviceKeyInfo = decodeCborIfBytes(taggedKeyInfo);
        }
        if (!deviceKeyInfo) return null;

        let deviceKey = getFieldAnyShared(deviceKeyInfo, ["deviceKey", 1]);
        if (deviceKey) {
            const taggedDeviceKey = unwrapTaggedBytes(deviceKey);
            if (taggedDeviceKey) deviceKey = decodeCborIfBytes(taggedDeviceKey);
        }
        return deviceKey || null;
    }

    function coseKeyToNoblePublicKey(coseKey) {
        if (!coseKey) throw new Error("Missing COSE key");
        const x = toUint8Shared(getFieldAnyShared(coseKey, [-2, "x", "-2"]));
        const y = toUint8Shared(getFieldAnyShared(coseKey, [-3, "y", "-3"]));
        if (!x || !y) {
            throw new Error("COSE key must contain x and y coordinates");
        }
        const crv = getFieldAnyShared(coseKey, [-1, "crv", "-1"]);
        const crvNum = typeof crv === "number" ? crv : parseInt(crv, 10);
        const curveByCose = {
            1: "p256",
            2: "p384",
            3: "p521",
            8: "brainpoolP256r1",
            9: "brainpoolP384r1",
            10: "brainpoolP512r1",
        };
        const nobleCurveName = curveByCose[crvNum];
        if (!nobleCurveName) throw new Error(`Unsupported COSE curve: ${String(crv)}`);
        const key = new Uint8Array(1 + x.length + y.length);
        key[0] = 0x04;
        key.set(x, 1);
        key.set(y, 1 + x.length);
        return {
            type: "noble",
            nobleCurveName,
            key,
        };
    }

    async function tryVerifyCredentialSignatureWithIsoLibraries(doc) {
        const bridge = getBridge();
        if (typeof bridge.verifyPresentedDocumentDetailed !== "function") {
            return null;
        }

        const codecDocument =
            doc?.codecDocument &&
            typeof doc.codecDocument === "object" &&
            typeof doc.codecDocument.encodeToCborValue === "function" &&
            typeof doc.codecDocument.docType === "string" &&
            doc.codecDocument.issuerSigned &&
            doc.codecDocument.deviceSigned
                ? doc.codecDocument
                : null;
        const rawDocument = doc?.rawDocument;
        if (!codecDocument && !rawDocument) {
            throw new Error("rawDocument/codecDocument missing from document view model");
        }

        const sessionTranscriptBytes = toUint8Shared(window.sessionDebug?.sessionTranscript);
        if (!sessionTranscriptBytes) {
            throw new Error("SessionTranscript bytes are not available");
        }

        const trustAnchors =
            (window.IacaManager?.getActiveIACAs?.() || [])
                .map((iaca) => iaca?.pem)
                .filter((pem) => typeof pem === "string" && pem.trim().length > 0);

        const sessionTranscript = bridge.decodeCbor(sessionTranscriptBytes);
        const document = rawDocument
            ? bridge.decodeMdocDocumentFromCborValue(rawDocument)
            : bridge.decodeMdocDocumentFromCborValue(codecDocument.encodeToCborValue());

        const verified = await bridge.verifyPresentedDocumentDetailed({
            document,
            sessionTranscript,
            trustAnchors,
        });

        const chainCertificates = Array.isArray(verified?.issuerChain?.chain)
            ? verified.issuerChain.chain
            : Array.isArray(verified?.issuerSignature?.chainFromLeaf)
              ? verified.issuerSignature.chainFromLeaf
              : [];
        const chainSubjects = chainCertificates
            .map((certificate) =>
                certificate?.subject ||
                certificate?.subjectName ||
                String(certificate || ""),
            )
            .filter(Boolean);

        return {
            signatureValid: verified?.issuerSignature?.ok === true,
            chainValid:
                verified?.issuerChain === null
                    ? null
                    : verified?.issuerChain?.ok === true,
            chainInfo: {
                valid:
                    verified?.issuerChain === null
                        ? null
                        : verified?.issuerChain?.ok === true,
                chain: chainSubjects,
                errors: verified?.issuerChain?.error
                    ? [verified.issuerChain.error]
                    : [],
            },
            mdocAuthValid: verified?.deviceAuth?.ok === true,
            holderAuthValid: verified?.deviceAuth?.ok === true,
            claims: {
                checked: 0,
                matched: 0,
                mismatched: 0,
                skipped: 0,
                allMatched: verified?.issuerSignature?.ok === true,
                errors: [],
            },
            errors: [],
            sharedVerification: verified,
        };
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

        try {
            log("🧩 Checking credential with iso18013 browser libraries…");
            const result = await tryVerifyCredentialSignatureWithIsoLibraries(doc);
            if (result?.signatureValid) log("✅ Shared issuer verification OK");
            else log("❌ Shared issuer verification failed");
            if (result?.mdocAuthValid) log("✅ Shared device authentication OK");
            else log("❌ Shared device authentication failed");
            return result;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error || "Unknown error");
            console.error("[Verification] Shared-library verification failed:", error);
            return {
                signatureValid: false,
                chainValid: null,
                chainInfo: null,
                errors: [message],
                claims: {
                    checked: 0,
                    matched: 0,
                    mismatched: 0,
                    skipped: 0,
                    allMatched: null,
                    errors: [message],
                },
                mdocAuthValid: false,
                mdocAuth: {
                    valid: false,
                    errors: [message],
                },
            };
        }
    }

    // Legacy-compatible placeholders (kept to avoid breaking optional debug tooling)
    async function verifyCoseSign1() {
        throw new Error("verifyCoseSign1 debug path removed. Use Iso18013Bridge.verifyCoseSign1.");
    }

    async function validateCertificateChain() {
        throw new Error("validateCertificateChain debug path removed. Chain validation is done by iso18013-security.");
    }

    function parseX509Certificate() {
        return null;
    }

    function convertDERSignatureToRaw(derSig) {
        return derSig;
    }

    function extractAuthorityKeyIdentifier() {
        return null;
    }

    function extractSubjectKeyIdentifier() {
        return null;
    }

    window.Verification = {
        extractPublicKeyFromCert,
        detectCurveFromCertOID,
        extractCertInfo,
        extractCertValidity,
        verifyCoseSign1,
        parseX509Certificate,
        convertDERSignatureToRaw,
        extractAuthorityKeyIdentifier,
        extractSubjectKeyIdentifier,
        validateCertificateChain,
        getFieldAnyShared,
        toUint8Shared,
        bytesEqualStrict,
        unwrapTaggedBytes,
        decodeCborIfBytes,
        extractDeviceKeyFromMso,
        coseKeyToNoblePublicKey,
        verifyCredentialSignature,
    };

    window.extractPublicKeyFromCert = extractPublicKeyFromCert;
    window.detectCurveFromCertOID = detectCurveFromCertOID;
    window.extractCertInfo = extractCertInfo;
    window.extractCertValidity = extractCertValidity;
    window.verifyCredentialSignature = verifyCredentialSignature;
    window.verifyCoseSign1 = verifyCoseSign1;
    window.validateCertificateChain = validateCertificateChain;
})();
