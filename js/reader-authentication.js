/*
  Copyright (c) 2026 Stelau
  Author: Nicolas Chalanset

  Reader Authentication (ISO 18013-5)
  - Manage reader private key (PKCS#8 EC) and certificate chain (PEM)
  - Delegate ReaderAuthentication / COSE_Sign1 construction to iso18013-security
*/

(function () {
    function requireLibraries() {
        if (!window.Iso18013Security) {
            throw new Error("Iso18013Security browser bundle is not available");
        }
        if (!window.Iso18013Bridge) {
            throw new Error("Iso18013Bridge is not available");
        }
        return {
            security: window.Iso18013Security,
            bridge: window.Iso18013Bridge,
        };
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
        let match;
        while ((match = re.exec(allPem))) {
            const type = match[1];
            const b64 = match[2]
                .replace(/[^A-Za-z0-9+/=\-_]/g, "")
                .replace(/-/g, "+")
                .replace(/_/g, "/");
            try {
                const raw = atob(b64);
                const bytes = new Uint8Array(raw.length);
                for (let i = 0; i < raw.length; i += 1) {
                    bytes[i] = raw.charCodeAt(i);
                }
                blocks.push({ type, bytes, pem: match[0] });
            } catch {
                // ignore malformed blocks
            }
        }
        return blocks;
    }

    function detectCurveFromCertPem(pem) {
        try {
            const blocks = parsePemBlocks(pem);
            const cert = blocks.find((block) => block.type === "CERTIFICATE");
            if (!cert) return null;
            if (window.detectCurveFromCertOID) {
                return window.detectCurveFromCertOID(cert.bytes);
            }
        } catch {}
        return null;
    }

    function firstCertDerArray(chainPem) {
        return parsePemBlocks(chainPem)
            .filter((block) => block.type === "CERTIFICATE")
            .map((block) => block.bytes);
    }

    function toCoseAlgorithmFromCurve(curveName) {
        const curve = String(curveName || "").toUpperCase();
        if (curve.includes("521") || curve.includes("512")) return -36n;
        if (curve.includes("384") || curve.includes("320")) return -35n;
        return -7n;
    }

    async function importPkcs8EcPrivateKey(pem, namedCurve) {
        const blocks = parsePemBlocks(pem);
        const pkcs8 = blocks.find((block) => block.type.includes("PRIVATE KEY"));
        if (!pkcs8) {
            throw new Error("No PKCS#8 private key found");
        }
        return crypto.subtle.importKey(
            "pkcs8",
            pkcs8.bytes,
            { name: "ECDSA", namedCurve },
            true,
            ["sign"],
        );
    }

    async function importPkcs8EcPrivateKeyAuto(pem) {
        try {
            const key = await importPkcs8EcPrivateKey(pem, "P-256");
            return { key, namedCurve: "P-256" };
        } catch {}
        const key = await importPkcs8EcPrivateKey(pem, "P-384");
        return { key, namedCurve: "P-384" };
    }

    async function loadReaderPrivateJwk() {
        const keyPem = loadKeyPem();
        if (!keyPem) {
            throw new Error("No private key configured");
        }
        const curveHint = detectCurveFromCertPem(loadChainPem());
        const preferredCurve = curveHint && curveHint.toUpperCase().includes("384")
            ? "P-384"
            : curveHint && curveHint.toUpperCase().includes("256")
              ? "P-256"
              : null;

        let keyResult;
        if (preferredCurve) {
            keyResult = {
                key: await importPkcs8EcPrivateKey(keyPem, preferredCurve),
                namedCurve: preferredCurve,
            };
        } else {
            keyResult = await importPkcs8EcPrivateKeyAuto(keyPem);
        }

        const jwk = await crypto.subtle.exportKey("jwk", keyResult.key);
        if (!jwk || !jwk.d || !jwk.x || !jwk.y || !jwk.crv) {
            throw new Error("Failed to export private EC key as JWK");
        }

        return {
            jwk,
            namedCurve: keyResult.namedCurve,
        };
    }

    async function signReaderAuthentication(itemsRequestCbor) {
        if (!loadEnabled()) {
            throw new Error("Reader authentication disabled");
        }

        const { security, bridge } = requireLibraries();
        const sessionTranscriptBytes = window.sessionDebug?.sessionTranscript;
        if (!(sessionTranscriptBytes instanceof Uint8Array)) {
            throw new Error("SessionTranscript not available yet");
        }

        const { jwk, namedCurve } = await loadReaderPrivateJwk();
        const x5chain = firstCertDerArray(loadChainPem());
        if (!x5chain.length) {
            throw new Error("No certificate(s) configured for x5chain");
        }

        const result = await security.signReaderAuthentication({
            sessionTranscript: sessionTranscriptBytes,
            itemsRequestBytes:
                itemsRequestCbor instanceof Uint8Array
                    ? itemsRequestCbor
                    : new Uint8Array(itemsRequestCbor),
            privateKey: jwk,
            algorithm: toCoseAlgorithmFromCurve(namedCurve),
            x5chain,
            provider: bridge.getSecurityCryptoProvider(),
        });

        return result.coseSign1;
    }

    function isEnabled() {
        return loadEnabled();
    }
    function setEnabled(value) {
        saveEnabled(!!value);
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
