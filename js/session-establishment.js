(function () {
    let _activeReaderSession = null;

    function getNamedCurveFromCoseKey(coseKey) {
        const crv = typeof coseKey?.crv === "bigint" ? Number(coseKey.crv) : coseKey?.crv;
        switch (crv) {
            case 1:
                return "P-256";
            case 2:
                return "P-384";
            case 3:
                return "P-521";
            case 4:
                return "X25519";
            case 5:
                return "X448";
            default:
                return "P-256";
        }
    }

    function requireLibraries() {
        if (!window.Iso18013Session) {
            throw new Error("Iso18013Session browser bundle is not available");
        }
        if (!window.Iso18013Bridge) {
            throw new Error("Iso18013Bridge is not available");
        }
        return {
            session: window.Iso18013Session,
            bridge: window.Iso18013Bridge,
        };
    }

    function hex(buf) {
        return [...new Uint8Array(buf)]
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(" ");
    }

    function getActiveReaderSession() {
        return _activeReaderSession;
    }

    function setActiveReaderSession(readerSession) {
        _activeReaderSession = readerSession || null;
    }

    function resetReaderCoseKeyCache() {
        _activeReaderSession = null;
    }

    async function makeReaderEphemeralKeyPair(deviceEngagementBytes) {
        const { session, bridge } = requireLibraries();
        let namedCurve = "P-256";
        if (deviceEngagementBytes) {
            try {
                const deviceEngagement =
                    bridge.decodeDeviceEngagement(deviceEngagementBytes);
                const deviceKey = bridge.decodeCoseKey(
                    deviceEngagement.security.eKey,
                );
                namedCurve = getNamedCurveFromCoseKey(deviceKey);
            } catch (error) {
                console.warn(
                    "Failed to determine device curve, defaulting to P-256:",
                    error,
                );
            }
        }
        const readerSession =
            await session.Iso180135SessionEncryption.create({ namedCurve });
        _activeReaderSession = readerSession;
        return readerSession;
    }

    function buildReaderCoseKey() {
        const { bridge } = requireLibraries();
        if (!_activeReaderSession) {
            throw new Error("reader session not ready");
        }
        return bridge.decodeCoseKey(_activeReaderSession.getReaderKeyCose());
    }

    async function exportReaderPublicToCoseKey(readerSession) {
        const { bridge } = requireLibraries();
        const sessionInstance = readerSession || _activeReaderSession;
        if (!sessionInstance) {
            throw new Error("reader session not ready");
        }
        _activeReaderSession = sessionInstance;
        const coseKey = bridge.decodeCoseKey(sessionInstance.getReaderKeyCose());
        const x = coseKey.x instanceof Uint8Array ? coseKey.x : null;
        const fingerprint = x ? hex(x.slice(0, 4)) : "unknown";
        return {
            fingerprint,
            x: coseKey.x,
            y: coseKey.y,
            coseKey,
            coseKeyBytes: sessionInstance.getReaderKeyCose(),
        };
    }

    async function buildTranscriptArtifacts(deBytes, readerSession) {
        const { bridge } = requireLibraries();
        const sessionInstance = readerSession || _activeReaderSession;
        if (!deBytes) {
            throw new Error("DeviceEngagement bytes required");
        }
        if (!sessionInstance) {
            throw new Error("reader session not ready");
        }

        const artifacts = bridge.createAnnexATranscriptArtifacts({
            deviceEngagementBytes: deBytes,
            eReaderKeyBytes: sessionInstance.getReaderKeyCose(),
            qrHandover: null,
        });

        try {
            window.sessionDebug = window.sessionDebug || {};
            window.sessionDebug.sessionTranscript = artifacts.transcriptBytes;
            window.sessionDebug.sessionTranscriptWrapped =
                artifacts.wrappedTranscriptBytes;
            window.sessionDebug.eReaderKey = sessionInstance.getReaderKeyCose();
        } catch {}

        return artifacts;
    }

    async function buildTranscriptAAD(deBytes, readerSession) {
        const artifacts = await buildTranscriptArtifacts(deBytes, readerSession);
        const digest = await crypto.subtle.digest(
            "SHA-256",
            artifacts.wrappedTranscriptBytes,
        );
        return new Uint8Array(digest);
    }

    async function buildLegacySessionEstablishmentWithData(opts) {
        const {
            deBytes,
            readerKeyPair,
            buildRequestByType,
        } = opts || {};

        if (!deBytes || !readerKeyPair || !buildRequestByType) {
            throw new Error(
                `Missing inputs for SessionEstablishment build: ${
                    [
                        !deBytes ? "deBytes" : null,
                        !readerKeyPair ? "readerKeyPair" : null,
                        !buildRequestByType ? "buildRequestByType" : null,
                    ]
                        .filter(Boolean)
                        .join(", ")
                }`,
            );
        }

        const { bridge } = requireLibraries();
        const readerSession = readerKeyPair;
        _activeReaderSession = readerSession;

        const deviceEngagement = bridge.decodeDeviceEngagement(deBytes);
        const {
            transcriptBytes,
            wrappedTranscriptBytes,
        } = await buildTranscriptArtifacts(deBytes, readerSession);

        if (!readerSession.isInitialized()) {
            await readerSession.deriveSessionKeys(
                deviceEngagement.security.eKey,
                wrappedTranscriptBytes,
            );
        }

        const mdlRequest = await buildRequestByType();
        const encryptedRequest = await readerSession.encryptFromReader(
            mdlRequest,
        );
        const final = bridge.createSessionEstablishmentBytes({
            eReaderKeyBytes: readerSession.getReaderKeyCose(),
            data: encryptedRequest,
        });

        let transcriptAAD = null;
        try {
            const digest = await crypto.subtle.digest(
                "SHA-256",
                wrappedTranscriptBytes,
            );
            transcriptAAD = new Uint8Array(digest);
        } catch {}

        return {
            message: final,
            keys: readerSession.getDerivedKeysForDebug(),
            transcriptAAD,
            transcriptBytes,
            wrappedTranscriptBytes,
        };
    }

    window.SessionEstablishment = {
        makeReaderEphemeralKeyPair,
        exportReaderPublicToCoseKey,
        buildReaderCoseKey,
        resetReaderCoseKeyCache,
        buildTranscriptAAD,
        buildLegacySessionEstablishmentWithData,
        getActiveReaderSession,
        setActiveReaderSession,
    };
})();
