(function () {
    function requireLibraries() {
        if (
            typeof window.Iso18013Codec === "undefined" ||
            typeof window.Iso18013Session === "undefined" ||
            typeof window.Iso18013Security === "undefined"
        ) {
            throw new Error(
                "ISO 18013 browser bundles are not loaded. Expected Iso18013Codec, Iso18013Session, and Iso18013Security.",
            );
        }

        return {
            codec: window.Iso18013Codec,
            session: window.Iso18013Session,
            security: window.Iso18013Security,
        };
    }

    function isPlainObject(value) {
        if (value === null || typeof value !== "object") {
            return false;
        }
        const prototype = Object.getPrototypeOf(value);
        return prototype === Object.prototype || prototype === null;
    }

    function normalizeCborValue(value) {
        const { codec } = requireLibraries();

        if (
            value === null ||
            value === undefined ||
            typeof value === "string" ||
            typeof value === "number" ||
            typeof value === "bigint" ||
            typeof value === "boolean"
        ) {
            return value;
        }
        if (value instanceof Uint8Array) {
            return value;
        }
        if (
            value &&
            typeof value === "object" &&
            typeof value.tag === "number" &&
            (value.contents !== undefined || value.value !== undefined)
        ) {
            return new codec.Tag(
                value.tag,
                normalizeCborValue(
                    value.contents !== undefined ? value.contents : value.value,
                ),
            );
        }
        if (ArrayBuffer.isView(value) && !(value instanceof DataView)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (value instanceof ArrayBuffer) {
            return new Uint8Array(value);
        }
        if (Array.isArray(value)) {
            return value.map(normalizeCborValue);
        }
        if (value instanceof Map) {
            return new Map(
                Array.from(value.entries()).map(([key, entryValue]) => [
                    normalizeCborValue(key),
                    normalizeCborValue(entryValue),
                ]),
            );
        }
        if (
            value &&
            typeof value === "object" &&
            value.type === "Buffer" &&
            Array.isArray(value.data)
        ) {
            return new Uint8Array(value.data);
        }
        if (
            value &&
            typeof value === "object" &&
            value.constructor &&
            value.constructor.name === "Tagged"
        ) {
            return new codec.Tag(
                value.tag,
                normalizeCborValue(
                    value.contents !== undefined ? value.contents : value.value,
                ),
            );
        }
        if (value instanceof Date || value instanceof Set || value instanceof URL) {
            return value;
        }
        if (isPlainObject(value)) {
            return Object.fromEntries(
                Object.entries(value).map(([key, entryValue]) => [
                    key,
                    normalizeCborValue(entryValue),
                ]),
            );
        }
        return value;
    }

    function mapToCoseKey(coseKeyMap) {
        const { codec } = requireLibraries();
        return new codec.CoseKey(
            2n,
            undefined,
            undefined,
            undefined,
            undefined,
            BigInt(coseKeyMap.get(-1) ?? 1),
            coseKeyMap.get(-2),
            coseKeyMap.get(-3),
        );
    }

    function createAnnexATranscriptArtifacts(input) {
        const { codec } = requireLibraries();
        const transcript = codec.createQrProximitySessionTranscript({
            deviceEngagementBytes: input.deviceEngagementBytes,
            eReaderKeyBytes: input.eReaderKeyBytes,
            qrHandover: input.qrHandover ?? null,
        });
        const transcriptBytes = codec.encodeCbor(transcript);
        const wrappedTranscriptBytes = codec.encodeCbor(
            codec.encodeTag24(transcript),
        );

        return {
            transcript,
            transcriptBytes,
            wrappedTranscriptBytes,
        };
    }

    function createSessionEstablishmentBytes(input) {
        const { session } = requireLibraries();
        return session
            .createSessionEstablishmentMessage({
                eReaderKeyBytes: input.eReaderKeyBytes,
                data: input.data,
            })
            .encode();
    }

    function decodeCbor(bytes) {
        const { codec } = requireLibraries();
        return codec.decodeCbor(bytes);
    }

    function describeCborShape(value, depth = 0) {
        if (depth > 4) {
            return "[max-depth]";
        }
        if (value === null) return "null";
        if (value === undefined) return "undefined";
        if (value instanceof Uint8Array) return `Uint8Array(${value.length})`;
        if (ArrayBuffer.isView(value)) {
            return `${value.constructor?.name || "TypedArray"}(${value.byteLength})`;
        }
        if (value instanceof ArrayBuffer) return `ArrayBuffer(${value.byteLength})`;
        if (Array.isArray(value)) {
            return {
                type: "Array",
                length: value.length,
                sample: value.slice(0, 4).map((entry) => describeCborShape(entry, depth + 1)),
            };
        }
        if (value instanceof Map) {
            return {
                type: "Map",
                size: value.size,
                sample: Array.from(value.entries())
                    .slice(0, 4)
                    .map(([key, entryValue]) => [
                        describeCborShape(key, depth + 1),
                        describeCborShape(entryValue, depth + 1),
                    ]),
            };
        }
        if (value instanceof Date) return `Date(${value.toISOString()})`;
        if (value instanceof Set) return `Set(${value.size})`;
        if (value instanceof URL) return `URL(${value.toString()})`;
        if (value && typeof value === "object") {
            return {
                type: value.constructor?.name || "Object",
                keys: Object.keys(value).slice(0, 8),
            };
        }
        return `${typeof value}:${String(value)}`;
    }

    function assertEncodable(label, value) {
        const { codec } = requireLibraries();
        try {
            codec.encodeCbor(value);
        } catch (error) {
            console.error(`[Iso18013Bridge] ${label} is not encodable`, {
                error,
                shape: describeCborShape(value),
                value,
            });
            throw error;
        }
    }

    function decodeMdocDocumentFromCborValue(value) {
        const { codec } = requireLibraries();
        if (
            value &&
            typeof value === "object" &&
            typeof value.docType === "string" &&
            value.issuerSigned &&
            value.deviceSigned &&
            typeof value.encodeToCborValue === "function"
        ) {
            return codec.MdocDocument.decode(
                codec.encodeCbor(normalizeCborValue(value.encodeToCborValue())),
            );
        }
        return codec.MdocDocument.decodeFromCborValue(normalizeCborValue(value));
    }

    function decodeDeviceResponse(bytes) {
        const { codec } = requireLibraries();
        return  codec.DeviceResponse.decode(bytes);
    }

    function decodeDeviceResponseFromCborValue(value) {
        const { codec } = requireLibraries();
        return codec.DeviceResponse.decodeFromCborValue(normalizeCborValue(value));
    }

    function decodeDeviceEngagement(bytes) {
        const { codec } = requireLibraries();
        return codec.DeviceEngagement.decode(bytes);
    }

    function decodeCoseKey(bytesOrValue) {
        const { codec } = requireLibraries();
        if (bytesOrValue && typeof bytesOrValue === "object") {
            if (
                typeof bytesOrValue.encodeToCborValue === "function" &&
                typeof bytesOrValue.kty !== "undefined"
            ) {
                return bytesOrValue;
            }
        }
        if (bytesOrValue instanceof Uint8Array) {
            return codec.CoseKey.decode(bytesOrValue);
        }
        return codec.CoseKey.decodeFromCborValue(normalizeCborValue(bytesOrValue));
    }

    function decodeSessionMessage(bytes) {
        const { codec } = requireLibraries();
        return codec.decodeSessionMessage(bytes);
    }

    function isSessionEstablishmentMessage(message) {
        const { codec } = requireLibraries();
        return codec.isSessionEstablishment(message);
    }

    function isSessionDataMessage(message) {
        const { codec } = requireLibraries();
        return codec.isSessionData(message);
    }

    async function verifyPresentedDocument(input) {
        const { codec, security } = requireLibraries();
        let normalizedDocument;
        try {
            normalizedDocument = decodeMdocDocumentFromCborValue(input.document);
        } catch (error) {
            throw new Error(
                `[Iso18013Bridge] document normalization failed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            );
        }

        let normalizedSessionTranscript;
        try {
            normalizedSessionTranscript =
                input.sessionTranscript instanceof Uint8Array
                    ? codec.decodeCbor(input.sessionTranscript)
                    : codec.decodeCbor(
                          codec.encodeCbor(
                              normalizeCborValue(input.sessionTranscript),
                          ),
                      );
        } catch (error) {
            throw new Error(
                `[Iso18013Bridge] sessionTranscript normalization failed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            );
        }

        try {
            assertEncodable(
                "verifyPresentedDocument.sessionTranscript",
                normalizedSessionTranscript,
            );
        } catch (error) {
            throw new Error(
                `[Iso18013Bridge] sessionTranscript encoding failed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            );
        }

        try {
            assertEncodable(
                "verifyPresentedDocument.document",
                normalizedDocument.encodeToCborValue(),
            );
        } catch (error) {
            throw new Error(
                `[Iso18013Bridge] document encoding failed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            );
        }

        try {
            codec.createDeviceAuthenticationBytes({
                sessionTranscript: normalizedSessionTranscript,
                docType: normalizedDocument.docType,
                deviceNamespaces: normalizedDocument.deviceSigned.nameSpaces,
            });
        } catch (error) {
            console.error(
                "[Iso18013Bridge] verifyPresentedDocument.deviceAuthenticationBytes failed",
                {
                    error,
                    docType: normalizedDocument.docType,
                    deviceNamespacesShape: describeCborShape(
                        normalizedDocument.deviceSigned.nameSpaces,
                    ),
                    deviceAuthShape: describeCborShape(
                        normalizedDocument.deviceSigned.deviceAuth,
                    ),
                },
            );
            throw new Error(
                `[Iso18013Bridge] deviceAuthenticationBytes failed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            );
        }

        try {
            const deviceAuth = normalizedDocument.deviceSigned.deviceAuth || {};
            if (Array.isArray(deviceAuth.deviceSignature)) {
                const coseSign1 = codec.parseCoseSign1(deviceAuth.deviceSignature);
                codec.buildCoseSign1SigStructure({
                    protectedBytes: coseSign1.protectedBytes,
                    payload: codec.createDeviceAuthenticationBytes({
                        sessionTranscript: normalizedSessionTranscript,
                        docType: normalizedDocument.docType,
                        deviceNamespaces: normalizedDocument.deviceSigned.nameSpaces,
                    }),
                });
            } else if (Array.isArray(deviceAuth.deviceMac)) {
                const coseMac0 = codec.parseCoseMac0(deviceAuth.deviceMac);
                codec.buildCoseMac0Structure({
                    protectedBytes: coseMac0.protectedBytes,
                    payload: codec.createDeviceAuthenticationBytes({
                        sessionTranscript: normalizedSessionTranscript,
                        docType: normalizedDocument.docType,
                        deviceNamespaces: normalizedDocument.deviceSigned.nameSpaces,
                    }),
                });
            } else {
                throw new Error("deviceAuth does not contain a COSE deviceSignature or deviceMac array");
            }
        } catch (error) {
            console.error(
                "[Iso18013Bridge] verifyPresentedDocument.deviceAuth preflight failed",
                {
                    error,
                    deviceAuthShape: describeCborShape(
                        normalizedDocument.deviceSigned.deviceAuth,
                    ),
                    deviceAuthValue: normalizedDocument.deviceSigned.deviceAuth,
                },
            );
            throw new Error(
                `[Iso18013Bridge] deviceAuth preflight failed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            );
        }
        try {
            return await security.verifyPresentedDocument({
                ...input,
                document: normalizedDocument,
                sessionTranscript: normalizedSessionTranscript,
            });
        } catch (error) {
            throw new Error(
                `[Iso18013Bridge] security.verifyPresentedDocument failed: ${
                    error instanceof Error ? error.message : String(error)
                }`,
            );
        }
    }

    async function verifyCoseSign1(input) {
        const { security } = requireLibraries();
        return security.verifyCoseSign1(input);
    }

    async function verifySignedStatusObject(input) {
        const { security } = requireLibraries();
        return security.verifySignedStatusObject(input);
    }

    window.Iso18013Bridge = {
        requireLibraries,
        mapToCoseKey,
        createAnnexATranscriptArtifacts,
        createSessionEstablishmentBytes,
        decodeCbor,
        normalizeCborValue,
        decodeMdocDocumentFromCborValue,
        decodeDeviceResponse,
        decodeDeviceResponseFromCborValue,
        decodeDeviceEngagement,
        decodeCoseKey,
        decodeSessionMessage,
        isSessionEstablishmentMessage,
        isSessionDataMessage,
        verifyPresentedDocument,
        verifyCoseSign1,
        verifySignedStatusObject,
    };
})();
