(function () {
    if (window.CBOR && window.cbor) {
        return;
    }

    const codec = window.Iso18013Codec;
    if (!codec) {
        throw new Error(
            "Iso18013Codec must be loaded before the CBOR shim.",
        );
    }

    class Tagged {
        constructor(tag, value) {
            this.tag = tag;
            this.value = value;
        }
    }

    function isPlainObject(value) {
        if (value === null || typeof value !== "object") {
            return false;
        }
        const prototype = Object.getPrototypeOf(value);
        return prototype === Object.prototype || prototype === null;
    }

    function toCodecValue(value) {
        if (value instanceof Tagged) {
            return new codec.Tag(value.tag, toCodecValue(value.value));
        }
        if (
            value &&
            typeof value === "object" &&
            typeof value.tag === "number" &&
            "value" in value &&
            !(value instanceof codec.Tag)
        ) {
            return new codec.Tag(value.tag, toCodecValue(value.value));
        }
        if (value instanceof codec.Tag) {
            return new codec.Tag(value.tag, toCodecValue(value.contents));
        }
        if (Array.isArray(value)) {
            return value.map(toCodecValue);
        }
        if (value instanceof Map) {
            return new Map(
                Array.from(value.entries()).map(([key, entryValue]) => [
                    toCodecValue(key),
                    toCodecValue(entryValue),
                ]),
            );
        }
        if (value instanceof ArrayBuffer) {
            return new Uint8Array(value);
        }
        if (ArrayBuffer.isView(value) && !(value instanceof DataView)) {
            return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (
            value &&
            typeof value === "object" &&
            value.type === "Buffer" &&
            Array.isArray(value.data)
        ) {
            return new Uint8Array(value.data);
        }
        if (isPlainObject(value)) {
            return Object.fromEntries(
                Object.entries(value).map(([key, entryValue]) => [key, toCodecValue(entryValue)]),
            );
        }
        return value;
    }

    function fromCodecValue(value) {
        if (value instanceof codec.Tag) {
            return new Tagged(value.tag, fromCodecValue(value.contents));
        }
        if (Array.isArray(value)) {
            return value.map(fromCodecValue);
        }
        if (value instanceof Map) {
            return new Map(
                Array.from(value.entries()).map(([key, entryValue]) => [
                    fromCodecValue(key),
                    fromCodecValue(entryValue),
                ]),
            );
        }
        if (isPlainObject(value)) {
            return Object.fromEntries(
                Object.entries(value).map(([key, entryValue]) => [key, fromCodecValue(entryValue)]),
            );
        }
        return value;
    }

    const CBOR = {
        Tagged,
        decode(input) {
            let bytes;
            if (input instanceof Uint8Array) {
                bytes = input;
            } else if (input instanceof ArrayBuffer) {
                bytes = new Uint8Array(input);
            } else if (ArrayBuffer.isView(input) && !(input instanceof DataView)) {
                bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
            } else if (Array.isArray(input)) {
                bytes = new Uint8Array(input);
            } else {
                throw new Error("CBOR.decode expects Uint8Array-compatible input");
            }
            return fromCodecValue(codec.decodeCbor(bytes));
        },
        encode(value) {
            return codec.encodeCbor(toCodecValue(value));
        },
    };

    window.CBOR = CBOR;
    window.cbor = CBOR;
})();
