/*
  SD-JWT Experiment Helpers
  - Build extended ItemsRequest snippets for SD-JWT based on current discussion
  - Non-invasive: standalone, can be used from sdjwt-lab.html or integrated later
*/

(function () {
  const enc = new TextEncoder();

  function toDotPath(input) {
    if (Array.isArray(input)) return input.map(String).join(".");
    return String(input || "").trim();
  }

  // Normalize claim selections per discussion:
  // - Accept arrays like ["address","street_address"] -> "address.street_address"
  // - Accept predicates like ["age_over_or_equals","18"] -> "age_over_or_equals.18"
  // - Accept already-joined strings
  function normalizeClaims(claimSelections) {
    if (!claimSelections) return [];
    const out = [];
    for (const sel of claimSelections) {
      const s = toDotPath(sel);
      if (s) out.push(s);
    }
    return out;
  }

  // Build an SD-JWT extended request snippet to be merged into a DeviceRequest
  // options: { vcts: string[], claimSelections: (string[]|string)[], intentToRetain?: boolean }
  function buildExtendedItemsRequest(options = {}) {
    const vcts = Array.isArray(options.vcts) ? options.vcts.map(String) : [];
    const claims = normalizeClaims(options.claimSelections);
    const intent = options.intentToRetain === true;

    // Proposed structure (details TBD): attach under an "sdjwt" extension block
    const sdjwt = {
      vct: vcts, // array of VCT strings
      claims: claims, // array of dot-path strings
      intent_to_retain: intent,
    };

    return { sdjwt };
  }

  // Merge the SD-JWT snippet into a DeviceRequest skeleton using 18013-5 2nd edition extended request shape
  // This DOES NOT sign or wrap in COSE. It only builds the JSON/JS structure that can later be CBOR-encoded.
  function mergeIntoDeviceRequest(baseRequest, sdjwtExt) {
    const req = JSON.parse(JSON.stringify(baseRequest || {}));
    // Place under a generic extension bucket to avoid colliding with existing 18013-5 fields
    if (!req.extensions) req.extensions = {};
    req.extensions.sdjwt =
      sdjwtExt && sdjwtExt.sdjwt ? sdjwtExt.sdjwt : sdjwtExt;
    return req;
  }

  // Build a minimal DeviceRequest example combining a classic docRequest and an SD-JWT request extension
  function buildSampleDeviceRequest(opts = {}) {
    const sdjwt = buildExtendedItemsRequest({
      vcts: opts.vcts || ["eu.europa.ec.eudiw.pid.1", "org.iso.18013.5.mDL"],
      claimSelections: opts.claimSelections || [
        ["age_over_or_equals", "18"],
        ["address", "street_address"],
      ],
      intentToRetain: !!opts.intentToRetain,
    });

    const base = {
      version: "1.0",
      docRequests: [
        // Keep an ordinary itemsRequest example (optional); RPs can choose either path client-side
        {
          itemsRequest: {
            docType: "org.iso.18013.5.1.mDL",
            nameSpaces: {
              "org.iso.18013.5.1": {
                family_name: true,
                given_name: true,
                age_over_18: true,
              },
            },
          },
        },
      ],
    };

    return mergeIntoDeviceRequest(base, sdjwt);
  }

  // Encode to CBOR bytes (if global CBOR is present)
  function toCBOR(struct) {
    const CBOR = self.CBOR || self.cbor || window.CBOR;
    if (!CBOR || typeof CBOR.encode !== "function")
      throw new Error("CBOR library not available");
    return CBOR.encode(struct);
  }

  window.SDJWT = {
    buildExtendedItemsRequest,
    mergeIntoDeviceRequest,
    buildSampleDeviceRequest,
    toCBOR,
  };
})();
