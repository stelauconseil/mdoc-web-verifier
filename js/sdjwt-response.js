/*
  SD-JWT Response Helpers
  - Detect and extract SD-JWT compact serialization strings from a DeviceResponse per proposed shape
*/

(function () {
  function extractSdJwtStrings(deviceResponse) {
    if (!deviceResponse || typeof deviceResponse !== "object") return [];
    const val =
      deviceResponse.sdjwtDocuments || deviceResponse["sdjwtDocuments"];
    if (!val) return [];
    if (Array.isArray(val)) {
      // Expect array of tstr, but be defensive
      return val
        .map((v) => (typeof v === "string" ? v : String(v)))
        .filter(Boolean);
    }
    // Some implementers may wrap as Map or object with numeric keys; try to coerce
    if (val instanceof Map) return Array.from(val.values()).map(String);
    if (typeof val === "object") return Object.values(val).map(String);
    return [];
  }

  // Small pretty preview: returns an array of { index, length, header } where header decodes the first JWT header base64url
  function previewSdJwt(sdjwt) {
    const parts = String(sdjwt).split(".");
    if (parts.length < 2) return { length: sdjwt.length, header: null };
    try {
      const b64 = parts[0].replace(/-/g, "+").replace(/_/g, "/");
      const pad = b64.length % 4 === 2 ? "==" : b64.length % 4 === 3 ? "=" : "";
      const json = atob(b64 + pad);
      return { length: sdjwt.length, header: JSON.parse(json) };
    } catch {
      return { length: sdjwt.length, header: null };
    }
  }

  // Convenience: apply extraction to a DeviceResponse JSON (already decoded)
  function extractFromDeviceResponse(deviceResponse) {
    const list = extractSdJwtStrings(deviceResponse);
    return list.map((token, i) => ({
      index: i,
      token,
      preview: previewSdJwt(token),
    }));
  }

  window.SDJWTResponse = {
    extractSdJwtStrings,
    extractFromDeviceResponse,
    previewSdJwt,
  };
})();
