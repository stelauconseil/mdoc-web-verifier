/*
  Copyright (c) 2025 Stelau
  Author: Nicolas Chalanset

  Wallet Response module: AES-GCM decrypt helpers and rendering
*/

(function () {
  const enc = new TextEncoder();
  function hex(buf) {
    return [...new Uint8Array(buf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  }
  function getCBOR() {
    return window.CBOR || self.CBOR || self.cbor;
  }
  const log = window.log || console.log;

  // JSON conversion helper used by response rendering and debug views
  function convertToJSON(obj) {
    if (obj === null || obj === undefined) return obj;
    // Represent raw bytes in a friendlier structure with base64
    if (obj instanceof Uint8Array) {
      const bin = Array.from(obj);
      let b64 = "";
      try {
        b64 = btoa(String.fromCharCode(...bin));
      } catch (_) {
        // Fallback for very large arrays (unlikely here): chunked encoding
        let s = "";
        for (let i = 0; i < obj.length; i += 0x8000) {
          s += String.fromCharCode.apply(null, obj.subarray(i, i + 0x8000));
        }
        b64 = btoa(s);
      }
      return { _type: "bytes", _length: obj.length, _base64: b64 };
    }
    if (ArrayBuffer.isView(obj)) return Array.from(obj);
    if (obj instanceof ArrayBuffer) return Array.from(new Uint8Array(obj));
    if (Array.isArray(obj)) return obj.map((item) => convertToJSON(item));
    if (obj instanceof Map) {
      const out = {};
      for (const [k, v] of obj.entries()) out[k] = convertToJSON(v);
      return out;
    }
    if (obj instanceof Set) return Array.from(obj).map((v) => convertToJSON(v));
    if (obj instanceof Date) return obj.toISOString();
    if (typeof obj === "object") {
      const res = {};
      for (const [k, v] of Object.entries(obj)) res[k] = convertToJSON(v);
      return res;
    }
    return obj;
  }

  // Helper: Format field names to be more readable
  function formatFieldName(fieldName) {
    return String(fieldName)
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  // AES-GCM decryption
  async function aesGcmDecrypt(ciphertextWithTag, keyBytes, iv, aad) {
    // Normalize keyBytes into a BufferSource
    let k = keyBytes;
    if (k && !(k instanceof Uint8Array) && !(k instanceof ArrayBuffer)) {
      if (Array.isArray(k)) k = new Uint8Array(k);
      else if (k?.buffer && typeof k.length === "number") k = new Uint8Array(k);
    }
    if (!k) throw new Error("SKDevice key not set");
    const key = await crypto.subtle.importKey(
      "raw",
      k,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const aadBytes =
      typeof aad === "string" ? enc.encode(aad) : new Uint8Array(aad || 0);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aadBytes, tagLength: 128 },
      key,
      ciphertextWithTag
    );
    return new Uint8Array(decrypted);
  }

  // Display DeviceResponse in a nice format
  function displayDeviceResponse(deviceResponse) {
    const CBOR = getCBOR();
    const responseSectionEl = document.getElementById("responseSection");
    const responseDisplayEl = document.getElementById("responseDisplay");
    const escapeHtml = window.escapeHtml || ((t) => t);
    const createJp2DownloadLink =
      window.createJp2DownloadLink ||
      (() => "<em>JP2 download not available</em>");
    const postTasks = [];

    // Show the response section
    responseSectionEl.style.display = "block";
    setTimeout(() => {
      responseSectionEl.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);

    const getField = (obj, key) =>
      obj instanceof Map ? obj.get(key) : obj?.[key];
    const version = getField(deviceResponse, "version") || "1.0";
    const documents = getField(deviceResponse, "documents");

    if (!documents || !Array.isArray(documents) || documents.length === 0) {
      responseDisplayEl.innerHTML = `
        <div class="response-header">
          <h3>🎉 Response Received</h3>
          <div class="response-meta">Version: ${version}</div>
        </div>
        <div class="no-data">No documents found in response</div>
      `;
      return;
    }

    let html = `
      <div class="response-header">
        <h3>🎉 Response Received</h3>
        <div class="response-meta">Version: ${version} • ${documents.length} document(s)</div>
        <button id="btnCopyResponse" class="copy-btn" style="margin-top: 10px; padding: 8px 16px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">
          📋 Copy as JSON
        </button>
      </div>
    `;

    documents.forEach((doc, docIndex) => {
      const docType = getField(doc, "docType") || "Unknown";
      html += `
        <div class="document-card">
          <div class="document-type">📄 ${escapeHtml(docType)}</div>
      `;

      const issuerSigned = getField(doc, "issuerSigned");
      if (!issuerSigned) {
        html += '<div class="no-data">No issuerSigned data</div></div>';
        return;
      }

      const nameSpaces = getField(issuerSigned, "nameSpaces");
      if (!nameSpaces) {
        html += '<div class="no-data">No nameSpaces data</div></div>';
        return;
      }

      const nsEntries =
        nameSpaces instanceof Map
          ? Array.from(nameSpaces.entries())
          : Object.entries(nameSpaces);
      nsEntries.forEach(([nsName, nsItems]) => {
        html += `
          <div class="namespace-section">
            <div class="namespace-title">📦 ${escapeHtml(nsName)}</div>
        `;
        if (!Array.isArray(nsItems) || nsItems.length === 0) {
          html += '<div class="no-data">No items in namespace</div></div>';
          return;
        }

        nsItems.forEach((item, itemIndex) => {
          try {
            let issuerSignedItem = item;
            if (item instanceof CBOR.Tagged && item.tag === 24) {
              const itemBytes = new Uint8Array(item.value);
              issuerSignedItem = CBOR.decode(itemBytes);
            }
            const elementIdentifier = getField(
              issuerSignedItem,
              "elementIdentifier"
            );
            const elementValue = getField(issuerSignedItem, "elementValue");
            if (elementIdentifier && elementValue !== undefined) {
              let valueHtml;
              let rawValue = elementValue;
              if (elementValue instanceof CBOR.Tagged) {
                if (elementValue.tag === 1004) {
                  const dateStr = elementValue.value;
                  try {
                    const date = new Date(dateStr);
                    const formatted = date.toLocaleDateString("en-US", {
                      year: "numeric",
                      month: "long",
                      day: "numeric",
                    });
                    valueHtml = `<div class="data-value">📅 ${formatted} <span class="binary" style="font-size:0.85em">(${dateStr})</span></div>`;
                    rawValue = dateStr;
                  } catch (_) {
                    valueHtml = `<div class="data-value">${escapeHtml(
                      String(elementValue.value)
                    )}</div>`;
                    rawValue = elementValue.value;
                  }
                } else if (elementValue.tag === 0) {
                  valueHtml = `<div class="data-value">🕐 ${escapeHtml(
                    elementValue.value
                  )}</div>`;
                  rawValue = elementValue.value;
                } else if (elementValue.tag === 1) {
                  const date = new Date(elementValue.value * 1000);
                  valueHtml = `<div class="data-value">🕐 ${date.toLocaleString()}</div>`;
                  rawValue = elementValue.value;
                } else {
                  valueHtml = `<div class="data-value">Tag(${
                    elementValue.tag
                  }): ${escapeHtml(String(elementValue.value))}</div>`;
                  rawValue = elementValue.value;
                }
              } else if (
                elementValue instanceof Uint8Array ||
                ArrayBuffer.isView(elementValue)
              ) {
                const byteLength = elementValue.length;
                if (
                  byteLength === 0 &&
                  (String(elementIdentifier)
                    .toLowerCase()
                    .includes("portrait") ||
                    String(elementIdentifier).toLowerCase().includes("image") ||
                    String(elementIdentifier).toLowerCase().includes("photo") ||
                    String(elementIdentifier)
                      .toLowerCase()
                      .includes("signature_usual_mark"))
                )
                  return;
                if (
                  String(elementIdentifier)
                    .toLowerCase()
                    .includes("portrait") ||
                  String(elementIdentifier).toLowerCase().includes("image") ||
                  String(elementIdentifier).toLowerCase().includes("photo") ||
                  String(elementIdentifier)
                    .toLowerCase()
                    .includes("signature_usual_mark")
                ) {
                  let mimeType = "application/octet-stream";
                  let formatLabel = "Unknown";
                  if (elementValue.length >= 2) {
                    if (
                      elementValue[0] === 0xff &&
                      elementValue[1] === 0xd8 &&
                      elementValue[2] === 0xff
                    ) {
                      mimeType = "image/jpeg";
                      formatLabel = "JPEG";
                    } else if (
                      elementValue.length >= 12 &&
                      elementValue[0] === 0x00 &&
                      elementValue[1] === 0x00 &&
                      elementValue[2] === 0x00 &&
                      elementValue[3] === 0x0c &&
                      elementValue[4] === 0x6a &&
                      elementValue[5] === 0x50 &&
                      elementValue[6] === 0x20 &&
                      elementValue[7] === 0x20 &&
                      elementValue[8] === 0x0d &&
                      elementValue[9] === 0x0a &&
                      elementValue[10] === 0x87 &&
                      elementValue[11] === 0x0a
                    ) {
                      mimeType = "image/jp2";
                      formatLabel = "JPEG2000";
                    } else if (
                      elementValue[0] === 0xff &&
                      elementValue[1] === 0x4f &&
                      elementValue.length >= 4 &&
                      elementValue[2] === 0xff &&
                      elementValue[3] === 0x51
                    ) {
                      mimeType = "image/jp2";
                      formatLabel = "JPEG2000";
                    }
                  }
                  try {
                    if (mimeType === "image/jp2") {
                      const portraitId = `portrait-${Date.now()}-${Math.random()
                        .toString(36)
                        .substr(2, 9)}`;
                      valueHtml = `
                        <div class="data-value portrait-preview">
                          ${createJp2DownloadLink(elementValue, portraitId)}
                          <span class="binary" style="margin-top: 0.5rem;">${byteLength.toLocaleString()} bytes (${formatLabel})</span>
                        </div>
                      `;
                    } else {
                      const base64 = btoa(String.fromCharCode(...elementValue));
                      const dataUri = `data:${mimeType};base64,${base64}`;
                      valueHtml = `
                        <div class="data-value portrait-preview">
                          <img src="${dataUri}" alt="Portrait" class="portrait-thumbnail" />
                          <span class="binary">${byteLength.toLocaleString()} bytes (${formatLabel})</span>
                        </div>
                      `;
                    }
                  } catch (_) {
                    valueHtml = `<div class="data-value binary">&lt;binary data, ${byteLength.toLocaleString()} bytes&gt;</div>`;
                  }
                } else {
                  valueHtml = `<div class="data-value binary">&lt;binary data, ${byteLength.toLocaleString()} bytes&gt;</div>`;
                }
              } else if (elementValue instanceof Date) {
                valueHtml = `<div class="data-value">${
                  elementValue.toISOString().split("T")[0]
                }</div>`;
              } else if (Array.isArray(elementValue)) {
                valueHtml = `<div class="data-value"><pre style="margin:0;font-size:0.85em">${escapeHtml(
                  JSON.stringify(elementValue, null, 2)
                )}</pre></div>`;
              } else if (
                typeof elementValue === "object" &&
                elementValue !== null
              ) {
                valueHtml = `<div class="data-value"><pre style="margin:0;font-size:0.85em">${escapeHtml(
                  JSON.stringify(elementValue, null, 2)
                )}</pre></div>`;
              } else if (typeof elementValue === "boolean") {
                valueHtml = `<div class="data-value">${
                  elementValue ? "✓ Yes" : "✗ No"
                }</div>`;
              } else {
                valueHtml = `<div class="data-value">${escapeHtml(
                  String(elementValue)
                )}</div>`;
              }
              html += `
                <div class="data-item">
                  <div class="data-label">${escapeHtml(
                    formatFieldName(elementIdentifier)
                  )}</div>
                  ${valueHtml}
                </div>
              `;
            }
          } catch (itemError) {
            html += `
              <div class="data-item">
                <div class="data-label">Item ${itemIndex + 1}</div>
                <div class="data-value binary">(parse error: ${escapeHtml(
                  itemError.message
                )})</div>
              </div>
            `;
          }
        });
        html += "</div>";
      });

      const issuerAuth = getField(issuerSigned, "issuerAuth");
      if (issuerAuth) {
        html += `
          <div class="signer-section" style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #007bff;">
            <div style="display:flex; justify-content:space-between; align-items:center; gap: 8px;">
              <div style="font-weight: bold; color: #007bff;">🔐 Issuer Signature Information</div>
              <button 
                onclick="toggleMSO('issuerDetails-${docIndex}')" 
                style="
                  background: #e2e8f0;
                  color: #0f172a;
                  border: 1px solid #cbd5e1;
                  padding: 4px 10px;
                  border-radius: 6px;
                  cursor: pointer;
                  font-size: 0.85rem;
                  font-weight: 600;
                  display: inline-flex;
                  align-items: center;
                  gap: 6px;
                "
                onmouseover="this.style.background='#cbd5e1'"
                onmouseout="this.style.background='#e2e8f0'"
              >
                <span id="issuerDetails-${docIndex}-icon">▶</span>
                <span>Details</span>
              </button>
            </div>

            <div class="verification-section" style="margin-top: 12px; padding: 12px; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0;">
              <div style="font-weight: 600; margin-bottom: 8px; color: #0f172a;">✍️ Verification Status</div>
              <div class="data-item">
                <div class="data-label">Signature</div>
                <div class="data-value" id="sigStatus-${docIndex}">… verifying</div>
              </div>
              <div class="data-item">
                <div class="data-label">Chain</div>
                <div class="data-value" id="chainStatus-${docIndex}">… validating</div>
              </div>
            </div>

            <div id="issuerDetails-${docIndex}" style="display:none; margin-top: 10px;">
        `;
        try {
          let coseSign1 = issuerAuth;
          if (issuerAuth instanceof CBOR.Tagged && issuerAuth.tag === 24) {
            const coseBytes = new Uint8Array(issuerAuth.value);
            coseSign1 = CBOR.decode(coseBytes);
          }
          if (Array.isArray(coseSign1) && coseSign1.length >= 4) {
            const [protectedHeader, unprotectedHeader, payload, signature] =
              coseSign1;

            // -- MSO FIRST --
            html += `
              <div style="font-weight: 600; margin: 10px 0 8px; color:#0f172a;">📦 MSO (Mobile Security Object)</div>
            `;
            let mso = null;
            try {
              if (payload) {
                const payloadBytes =
                  payload instanceof Uint8Array
                    ? payload
                    : new Uint8Array(payload);
                mso = CBOR.decode(payloadBytes);
                if (mso instanceof CBOR.Tagged && mso.tag === 24) {
                  try {
                    const inner = new Uint8Array(mso.value);
                    mso = CBOR.decode(inner);
                  } catch (_) {}
                }
                const getField = (obj, key) =>
                  obj instanceof Map ? obj.get(key) : obj?.[key];
                const msoDocType = getField(mso, "docType");
                if (msoDocType) {
                  html += `
                    <div class="data-item">
                      <div class="data-label">MSO DocType</div>
                      <div class="data-value">${escapeHtml(
                        String(msoDocType)
                      )}</div>
                    </div>
                  `;
                }
                const validityInfo = getField(mso, "validityInfo");
                if (validityInfo) {
                  const vf = getField(validityInfo, "validFrom");
                  const vu = getField(validityInfo, "validUntil");
                  const signedAt = getField(validityInfo, "signed");
                  const formatDate = (v, withTime = false) => {
                    try {
                      let val = v;
                      if (v instanceof CBOR.Tagged) {
                        if (v.tag === 0) val = v.value; // RFC 3339
                        else if (v.tag === 1)
                          val = new Date(v.value * 1000).toISOString();
                      }
                      const d = new Date(val);
                      return withTime
                        ? d.toLocaleString()
                        : d.toLocaleDateString();
                    } catch {
                      return String(v);
                    }
                  };
                  if (signedAt) {
                    html += `
                      <div class="data-item">
                        <div class="data-label">📅 Signed</div>
                        <div class="data-value">${escapeHtml(
                          formatDate(signedAt, true)
                        )}</div>
                      </div>
                    `;
                  }
                  if (vf) {
                    html += `
                      <div class="data-item">
                        <div class="data-label">Valid From</div>
                        <div class="data-value">${escapeHtml(
                          formatDate(vf)
                        )}</div>
                      </div>
                    `;
                  }
                  if (vu) {
                    const vuStr = formatDate(vu);
                    const isExpired = (() => {
                      try {
                        let val = vu;
                        if (vu instanceof CBOR.Tagged) {
                          if (vu.tag === 0) val = vu.value;
                          else if (vu.tag === 1)
                            val = new Date(vu.value * 1000).toISOString();
                        }
                        return new Date(val) < new Date();
                      } catch {
                        return false;
                      }
                    })();
                    html += `
                      <div class="data-item">
                        <div class="data-label">Valid Until</div>
                        <div class="data-value" style="${
                          isExpired ? "color:#dc2626;font-weight:600;" : ""
                        }">${isExpired ? "⚠️ " : ""}${escapeHtml(vuStr)}</div>
                      </div>
                    `;
                  }
                }
                const digestAlgorithm = getField(mso, "digestAlgorithm");
                if (digestAlgorithm) {
                  html += `
                    <div class="data-item">
                      <div class="data-label">Digest Algorithm</div>
                      <div class="data-value">${escapeHtml(
                        String(digestAlgorithm)
                      )}</div>
                    </div>
                  `;
                }
              }
            } catch (_) {}

            // MSO structure viewer
            {
              const msoId = `mso-${docIndex}`;
              let src = mso || issuerSigned;
              let msoStr = "{}";
              try {
                msoStr = JSON.stringify(convertToJSON(src), null, 2);
              } catch (_) {}
              const msoStrEsc = escapeHtml(msoStr);
              html += `
                <div style="margin-top: 1rem; border-top: 1px solid #e2e8f0; padding-top: 1rem;">
                  <button onclick="toggleMSO('${msoId}')" style="background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; font-size: 0.9rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; width: 100%; justify-content: center; transition: background 0.2s ease;" onmouseover="this.style.background='#e2e8f0'" onmouseout="this.style.background='#f1f5f9'">
                    <span id="${msoId}-icon">▶</span>
                    <span>View Complete MSO Structure</span>
                  </button>
                  <div id="${msoId}" style="display: none; margin-top: 0.75rem; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; max-height: 400px; overflow-y: auto;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                      <span style="font-size: 0.85rem; color: #64748b; font-weight: 600;">Complete MSO (JSON)</span>
                      <button onclick="copyMSO('${msoId}-content')" style="background: #059669; color: white; border: none; padding: 0.35rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 600;">📋 Copy</button>
                    </div>
                    <pre id="${msoId}-content" style="margin: 0; font-family: 'SFMono-Regular', 'JetBrains Mono', ui-monospace, monospace; font-size: 0.85rem; line-height: 1.5; color: #0f172a; white-space: pre-wrap; word-break: break-word;">${msoStrEsc}</pre>
                  </div>
                </div>
              `;
            }

            // -- DOCUMENT SIGNER AFTER MSO --
            html += `<div style="font-weight: 600; margin: 14px 0 8px; color:#0f172a; border-top: 1px dashed #cbd5e1; padding-top: 10px;">🧾 Document signer</div>`;

            let protectedData = {};
            if (protectedHeader && protectedHeader.length > 0) {
              try {
                const protectedHeaderCopy = new Uint8Array(protectedHeader);
                const decoded = CBOR.decode(protectedHeaderCopy);
                protectedData =
                  decoded instanceof Map
                    ? Object.fromEntries(decoded)
                    : decoded;
              } catch (_) {}
            }
            let headerAlgLabel = "Unknown";
            const alg =
              protectedData[1] ||
              (unprotectedHeader instanceof Map
                ? unprotectedHeader.get(1)
                : unprotectedHeader?.[1]);
            if (alg === -7) headerAlgLabel = "ES256 (ECDSA with SHA-256)";
            else if (alg === -35) headerAlgLabel = "ES384 (ECDSA with SHA-384)";
            else if (alg === -36) headerAlgLabel = "ES512 (ECDSA with SHA-512)";
            else if (alg === -8) headerAlgLabel = "EdDSA";
            else if (alg != null) headerAlgLabel = `Algorithm ${alg}`;
            const sigAlgId = `sig-alg-${docIndex}`;
            html += `
              <div class=\"data-item\">\n                <div class=\"data-label\">Signature Algorithm</div>\n                <div class=\"data-value\" id=\"${sigAlgId}\">${escapeHtml(
              headerAlgLabel
            )}</div>\n              </div>
            `;
            const _issuerCertRaw =
              unprotectedHeader instanceof Map
                ? unprotectedHeader.get(33)
                : unprotectedHeader?.[33];
            let issuerCertFirst = null;
            if (_issuerCertRaw) {
              issuerCertFirst = Array.isArray(_issuerCertRaw)
                ? _issuerCertRaw[0]
                : _issuerCertRaw;
            }
            if (issuerCertFirst) {
              setTimeout(async () => {
                try {
                  const el = document.getElementById(sigAlgId);
                  if (!el) return;
                  const pub = await window.extractPublicKeyFromCert(
                    issuerCertFirst,
                    true
                  );
                  let curveName = (pub?.nobleCurveName || "").toLowerCase();
                  let effectiveAlgLabel = headerAlgLabel;
                  let curveLabel = "";
                  if (!curveName) {
                    const label =
                      window.detectCurveFromCertOID(issuerCertFirst);
                    curveLabel = label || "";
                    curveName = (label || "").toLowerCase();
                  }
                  if (
                    curveName.includes("p256") ||
                    curveName.includes("brainpoolp256")
                  ) {
                    effectiveAlgLabel = "ES256 (ECDSA with SHA-256)";
                    curveLabel = curveName.includes("brainpool")
                      ? "brainpoolP256r1"
                      : "P-256";
                  } else if (
                    curveName.includes("p384") ||
                    curveName.includes("brainpoolp384") ||
                    curveName.includes("brainpoolp320")
                  ) {
                    effectiveAlgLabel = "ES384 (ECDSA with SHA-384)";
                    if (curveName.includes("brainpoolp320"))
                      curveLabel = "brainpoolP320r1";
                    else if (curveName.includes("brainpool"))
                      curveLabel = "brainpoolP384r1";
                    else curveLabel = "P-384";
                  } else if (
                    curveName.includes("p521") ||
                    curveName.includes("brainpoolp512")
                  ) {
                    effectiveAlgLabel = "ES512 (ECDSA with SHA-512)";
                    curveLabel = curveName.includes("brainpool")
                      ? "brainpoolP512r1"
                      : "P-521";
                  } else if (
                    curveName.includes("ed25519") ||
                    curveName.includes("ed448")
                  ) {
                    effectiveAlgLabel = "EdDSA";
                    curveLabel = curveName.includes("ed448")
                      ? "Ed448"
                      : "Ed25519";
                  }
                  const curveSuffix = curveLabel
                    ? ` <span style=\"color:#475569;\">— Curve: ${curveLabel}</span>`
                    : "";
                  if (effectiveAlgLabel !== headerAlgLabel) {
                    el.innerHTML = `${effectiveAlgLabel}${curveSuffix} <span style=\"color:#64748b;\">(header: ${escapeHtml(
                      headerAlgLabel
                    )})</span>`;
                  } else {
                    el.innerHTML = `${effectiveAlgLabel}${curveSuffix}`;
                  }
                } catch (_) {}
              }, 0);
            }
            const issuerCert =
              unprotectedHeader instanceof Map
                ? unprotectedHeader.get(33)
                : unprotectedHeader?.[33];
            if (issuerCert) {
              try {
                const certDer =
                  issuerCertFirst &&
                  (issuerCertFirst instanceof Uint8Array ||
                    ArrayBuffer.isView(issuerCertFirst))
                    ? issuerCertFirst
                    : issuerCert instanceof Uint8Array ||
                      ArrayBuffer.isView(issuerCert)
                    ? issuerCert
                    : null;
                if (certDer) {
                  const certInfo = window.extractCertInfo
                    ? window.extractCertInfo(certDer)
                    : {};
                  if (certInfo.subjectDN) {
                    html += `
                      <div class="data-item">
                        <div class="data-label">Subject</div>
                        <div class="data-value" style="font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.85rem;">${escapeHtml(
                          certInfo.subjectDN
                        )}</div>
                      </div>
                    `;
                  } else if (certInfo.subjectCN) {
                    html += `
                      <div class="data-item">
                        <div class="data-label">Subject CN</div>
                        <div class="data-value">${escapeHtml(
                          certInfo.subjectCN
                        )}</div>
                      </div>
                    `;
                  }
                  if (certInfo.issuerDN) {
                    html += `
                      <div class="data-item">
                        <div class="data-label">Issuer</div>
                        <div class="data-value" style="font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.85rem;">${escapeHtml(
                          certInfo.issuerDN
                        )}</div>
                      </div>
                    `;
                  } else if (certInfo.issuerCN) {
                    html += `
                      <div class="data-item">
                        <div class="data-label">Issuer CN</div>
                        <div class="data-value">${escapeHtml(
                          certInfo.issuerCN
                        )}</div>
                      </div>
                    `;
                  }
                  try {
                    const validity = window.extractCertValidity
                      ? window.extractCertValidity(certDer)
                      : null;
                    if (validity) {
                      const nf = validity.notBefore
                        ? new Date(validity.notBefore)
                        : null;
                      const na = validity.notAfter
                        ? new Date(validity.notAfter)
                        : null;
                      if (nf) {
                        html += `
                          <div class="data-item">
                            <div class="data-label">Valid From</div>
                            <div class="data-value">${escapeHtml(
                              nf.toLocaleString()
                            )}</div>
                          </div>
                        `;
                      }
                      if (na) {
                        const expired = na < new Date();
                        html += `
                          <div class="data-item">
                            <div class="data-label">Valid Until</div>
                            <div class="data-value" style="${
                              expired ? "color:#dc2626;font-weight:600;" : ""
                            }">${expired ? "⚠️ " : ""}${escapeHtml(
                          na.toLocaleString()
                        )}</div>
                          </div>
                        `;
                      }
                    }
                  } catch (_) {}
                }
              } catch (_) {}
            }

            // Close details container
            html += `</div>`;

            // Queue post-render tasks for this document (verification only)
            postTasks.push({ docIndex, coseSign1 });
          } else {
            html += `<div class="data-value">⚠️ Unexpected COSE_Sign1 structure</div>`;
          }
        } catch (sigError) {
          html += `
            <div class="data-item">
              <div class="data-value" style="color: #dc3545;">❌ Error parsing signature: ${escapeHtml(
                sigError.message
              )}</div>
            </div>
          `;
        }
        html += "</div>";
      } else {
        html += `
          <div class="signer-section" style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;">
            <div style="color: #856404;">⚠️ No issuer signature found (issuerAuth missing)</div>
          </div>
        `;
      }
      html += "</div>";
    });

    responseDisplayEl.innerHTML = html;

    setTimeout(() => {
      const btnCopy = document.getElementById("btnCopyResponse");
      if (btnCopy) {
        btnCopy.addEventListener("click", async () => {
          try {
            const jsonData = convertToJSON(deviceResponse);
            const jsonString = JSON.stringify(jsonData, null, 2);
            await navigator.clipboard.writeText(jsonString);
            const originalText = btnCopy.textContent;
            btnCopy.textContent = "✅ Copied!";
            btnCopy.style.background = "#218838";
            setTimeout(() => {
              btnCopy.textContent = originalText;
              btnCopy.style.background = "#28a745";
            }, 2000);
            log("📋 Response copied to clipboard as JSON");
          } catch (err) {
            log("❌ Failed to copy: " + err.message);
          }
        });
      }
      // Execute post-render tasks per document: run verification
      (async () => {
        for (const task of postTasks) {
          try {
            // Run signature + chain verification (using global helper)
            if (
              typeof window.verifyCOSESign1SignatureWithChain === "function"
            ) {
              try {
                const res = await window.verifyCOSESign1SignatureWithChain(
                  task.coseSign1
                );
                const sigEl = document.getElementById(
                  `sigStatus-${task.docIndex}`
                );
                const chainEl = document.getElementById(
                  `chainStatus-${task.docIndex}`
                );
                if (sigEl) {
                  sigEl.textContent = res.signatureValid
                    ? "✅ Valid"
                    : "❌ Invalid";
                  sigEl.style.color = res.signatureValid
                    ? "#16a34a"
                    : "#dc2626";
                }
                if (chainEl) {
                  if (res.chainValid) {
                    const iaca = res.chainInfo?.matchedIACA;
                    const label = iaca
                      ? `✅ Valid — IACA: ${iaca.name}${
                          iaca.test ? " (TEST)" : ""
                        }`
                      : "✅ Valid";
                    chainEl.textContent = label;
                    chainEl.style.color = "#16a34a";
                  } else {
                    chainEl.textContent = "❌ Invalid";
                    chainEl.style.color = "#dc2626";
                  }
                }
              } catch (e) {
                log("❌ Verification error: " + e.message);
              }
            }
          } catch (_) {}
        }
      })();
    }, 100);

    log("✅ Response decrypted and displayed successfully!");

    setTimeout(async () => {
      try {
        const device = window.device;
        const chState = window.chState;
        const writeState = window.writeState;
        if (device?.gatt?.connected && chState) {
          try {
            log("🔚 Sending END state (0x02) to wallet...");
            await writeState(0x02);
            log("✅ END state sent");
            setTimeout(() => {
              if (device?.gatt?.connected) {
                log("🔌 Closing BLE connection...");
                device.gatt.disconnect();
                log("✅ Connection closed - ready for next scan");
              }
            }, 500);
          } catch (stateError) {
            if (device?.gatt?.connected) device.gatt.disconnect();
            log("✅ Connection closed - ready for next scan");
          }
        } else {
          log("✅ Wallet disconnected - ready for next scan");
        }
      } catch (_) {
        log("✅ Session ended - ready for next scan");
      }
    }, 1000);
  }

  // Decrypt and display mDL response (COSE_Encrypt0)
  async function decryptAndDisplayResponse(encryptedData) {
    const CBOR = getCBOR();
    const coseEnc0 = CBOR.decode(encryptedData);
    if (!Array.isArray(coseEnc0) || coseEnc0.length !== 3)
      throw new Error(
        "Invalid COSE_Encrypt0 structure - expected 3-element array"
      );
    const [protectedHeaderBytes, unprotectedHeader, ciphertext] = coseEnc0;
    let protectedHeader = {};
    if (protectedHeaderBytes && protectedHeaderBytes.length > 0)
      protectedHeader = CBOR.decode(protectedHeaderBytes);
    const iv =
      unprotectedHeader instanceof Map
        ? unprotectedHeader.get(5)
        : unprotectedHeader[5];
    if (!iv) throw new Error("No IV found in unprotected header");
    const plaintext = await aesGcmDecrypt(
      new Uint8Array(ciphertext),
      window.skDevice ? new Uint8Array(window.skDevice) : null,
      new Uint8Array(iv),
      ""
    );
    const deviceResponse = CBOR.decode(plaintext);
    displayDeviceResponse(deviceResponse);
  }

  // Decrypt SessionEstablishment response data field (raw AES-GCM)
  async function decryptSessionEstablishmentData(encryptedData) {
    const mdocIdentifier = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]);
    const counter = 1;
    const iv = new Uint8Array(12);
    iv.set(mdocIdentifier, 0);
    new DataView(iv.buffer, 8, 4).setUint32(0, counter, false);
    const skd = window.skDevice ? new Uint8Array(window.skDevice) : null;
    if (!skd) throw new Error("SKDevice key not set");
    const key = await crypto.subtle.importKey(
      "raw",
      skd,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new Uint8Array(0),
        tagLength: 128,
      },
      key,
      encryptedData
    );
    const plaintext = new Uint8Array(decrypted);
    const deviceResponse = getCBOR().decode(plaintext);
    displayDeviceResponse(deviceResponse);
  }

  window.WalletResponse = {
    aesGcmDecrypt,
    decryptSessionEstablishmentData,
    decryptAndDisplayResponse,
    displayDeviceResponse,
    convertToJSON,
  };

  // Global helpers for MSO classic UI
  window.toggleMSO = function (id) {
    try {
      const section = document.getElementById(id);
      const icon = document.getElementById(`${id}-icon`);
      if (!section) return;
      const isHidden =
        section.style.display === "" || section.style.display === "none";
      if (isHidden) {
        section.style.display = "block";
        if (icon) icon.textContent = "▼";
      } else {
        section.style.display = "none";
        if (icon) icon.textContent = "▶";
      }
    } catch (_) {}
  };

  window.copyMSO = async function (contentId) {
    try {
      const pre = document.getElementById(contentId);
      if (!pre) return;
      const text = pre.textContent || pre.innerText || "";
      await navigator.clipboard.writeText(text);
      // Optional visual feedback on the button if available via event
      const evt = window.event;
      const btn = evt && evt.currentTarget ? evt.currentTarget : null;
      if (btn) {
        const original = btn.textContent;
        btn.textContent = "✅ Copied";
        btn.style.background = "#047857";
        setTimeout(() => {
          btn.textContent = original;
          btn.style.background = "#059669";
        }, 1200);
      }
    } catch (e) {
      (window.log || console.log)("❌ Copy failed: " + e.message);
    }
  };
})();
