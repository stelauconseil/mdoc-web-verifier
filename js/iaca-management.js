/*
  Copyright (c) 2025 Stelau
  Author: Nicolas Chalanset

  IACA Management module
  Extracted IACA storage and UI helpers
*/

(function () {
  // Storage keys
  const IACA_STORAGE_KEY = "mdoc_iaca_certificates";
  const IACA_VERSION_KEY = "mdoc_iaca_version";

  // Initialize IACA storage with defaults
  function initializeIACAs() {
    const storedVersion = parseInt(localStorage.getItem(IACA_VERSION_KEY)) || 0;
    let stored = localStorage.getItem(IACA_STORAGE_KEY);

    if (storedVersion < (window.APP_VERSION || 0)) {
      console.log(
        `Updating IACA certificates from version ${storedVersion} to ${window.APP_VERSION}`
      );
      let userAddedCerts = [];
      if (stored) {
        try {
          const existingIacas = JSON.parse(stored);
          userAddedCerts = existingIacas.filter((iaca) => {
            return !(
              Array.isArray(window.DEFAULT_IACA_CERTIFICATES) &&
              window.DEFAULT_IACA_CERTIFICATES.some(
                (defaultCert) => defaultCert.pem === iaca.pem
              )
            );
          });
          console.log(
            `Preserving ${userAddedCerts.length} user-added certificate(s)`
          );
        } catch (e) {
          console.error("Failed to parse stored IACAs during update:", e);
        }
      }
      const updatedIacas = [
        ...(window.DEFAULT_IACA_CERTIFICATES || []),
        ...userAddedCerts,
      ];
      localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(updatedIacas));
      localStorage.setItem(IACA_VERSION_KEY, String(window.APP_VERSION || 0));
      console.log(
        `IACA certificates updated: ${
          (window.DEFAULT_IACA_CERTIFICATES || []).length
        } default(s), ${userAddedCerts.length} user-added`
      );
      return updatedIacas;
    }

    if (!stored) {
      localStorage.setItem(
        IACA_STORAGE_KEY,
        JSON.stringify(window.DEFAULT_IACA_CERTIFICATES || [])
      );
      localStorage.setItem(IACA_VERSION_KEY, String(window.APP_VERSION || 0));
      return window.DEFAULT_IACA_CERTIFICATES || [];
    }

    try {
      const iacas = JSON.parse(stored);
      iacas.forEach((iaca) => {
        if (iaca.active === undefined) iaca.active = true;
      });
      return iacas;
    } catch (e) {
      console.error("Failed to parse stored IACAs, using defaults:", e);
      localStorage.setItem(
        IACA_STORAGE_KEY,
        JSON.stringify(window.DEFAULT_IACA_CERTIFICATES || [])
      );
      localStorage.setItem(IACA_VERSION_KEY, String(window.APP_VERSION || 0));
      return window.DEFAULT_IACA_CERTIFICATES || [];
    }
  }

  function getIACAs() {
    return initializeIACAs();
  }
  function getActiveIACAs() {
    return getIACAs().filter((iaca) => iaca.active !== false);
  }

  function parsePEMCertificate(pem) {
    try {
      const b64 = pem
        .replace(/-----BEGIN CERTIFICATE-----/, "")
        .replace(/-----END CERTIFICATE-----/, "")
        .replace(/\s+/g, "");
      const binaryString = atob(b64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++)
        bytes[i] = binaryString.charCodeAt(i);
      let subject = "Unknown";
      let subjectDN = null;
      try {
        const certInfo = window.extractCertInfo
          ? window.extractCertInfo(bytes)
          : null;
        if (certInfo && certInfo.subjectCN) subject = certInfo.subjectCN;
        if (certInfo && certInfo.subjectDN) subjectDN = certInfo.subjectDN;
      } catch (e) {
        console.warn("Could not extract subject CN, trying fallback method");
        const certStr = new TextDecoder("utf-8", { fatal: false }).decode(
          bytes
        );
        const cnMatch = certStr.match(/CN=([^,\n\r]+)/);
        if (cnMatch) subject = cnMatch[1].trim();
      }
      return { subject, subjectDN, bytes, pem };
    } catch (e) {
      console.error("Failed to parse PEM certificate:", e);
      return null;
    }
  }

  async function pemToCryptoKey(pem) {
    try {
      const b64 = pem
        .replace(/-----BEGIN CERTIFICATE-----/, "")
        .replace(/-----END CERTIFICATE-----/, "")
        .replace(/\s+/g, "");
      const binaryString = atob(b64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++)
        bytes[i] = binaryString.charCodeAt(i);
      const key = await window.extractPublicKeyFromCert(bytes);
      if (!key) {
        console.error("Failed to extract public key from IACA certificate");
        return null;
      }
      return key;
    } catch (e) {
      if (e.name === "DataError") {
        console.error(
          "IACA certificate is missing, invalid, or has an unsupported key format:",
          e.message
        );
      } else {
        console.error("Failed to import certificate as CryptoKey:", e.message);
      }
      return null;
    }
  }

  function addIACA(pem, name = null, isTest = false) {
    const certInfo = parsePEMCertificate(pem);
    if (!certInfo) throw new Error("Invalid PEM certificate format");
    const iacas = getIACAs();
    if (iacas.some((i) => i.pem === pem))
      throw new Error("This certificate is already installed");
    const newIACA = {
      name: name || certInfo.subject || "Unknown Certificate",
      pem: pem.trim(),
      issuer: certInfo.subject || "Unknown",
      addedAt: new Date().toISOString(),
      active: true,
      test: isTest,
    };
    iacas.push(newIACA);
    localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(iacas));
    return newIACA;
  }

  function removeIACA(index) {
    const iacas = getIACAs();
    if (index >= 0 && index < iacas.length) {
      const removed = iacas.splice(index, 1);
      localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(iacas));
      return removed[0];
    }
    return null;
  }

  function toggleIACAStatus(index) {
    const iacas = getIACAs();
    if (index >= 0 && index < iacas.length) {
      iacas[index].active = !iacas[index].active;
      localStorage.setItem(IACA_STORAGE_KEY, JSON.stringify(iacas));
      return iacas[index];
    }
    return null;
  }

  async function updateIACAList() {
    const iacaListEl = document.getElementById("iacaList");
    const iacas = getIACAs();
    if (!iacaListEl) return;

    if (iacas.length === 0) {
      iacaListEl.innerHTML =
        '<div class="muted" style="font-style: italic;">No certificates installed</div>';
      return;
    }

    let html = '<div style="display: grid; gap: 0.75rem;">';
    for (let index = 0; index < iacas.length; index++) {
      const iaca = iacas[index];
      const isDefault =
        Array.isArray(window.DEFAULT_IACA_CERTIFICATES) &&
        index < window.DEFAULT_IACA_CERTIFICATES.length;
      const isActive = iaca.active !== false;
      const isTest = iaca.test === true;
      const statusColor = isActive ? "#059669" : "#94a3b8";
      const statusText = isActive ? "● Active" : "○ Inactive";
      const bgOpacity = isActive ? "1" : "0.6";
      const testBadge = isTest
        ? '<div style="font-size: 0.8rem; color: #f59e0b; margin-top: 0.25rem; font-weight: 500;">⚠️ Test/Development Certificate</div>'
        : "";

      let certDetails = "";
      try {
        const certInfo = parsePEMCertificate(iaca.pem);
        if (certInfo) {
          const parsed = window.parseX509Certificate
            ? window.parseX509Certificate(certInfo.bytes)
            : null;
          const validity = window.extractCertValidity
            ? window.extractCertValidity(certInfo.bytes)
            : {};
          const sha256Hash = await crypto.subtle.digest(
            "SHA-256",
            certInfo.bytes
          );
          const hexThumbprint = Array.from(new Uint8Array(sha256Hash))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(":")
            .toUpperCase();
          const subjectDisplay = certInfo.subjectDN || iaca.issuer;

          let cryptoLabel = null;
          try {
            const pubKey = await window.extractPublicKeyFromCert(
              certInfo.bytes,
              true
            );
            if (pubKey && pubKey.nobleCurveName) {
              const map = {
                p256: "ECDSA P-256 (secp256r1)",
                p384: "ECDSA P-384 (secp384r1)",
                p521: "ECDSA P-521 (secp521r1)",
                brainpoolP256r1: "ECDSA brainpoolP256r1",
                brainpoolP320r1: "ECDSA brainpoolP320r1",
                brainpoolP384r1: "ECDSA brainpoolP384r1",
                brainpoolP512r1: "ECDSA brainpoolP512r1",
              };
              cryptoLabel =
                map[pubKey.nobleCurveName] ||
                `ECDSA (${pubKey.nobleCurveName})`;
            } else if (window.detectCurveFromCertOID) {
              const detected = window.detectCurveFromCertOID(certInfo.bytes);
              if (detected) {
                const map = {
                  "P-256": "ECDSA P-256 (secp256r1)",
                  "P-384": "ECDSA P-384 (secp384r1)",
                  "P-521": "ECDSA P-521 (secp521r1)",
                  brainpoolP256r1: "ECDSA brainpoolP256r1",
                  brainpoolP320r1: "ECDSA brainpoolP320r1",
                  brainpoolP384r1: "ECDSA brainpoolP384r1",
                  brainpoolP512r1: "ECDSA brainpoolP512r1",
                };
                cryptoLabel = map[detected] || `ECDSA (${detected})`;
              }
            }
          } catch {}
          const defaultBadge = isDefault
            ? '<div style="font-size: 0.8rem; color: #059669; margin: 0.25rem 0 0.5rem;">✓ Default certificate</div>'
            : "";

          certDetails = `
            <div id="iaca-details-${index}" style="display: none; margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid rgba(148,163,184,0.25);">
              <div style="font-size: 0.85rem; color: #475569;">
                ${defaultBadge}
                <div style="margin-bottom: 0.5rem;">
                  <strong>Subject:</strong>
                  <div style="color: #1e293b; font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.8rem; margin-top: 0.25rem; word-break: break-all; line-height: 1.4;">${
                    window.escapeHtml
                      ? window.escapeHtml(subjectDisplay)
                      : subjectDisplay
                  }</div>
                </div>
                ${
                  cryptoLabel
                    ? `<div style="margin-bottom: 0.5rem;"><strong>Crypto:</strong> <span style="color: #1e293b;">${cryptoLabel}</span></div>`
                    : ""
                }
                ${
                  validity.notBefore
                    ? `<div style="margin-bottom: 0.5rem;">
                  <strong>Valid From:</strong> <span style="color: #1e293b;">${validity.notBefore.toLocaleString()}</span>
                </div>`
                    : ""
                }
                ${
                  validity.notAfter
                    ? `<div style="margin-bottom: 0.5rem;">
                  <strong>Valid Until:</strong> <span style="color: #1e293b;">${validity.notAfter.toLocaleString()}</span>
                </div>`
                    : ""
                }
                <div style="margin-bottom: 0.5rem;">
                  <strong>SHA-256 Fingerprint:</strong> 
                  <div style="font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.75rem; color: #1e293b; margin-top: 0.25rem; word-break: break-all;">${hexThumbprint}</div>
                </div>
                <div style="margin-top: 0.75rem;">
                  <button onclick="viewIACAPEM(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #0ea5e9;">
                    📄 View PEM
                  </button>
                  <button onclick="copyIACAPEM(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #059669;">
                    📋 Copy PEM
                  </button>
                </div>
              </div>
            </div>
          `;
        }
      } catch (e) {
        console.error("Error parsing certificate details:", e);
      }

      html += `
        <div style="background: #f8fafc; border: 1px solid rgba(148,163,184,0.25); border-radius: 8px; padding: 0.75rem; opacity: ${bgOpacity};">
          <div style="display: flex; justify-content: space-between; align-items: start;">
            <div style="flex: 1;">
              <div style="display: flex; align-items: center; gap: 0.5rem;">
                <div style="font-weight: 600; color: #0f172a;">${
                  window.escapeHtml ? window.escapeHtml(iaca.name) : iaca.name
                }</div>
                <div style="font-size: 0.8rem; color: ${statusColor}; font-weight: 500;">${statusText}</div>
              </div>
              <div style="font-size: 0.85rem; color: #64748b; margin-top: 0.25rem;">${
                window.escapeHtml ? window.escapeHtml(iaca.issuer) : iaca.issuer
              }</div>
              ${testBadge}
            </div>
            <div style="display: flex; gap: 0.5rem; align-items: center;">
              ${
                certDetails
                  ? `<button onclick="toggleIACADetails(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #64748b; display: inline-flex; align-items: center; gap: 0.35rem;">
                <span id="iaca-details-icon-${index}">▶</span> Details
              </button>`
                  : ""
              }
              <button onclick="toggleIACACert(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: ${
        isActive ? "#64748b" : "#059669"
      };">
                ${isActive ? "Deactivate" : "Activate"}
              </button>
              ${
                !isDefault
                  ? `<button onclick="removeIACACert(${index})" style="padding: 0.35rem 0.65rem; font-size: 0.85rem; background: #dc2626;">Remove</button>`
                  : ""
              }
            </div>
          </div>
          ${certDetails}
        </div>
      `;
    }
    html += "</div>";
    iacaListEl.innerHTML = html;
  }

  // Global handlers used by HTML
  window.toggleIACACert = function (index) {
    const toggled = toggleIACAStatus(index);
    if (toggled) {
      const status = toggled.active ? "activated" : "deactivated";
      (window.log || console.log)(
        `${toggled.active ? "✅" : "⏸️"} ${
          status.charAt(0).toUpperCase() + status.slice(1)
        } IACA: ${toggled.name}`
      );
      updateIACAList();
    }
  };
  window.removeIACACert = function (index) {
    if (confirm("Are you sure you want to remove this certificate?")) {
      const removed = removeIACA(index);
      if (removed) {
        (window.log || console.log)(`🗑️ Removed IACA: ${removed.name}`);
        updateIACAList();
      }
    }
  };
  window.toggleIACADetails = function (index) {
    const detailsDiv = document.getElementById(`iaca-details-${index}`);
    const icon = document.getElementById(`iaca-details-icon-${index}`);
    if (!detailsDiv || !icon) return;
    if (detailsDiv.style.display === "none") {
      detailsDiv.style.display = "block";
      icon.textContent = "▼";
    } else {
      detailsDiv.style.display = "none";
      icon.textContent = "▶";
    }
  };
  window.viewIACAPEM = function (index) {
    const iacas = getIACAs();
    if (index >= 0 && index < iacas.length) {
      const iaca = iacas[index];
      const modal = document.createElement("div");
      modal.style.cssText =
        "position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; display: flex; align-items: center; justify-content: center; padding: 2rem;";
      modal.onclick = (e) => {
        if (e.target === modal) modal.remove();
      };
      const content = document.createElement("div");
      content.style.cssText =
        "background: white; border-radius: 12px; padding: 1.5rem; max-width: 800px; max-height: 80vh; overflow: auto; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.3);";
      content.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <h3 style="margin: 0; color: #0f172a;">${
            window.escapeHtml ? window.escapeHtml(iaca.name) : iaca.name
          }</h3>
          <button onclick="this.closest('div').parentElement.parentElement.remove()" style="background: #dc2626; padding: 0.5rem 1rem; border-radius: 6px; border: none; color: white; cursor: pointer;">Close</button>
        </div>
        <pre style="background: #f8fafc; padding: 1rem; border-radius: 8px; overflow-x: auto; font-family: 'SFMono-Regular','JetBrains Mono',ui-monospace,monospace; font-size: 0.85rem; color: #1e293b; white-space: pre-wrap; word-break: break-all;">${
          window.escapeHtml ? window.escapeHtml(iaca.pem) : iaca.pem
        }</pre>
        <div style="margin-top: 1rem;">
          <button onclick="copyIACAPEM(${index}); this.textContent='✅ Copied!'; setTimeout(() => this.textContent='📋 Copy to Clipboard', 2000);" style="background: #059669; padding: 0.5rem 1rem; border-radius: 6px; border: none; color: white; cursor: pointer;">📋 Copy to Clipboard</button>
        </div>
      `;
      modal.appendChild(content);
      document.body.appendChild(modal);
    }
  };
  window.copyIACAPEM = async function (index) {
    const iacas = getIACAs();
    if (index >= 0 && index < iacas.length) {
      try {
        await navigator.clipboard.writeText(iacas[index].pem);
        (window.log || console.log)(
          `📋 Copied IACA PEM to clipboard: ${iacas[index].name}`
        );
      } catch (err) {
        console.error("Copy failed:", err);
        (window.log || console.log)("❌ Failed to copy PEM: " + err.message);
      }
    }
  };

  // Expose public API if needed
  window.IacaManager = {
    initializeIACAs,
    getIACAs,
    getActiveIACAs,
    addIACA,
    removeIACA,
    toggleIACAStatus,
    parsePEMCertificate,
    pemToCryptoKey,
    updateIACAList,
  };
})();
