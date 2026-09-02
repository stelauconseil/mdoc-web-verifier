/*
  User-defined ISO 18013-5 credential profiles.

  Supported CDDL profile shape:
    profile-name = {
      displayName: "Human-readable name",
      docType: "example.doc.type.1",
      claims: {
        "example.namespace~mandatory_claim" => tstr,
        ? "example.namespace~optional_claim" => tstr,
      },
    }
*/

(function () {
    "use strict";

    const STORAGE_KEY = "mdoc_user_defined_credentials_v1";
    const REQUEST_PREFIX = "user_defined:";
    const MAX_DEFINITIONS = 25;
    const MAX_CDDL_LENGTH = 50000;
    const MAX_CLAIMS = 200;
    let editingId = null;

    function loadAll() {
        try {
            const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
            return Array.isArray(parsed) ? parsed : [];
        } catch {
            return [];
        }
    }

    function saveAll(definitions) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(definitions));
    }

    function makeId(docType) {
        const slug = docType
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "")
            .slice(0, 60);
        const suffix =
            typeof crypto !== "undefined" &&
            typeof crypto.randomUUID === "function"
                ? crypto.randomUUID().slice(0, 8)
                : Date.now().toString(36);
        return `${slug}-${suffix}`;
    }

    function parseCddl(cddl) {
        if (typeof cddl !== "string" || !cddl.trim()) {
            throw new Error("Paste a CDDL definition first");
        }
        if (cddl.length > MAX_CDDL_LENGTH) {
            throw new Error("The CDDL definition is too large");
        }

        const source = cddl.replace(/;[^\r\n]*/g, "");
        const ruleMatch = source.match(/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*\{/);
        const displayNameMatch = source.match(/\bdisplayName\s*:\s*"([^"]+)"\s*,?/);
        const docTypeMatch = source.match(/\bdocType\s*:\s*"([^"]+)"\s*,?/);
        const claimsStart = source.match(/\bclaims\s*:\s*\{/);

        if (!docTypeMatch) throw new Error('Missing docType: "…"');
        if (!claimsStart || claimsStart.index == null) {
            throw new Error("Missing claims map");
        }

        const docType = docTypeMatch[1].trim();
        if (!docType || docType.length > 150 || /[~\s]/.test(docType)) {
            throw new Error("Invalid docType");
        }

        const claimsBodyStart = claimsStart.index + claimsStart[0].length;
        let depth = 1;
        let inString = false;
        let escaped = false;
        let claimsBodyEnd = -1;
        for (let i = claimsBodyStart; i < source.length; i++) {
            const char = source[i];
            if (inString) {
                if (escaped) escaped = false;
                else if (char === "\\") escaped = true;
                else if (char === '"') inString = false;
                continue;
            }
            if (char === '"') inString = true;
            else if (char === "{") depth++;
            else if (char === "}" && --depth === 0) {
                claimsBodyEnd = i;
                break;
            }
        }
        if (claimsBodyEnd < 0) throw new Error("Unclosed claims map");

        const claimsBody = source.slice(claimsBodyStart, claimsBodyEnd);
        const memberPattern = /^\s*(\?)?\s*"([^"]+)"\s*=>\s*([A-Za-z][A-Za-z0-9_.-]*)\s*,?\s*$/gm;
        const claims = [];
        let memberMatch;
        while ((memberMatch = memberPattern.exec(claimsBody))) {
            const qualifiedName = memberMatch[2].trim();
            const separator = qualifiedName.indexOf("~");
            if (separator <= 0 || separator === qualifiedName.length - 1) {
                throw new Error(
                    `Claim key must use "namespace~identifier": ${qualifiedName}`,
                );
            }
            claims.push({
                namespace: qualifiedName.slice(0, separator),
                identifier: qualifiedName.slice(separator + 1),
                required: !memberMatch[1],
                format: memberMatch[3],
            });
        }

        const unparsed = claimsBody
            .replace(memberPattern, "")
            .replace(/[\s,]/g, "");
        if (unparsed) {
            throw new Error(`Unsupported CDDL near: ${unparsed.slice(0, 40)}`);
        }
        if (claims.length === 0) throw new Error("No claims found");
        if (claims.length > MAX_CLAIMS) throw new Error("Too many claims");

        const seen = new Set();
        for (const claim of claims) {
            const key = `${claim.namespace}~${claim.identifier}`;
            if (seen.has(key)) throw new Error(`Duplicate claim: ${key}`);
            seen.add(key);
        }

        return {
            name:
                (displayNameMatch && displayNameMatch[1].trim()) ||
                (ruleMatch && ruleMatch[1]) ||
                docType,
            docType,
            claims,
            cddl: cddl.trim(),
        };
    }

    function add(cddl, idToEdit = null) {
        const definition = parseCddl(cddl);
        const definitions = loadAll();
        const edited = idToEdit
            ? definitions.find((item) => item.id === idToEdit)
            : null;
        if (idToEdit && !edited) {
            throw new Error("The credential being edited no longer exists");
        }
        const duplicate = definitions.find(
            (item) =>
                item.docType === definition.docType && item.id !== idToEdit,
        );
        if (edited && duplicate) {
            throw new Error(
                `Another credential already uses docType ${definition.docType}`,
            );
        }
        let savedDefinition;
        if (edited) {
            Object.assign(edited, definition);
            savedDefinition = edited;
        } else if (duplicate) {
            Object.assign(duplicate, definition);
            savedDefinition = duplicate;
        } else {
            if (definitions.length >= MAX_DEFINITIONS) {
                throw new Error(`Maximum ${MAX_DEFINITIONS} credentials reached`);
            }
            definition.id = makeId(definition.docType);
            definitions.push(definition);
            savedDefinition = definition;
        }
        saveAll(definitions);
        renderList();
        return savedDefinition;
    }

    function remove(id) {
        saveAll(loadAll().filter((item) => item.id !== id));
        renderList();
    }

    function resolveRequestType(requestType) {
        if (!requestType || !requestType.startsWith(REQUEST_PREFIX)) return null;
        const value = requestType.slice(REQUEST_PREFIX.length);
        const modeMatch = value.match(/:(basic|full)$/);
        const mode = modeMatch ? modeMatch[1] : "full";
        const id = modeMatch ? value.slice(0, -modeMatch[0].length) : value;
        const definition = loadAll().find((item) => item.id === id) || null;
        return definition ? { definition, mode } : null;
    }

    function getByRequestType(requestType) {
        return resolveRequestType(requestType)?.definition || null;
    }

    function toNameSpaces(definition, mode = "full") {
        const nameSpaces = {};
        for (const claim of definition.claims) {
            if (mode === "basic" && !claim.required) continue;
            if (!nameSpaces[claim.namespace]) nameSpaces[claim.namespace] = {};
            nameSpaces[claim.namespace][claim.identifier] = false;
        }
        return nameSpaces;
    }

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function renderList() {
        const container = document.getElementById("userDefinedCredentialList");
        if (!container) return;
        const definitions = loadAll();
        if (definitions.length === 0) {
            container.innerHTML =
                '<div class="muted" style="font-size:0.85rem">No user-defined credential saved.</div>';
            return;
        }
        container.innerHTML = definitions
            .map(
                (definition) => `
                    <div class="user-credential-row">
                        <strong>${escapeHtml(definition.name)}</strong>
                        <label class="radio-chip small">
                            <input type="checkbox" name="requestType" value="${REQUEST_PREFIX}${escapeHtml(definition.id)}:basic" data-user-credential-mode-id="${escapeHtml(definition.id)}" />
                            Basic
                        </label>
                        <label class="radio-chip small">
                            <input type="checkbox" name="requestType" value="${REQUEST_PREFIX}${escapeHtml(definition.id)}:full" data-user-credential-mode-id="${escapeHtml(definition.id)}" />
                            Full
                        </label>
                        <span class="muted user-credential-doctype">${escapeHtml(definition.docType)}</span>
                        <button type="button" class="secondary user-credential-action" data-edit-user-credential-id="${escapeHtml(definition.id)}">Edit</button>
                        <button type="button" class="secondary user-credential-action" data-delete-user-credential-id="${escapeHtml(definition.id)}">Delete</button>
                    </div>`,
            )
            .join("");
    }

    function setStatus(message, isError) {
        const status = document.getElementById("userCredentialStatus");
        if (!status) return;
        status.textContent = message || "";
        status.style.color = isError ? "#b91c1c" : "#15803d";
    }

    function initializeUi() {
        const input = document.getElementById("userCredentialCddl");
        const addButton = document.getElementById("btnAddUserCredential");
        const cancelButton = document.getElementById("btnCancelUserCredentialEdit");
        const list = document.getElementById("userDefinedCredentialList");
        if (!input || !addButton || !list) return;

        renderList();
        const leaveEditMode = () => {
            editingId = null;
            addButton.textContent = "Add credential";
            if (cancelButton) cancelButton.style.display = "none";
        };
        addButton.addEventListener("click", () => {
            try {
                const wasEditing = Boolean(editingId);
                const definition = add(input.value, editingId);
                input.value = "";
                leaveEditMode();
                setStatus(
                    `${definition.name} ${wasEditing ? "updated" : "saved"} locally.`,
                    false,
                );
            } catch (error) {
                setStatus(error.message || String(error), true);
            }
        });
        cancelButton?.addEventListener("click", () => {
            input.value = "";
            leaveEditMode();
            setStatus("Editing cancelled.", false);
        });
        list.addEventListener("click", (event) => {
            const editButton = event.target.closest(
                "[data-edit-user-credential-id]",
            );
            if (editButton) {
                const definition = loadAll().find(
                    (item) => item.id === editButton.dataset.editUserCredentialId,
                );
                if (!definition) return;
                editingId = definition.id;
                input.value = definition.cddl;
                addButton.textContent = "Save changes";
                if (cancelButton) cancelButton.style.display = "inline-flex";
                input.focus();
                input.scrollIntoView({ behavior: "smooth", block: "center" });
                setStatus(`Editing ${definition.name}.`, false);
                return;
            }

            const deleteButton = event.target.closest(
                "[data-delete-user-credential-id]",
            );
            if (!deleteButton) return;
            const id = deleteButton.dataset.deleteUserCredentialId;
            remove(id);
            if (editingId === id) {
                input.value = "";
                leaveEditMode();
            }
            setStatus("Credential deleted from local storage.", false);
        });
        list.addEventListener("change", (event) => {
            const checkbox = event.target.closest(
                "input[data-user-credential-mode-id]",
            );
            if (!checkbox || !checkbox.checked) return;
            const id = checkbox.dataset.userCredentialModeId;
            for (const other of list.querySelectorAll(
                "input[data-user-credential-mode-id]",
            )) {
                if (
                    other !== checkbox &&
                    other.dataset.userCredentialModeId === id
                ) {
                    other.checked = false;
                }
            }
        });
    }

    window.UserDefinedCredentials = {
        REQUEST_PREFIX,
        parseCddl,
        loadAll,
        add,
        remove,
        resolveRequestType,
        getByRequestType,
        toNameSpaces,
        renderList,
    };

    initializeUi();
})();
