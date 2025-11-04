/*
  Copyright (c) 2025 Stelau
  Author: Nicolas Chalanset
  
  Request Builder module
  Builds device requests for mDL, EU PID, Age Verification, Photo ID, mICOV, and mVC
*/

(function () {
  // Resolve CBOR lazily at call time to avoid load-order races
  function getCBOR() {
    return window.CBOR || self.CBOR || self.cbor;
  }
  const log = window.log || console.log;

  async function buildRequestByType(requestTypes) {
    const CBOR = getCBOR();
    if (!CBOR) throw new Error("CBOR library not available");
    if (!requestTypes) {
      requestTypes = Array.from(
        document.querySelectorAll('input[name="requestType"]:checked')
      ).map((cb) => cb.value);
    }
    if (!Array.isArray(requestTypes)) requestTypes = [requestTypes];
    if (requestTypes.length === 0) requestTypes = ["full"];

    log("Building request for types: " + JSON.stringify(requestTypes));

    const deviceRequest = { version: "1.0", docRequests: [] };
    for (const requestType of requestTypes) {
      const docRequest = buildSingleDocRequest(requestType);
      if (docRequest) deviceRequest.docRequests.push(docRequest);
    }

    log(
      `→ Device Request with ${deviceRequest.docRequests.length} document(s)`
    );

    // Optionally add Reader Authentication per spec (inside each DocRequest)
    try {
      console.log("Checking Reader Authentication status...");
      const ra = window.ReaderAuth;
      console.log("ReaderAuth object:", ra);
      console.log(
        "ReaderAuth.isEnabled():",
        ra?.isEnabled ? ra.isEnabled() : undefined
      );
      console.log(
        "ReaderAuth.signReaderAuthentication:",
        !!(ra && typeof ra.signReaderAuthentication === "function")
      );
      if (ra && ra.isEnabled && ra.isEnabled()) {
        let addedCount = 0;
        for (const dr of deviceRequest.docRequests) {
          if (dr && dr.itemsRequest && dr.itemsRequest.tag === 24) {
            const itemsCbor = dr.itemsRequest.value; // raw ItemsRequest CBOR
            try {
              const cose = await ra.signReaderAuthentication(itemsCbor);
              dr.readerAuth = cose; // Per ISO 18013-5: readerAuth is inside DocRequest
              addedCount++;
            } catch (signErr) {
              console.warn(
                "ReaderAuth signing failed for a document:",
                signErr?.message || signErr
              );
            }
          }
        }
        if (addedCount > 0) {
          log(`🔏 Added Reader Authentication to ${addedCount} document(s)`);
        } else {
          log(
            "⚠️ ReaderAuth enabled but no itemsRequest found to sign in any DocRequest"
          );
        }
      }
    } catch (e) {
      console.warn("Reader Authentication processing failed:", e.message || e);
    }

    return CBOR.encode(deviceRequest);
  }

  function buildSingleDocRequest(requestType) {
    const CBOR = getCBOR();
    if (!CBOR) throw new Error("CBOR library not available");
    let docType, namespace, fields;
    // Optional multi-namespace holders for specific doctypes
    let photoIdFields = null; // org.iso.23220.photoID.1
    let photoIdDGFields = null; // org.iso.23220.datagroups.1
    let micovAttestationFields = null;

    if (requestType.startsWith("pid_")) {
      docType = "eu.europa.ec.eudi.pid.1";
      namespace = "eu.europa.ec.eudi.pid.1";
    } else if (requestType.startsWith("age_verify_")) {
      docType = "eu.europa.ec.av.1";
      namespace = "eu.europa.ec.av.1";
    } else if (requestType.startsWith("photoid_")) {
      docType = "org.iso.23220.photoID.1";
      // This document type uses multiple namespaces; 'namespace' is unused in multi-namespace branch
      namespace = "org.iso.23220.photoID.1";
      log(
        "📸 Building Photo ID request - docType: " +
          docType +
          " (multi-namespace)"
      );
    } else if (requestType.startsWith("micov_")) {
      docType = "org.micov.1";
      namespace = "org.micov.vtr.1";
      log(
        "💉 Building mICOV request - docType: " +
          docType +
          " namespace: " +
          namespace
      );
    } else if (requestType.startsWith("mvc_")) {
      docType = "org.iso.7367.1.mVC";
      namespace = "org.iso.7367.1";
      log(
        "🚗 Building mVC request - docType: " +
          docType +
          " namespace: " +
          namespace
      );
    } else {
      docType = "org.iso.18013.5.1.mDL";
      namespace = "org.iso.18013.5.1";
    }

    switch (requestType) {
      case "mdl_minimal":
        fields = {
          family_name: true,
          given_name: true,
        };
        break;
      case "mdl_basic":
        fields = {
          family_name: false,
          given_name: false,
          birth_date: false,
          portrait: false,
        };
        break;
      case "mdl_age":
        fields = { age_over_18: false, age_over_21: false, birth_date: false };
        break;
      case "mdl_driving":
        fields = {
          family_name: false,
          given_name: false,
          birth_date: false,
          driving_privileges: false,
          issue_date: false,
          expiry_date: false,
          document_number: false,
          portrait: false,
        };
        break;
      case "mdl_full":
        fields = {
          family_name: false,
          given_name: false,
          birth_date: false,
          age_over_18: false,
          age_over_21: false,
          issue_date: false,
          expiry_date: false,
          issuing_country: false,
          issuing_authority: false,
          document_number: false,
          driving_privileges: false,
          height: false,
          weight: false,
          eye_colour: false,
          hair_colour: false,
          sex: false,
          resident_address: false,
          resident_city: false,
          resident_state: false,
          resident_postal_code: false,
          resident_country: false,
          portrait: false,
          signature_usual_mark: false,
        };
        break;
      case "pid_minimal":
        fields = {
          family_name: true,
          given_name: true,
        };
        break;
      case "pid_basic":
        fields = {
          family_name: false,
          given_name: false,
          birth_date: false,
          portrait: false,
        };
        break;
      case "pid_age":
        fields = { age_over_18: false, age_over_21: false, birth_date: false };
        break;
      case "pid_full":
        fields = {
          family_name: false,
          given_name: false,
          birth_date: false,
          birth_place: false,
          nationality: false,
          resident_address: false,
          resident_country: false,
          resident_state: false,
          resident_city: false,
          resident_postal_code: false,
          resident_street: false,
          resident_house_number: false,
          personal_administrative_number: false,
          portrait: false,
          family_name_birth: false,
          given_name_birth: false,
          sex: false,
          email_address: false,
          mobile_phone_number: false,
          expiry_date: false,
          issuing_authority: false,
          issuing_country: false,
          document_number: false,
          issuing_jurisdiction: false,
          location_status: false,
          issuance_date: false,
          trust_anchor: false,
          // removed from PID rule book ARF >= 2.5.0
          age_over_18: false,
          age_over_21: false,
          age_in_years: false,
          age_birth_year: false,
        };
        break;
      case "age_verify_18":
        fields = { age_over_18: false };
        break;
      case "age_verify_21":
        fields = { age_over_18: false, age_over_21: false };
        break;
      case "age_verify_full":
        fields = {
          age_over_18: false,
          age_over_21: false,
          age_in_years: false,
          age_birth_year: false,
          birth_date: false,
          issuing_country: false,
          issuance_date: false,
          expiry_date: false,
        };
        break;
      case "photoid_full":
        // org.iso.23220.1
        fields = {
          family_name: false,
          given_name: false,
          birth_date: false,
          portrait: false,
          issue_date: false,
          expiry_date: false,
          issuing_authority: false,
          issuing_authority_unicode: false,
          issuing_country: false,
          age_over_18: false,
          age_in_years: false,
          age_birth_year: false,
          portrait_capture_date: false,
          birthplace: false,
          name_at_birth: false,
          resident_address: false,
          resident_city: false,
          resident_postal_code: false,
          resident_country: false,
          sex: false,
          nationality: false,
          document_number: false,
        };
        // org.iso.23220.photoID.1
        photoIdFields = {
          person_id: false,
          birth_country: false,
          birth_state: false,
          birth_city: false,
          administrative_number: false,
          resident_street: false,
          resident_house_number: false,
          travel_document_number: false,
        };
        //org.iso.23220.datagroups.1
        photoIdDGFields = {
          dg1: false,
          dg2: false,
          dg11: false,
          dg12: false,
          dg13: false,
          sod: false,
        };
        break;
      case "micov_full":
        fields = {
          fn: false,
          gn: false,
          dob: false,
          sex: false,
          pid_PPN: false,
          pid_DL: false,
          v_RA01_1: false,
          v_RA01_2: false,
        };
        micovAttestationFields = {
          "1D47_vaccinated": false,
          RA01_vaccinated: false,
          RA01_test: false,
          safeEntry_Leisure: false,
          fac: false,
          fni: false,
          gni: false,
          by: false,
          bm: false,
          bd: false,
        };
        break;
      case "mvc_full":
        fields = {
          registration_number: false,
          issue_date: false,
          expiry_date: false,
          issuing_country: false,
          issuing_authority_unicode: false,
          document_number: false,
          un_distinguishing_signs: false,
          date_of_registration: false,
          date_of_first_registration: false,
          vehicle_identification_number: false,
          basic_vehicle_info: false,
          mass_info: false,
          trailer_mass_info: false,
          engine_info: false,
          seating_info: false,
          registered_users: false,
        };
        break;
      default:
        console.warn("Unknown request type:", requestType);
        return null;
    }

    let nameSpacesObj;
    if (requestType.startsWith("micov_")) {
      nameSpacesObj = {
        "org.micov.vtr.1": fields,
        "org.micov.attestation.1": micovAttestationFields || {},
      };
    } else if (requestType.startsWith("photoid_")) {
      // Build multi-namespace request for ISO 23220 Photo ID (three namespaces)
      nameSpacesObj = {
        "org.iso.23220.1": fields || {},
        "org.iso.23220.photoID.1": photoIdFields || {},
        "org.iso.23220.datagroups.1": photoIdDGFields || {},
      };
    } else {
      nameSpacesObj = { [namespace]: fields };
    }

    const itemsRequest = {
      docType: docType,
      nameSpaces: nameSpacesObj,
      requestInfo: {},
    };

    // Capture the requested display order so the renderer can mirror it
    try {
      const namespaceOrder = Object.keys(nameSpacesObj);
      const fieldsOrder = {};
      for (const ns of namespaceOrder) {
        const obj = nameSpacesObj[ns];
        if (obj && typeof obj === "object" && !Array.isArray(obj)) {
          fieldsOrder[ns] = Object.keys(obj);
        } else {
          fieldsOrder[ns] = [];
        }
      }
      const orderSnapshot = { docType, namespaceOrder, fieldsOrder };
      // Expose for downstream renderers
      if (!window.RequestBuilder) window.RequestBuilder = {};
      window.RequestBuilder.lastOrder = orderSnapshot;
      window.LAST_REQUEST_ORDER = orderSnapshot; // convenience alias
      // Also keep a per-docType registry so multi-document requests are preserved
      try {
        if (!window.REQUEST_ORDERS_BY_DOCTYPE)
          window.REQUEST_ORDERS_BY_DOCTYPE = {};
        window.REQUEST_ORDERS_BY_DOCTYPE[docType] = orderSnapshot;
      } catch {}
    } catch (_) {}
    const itemsRequestCbor = CBOR.encode(itemsRequest);
    const taggedItemsRequest = new CBOR.Tagged(24, itemsRequestCbor);
    const docRequest = { itemsRequest: taggedItemsRequest };
    return docRequest;
  }

  window.RequestBuilder = {
    buildRequestByType,
    buildSingleDocRequest,
  };
  // Maintain backward-compatible globals
  window.buildRequestByType = buildRequestByType;
  window.buildSingleDocRequest = buildSingleDocRequest;
})();
