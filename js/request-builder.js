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
    return CBOR.encode(deviceRequest);
  }

  function buildSingleDocRequest(requestType) {
    const CBOR = getCBOR();
    if (!CBOR) throw new Error("CBOR library not available");
    let docType, namespace, fields;
    let micovAttestationFields = null;

    if (requestType.startsWith("pid_")) {
      docType = "eu.europa.ec.eudi.pid.1";
      namespace = "eu.europa.ec.eudi.pid.1";
    } else if (requestType.startsWith("age_verify_")) {
      docType = "eu.europa.ec.av.1";
      namespace = "eu.europa.ec.av.1";
    } else if (requestType.startsWith("photoid_")) {
      docType = "org.iso.23220.photoID.1";
      namespace = "org.iso.23220.1";
      log(
        "📸 Building Photo ID request - docType: " +
          docType +
          " namespace: " +
          namespace
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
      case "basic":
        fields = {
          family_name: true,
          given_name: true,
          birth_date: true,
          portrait: true,
        };
        break;
      case "age":
        fields = { age_over_18: true, age_over_21: true, birth_date: true };
        break;
      case "driving":
        fields = {
          family_name: true,
          given_name: true,
          birth_date: true,
          driving_privileges: true,
          issue_date: true,
          expiry_date: true,
          document_number: true,
          portrait: true,
        };
        break;
      case "full":
        fields = {
          family_name: true,
          given_name: true,
          birth_date: true,
          age_over_18: true,
          age_over_21: true,
          issue_date: true,
          expiry_date: true,
          issuing_country: true,
          issuing_authority: true,
          document_number: true,
          driving_privileges: true,
          height: true,
          weight: true,
          eye_colour: true,
          hair_colour: true,
          sex: true,
          resident_address: true,
          resident_city: true,
          resident_state: true,
          resident_postal_code: true,
          resident_country: true,
          portrait: true,
          signature_usual_mark: true,
        };
        break;
      case "pid_basic":
        fields = {
          family_name: true,
          given_name: true,
          birth_date: true,
          portrait: true,
        };
        break;
      case "pid_age":
        fields = { age_over_18: true, age_over_21: true, birth_date: true };
        break;
      case "pid_full":
        fields = {
          family_name: true,
          given_name: true,
          birth_date: true,
          birth_place: true,
          birth_country: true,
          birth_state: true,
          birth_city: true,
          resident_address: true,
          resident_country: true,
          resident_state: true,
          resident_city: true,
          resident_postal_code: true,
          resident_street: true,
          resident_house_number: true,
          gender: true,
          nationality: true,
          age_over_18: true,
          age_over_21: true,
          age_in_years: true,
          age_birth_year: true,
          family_name_birth: true,
          given_name_birth: true,
          portrait: true,
          issuing_authority: true,
          issuing_country: true,
          issuance_date: true,
          expiry_date: true,
          document_number: true,
        };
        break;
      case "age_verify_18":
        fields = { age_over_18: true };
        break;
      case "age_verify_21":
        fields = { age_over_18: true, age_over_21: true };
        break;
      case "age_verify_full":
        fields = {
          age_over_18: true,
          age_over_21: true,
          age_in_years: true,
          age_birth_year: true,
          birth_date: true,
          issuing_country: true,
          issuance_date: true,
          expiry_date: true,
        };
        break;
      case "photoid_full":
        fields = {
          given_name: true,
          family_name: true,
          birth_date: true,
          portrait: true,
          issuing_country: true,
          issuing_authority: true,
          document_number: true,
          issuance_date: true,
          expiry_date: true,
          sex: true,
          nationality: true,
          height: true,
          eye_colour: true,
          resident_address: true,
          resident_city: true,
          resident_postal_code: true,
          resident_country: true,
        };
        break;
      case "micov_full":
        fields = {
          fn: true,
          gn: true,
          dob: true,
          sex: true,
          pid_PPN: true,
          pid_DL: true,
          v_RA01_1: true,
          v_RA01_2: true,
        };
        micovAttestationFields = {
          "1D47_vaccinated": true,
          RA01_vaccinated: true,
          RA01_test: true,
          safeEntry_Leisure: true,
          fac: true,
          fni: true,
          gni: true,
          by: true,
          bm: true,
          bd: true,
        };
        break;
      case "mvc_full":
        fields = {
          registration_number: true,
          issue_date: true,
          expiry_date: true,
          issuing_country: true,
          issuing_authority_unicode: true,
          document_number: true,
          un_distinguishing_signs: true,
          date_of_registration: true,
          date_of_first_registration: true,
          vehicle_identification_number: true,
          basic_vehicle_info: true,
          mass_info: true,
          trailer_mass_info: true,
          engine_info: true,
          seating_info: true,
          registered_users: true,
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
    } else {
      nameSpacesObj = { [namespace]: fields };
    }

    const itemsRequest = {
      docType: docType,
      nameSpaces: nameSpacesObj,
      requestInfo: {},
    };
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
