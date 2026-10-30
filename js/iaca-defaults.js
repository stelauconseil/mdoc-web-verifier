/*
  Copyright (c) 2026 Stelau
  Author: Nicolas Chalanset

  Default IACA trust anchors, shared by index.html and the Visitor Desk app.
*/
window.DEFAULT_IACA_CERTIFICATES = [
                    {
                        name: "Autorité de Certification France Identité IACA",
                        pem: `-----BEGIN CERTIFICATE-----
    MIIDHTCCAsSgAwIBAgISESEhmoph1P1OOjDCLJAgGdBbMAoGCCqGSM49BAMCMIGf
    MQswCQYDVQQGEwJGUjEwMC4GA1UECgwnQWdlbmNlIE5hdGlvbmFsZSBkZXMgVGl0
    cmVzIFPDqWN1cmlzw6lzMRcwFQYDVQQLDA4wMDAyIDEzMDAwMzI2MjE5MDcGA1UE
    AwwwQXV0b3JpdMOpIGRlIENlcnRpZmljYXRpb24gRnJhbmNlIElkZW50aXTDqSBJ
    QUNBMQowCAYDVQQFEwExMB4XDTI1MTAxNzAwMDAwMFoXDTM0MTAxNzAwMDAwMFow
    gZ8xCzAJBgNVBAYTAkZSMTAwLgYDVQQKDCdBZ2VuY2UgTmF0aW9uYWxlIGRlcyBU
    aXRyZXMgU8OpY3VyaXPDqXMxFzAVBgNVBAsMDjAwMDIgMTMwMDAzMjYyMTkwNwYD
    VQQDDDBBdXRvcml0w6kgZGUgQ2VydGlmaWNhdGlvbiBGcmFuY2UgSWRlbnRpdMOp
    IElBQ0ExCjAIBgNVBAUTATEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqfRW/
    7OTJS4K0IPMa/c8UicIUq62jTccQtGnHAYk6UnvXyRO3PC4/2pdq5QjhwIKwJVqC
    FOr4fbGboMKLX+L/o4HdMIHaMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
    AQH/AgEAMCwGA1UdEgQlMCOBIWZyYW5jZS1pZGVudGl0ZUBpbnRlcmlldXIuZ291
    di5mcjBGBgNVHR8EPzA9MDugOaA3hjVodHRwOi8vY3JsLmFudHMuZ291di5mci9h
    Y19mcmFuY2VfaWRlbnRpdGVfaWFjYV8xLmNybDAdBgNVHQ4EFgQUAQ1+Rjq9mU0k
    AyKKyTwFdgjmwA4wHwYDVR0jBBgwFoAUAQ1+Rjq9mU0kAyKKyTwFdgjmwA4wCgYI
    KoZIzj0EAwIDRwAwRAIgSNKCT8z4zaZLfdOd/rHevKYDbvjqylK723wjd4g4s0EC
    IDnoWVWyJHwlO31z3QmK7QapM00sOCJnsTIvEGi1Fz/I
    -----END CERTIFICATE-----`,
                        issuer: "CN=Autorité de Certification France Identité IACA, C=FR",
                        test: false,
                        active: true,
                    },
                    {
                        name: "Autorité de Certification France Attestations IACA",
                        pem: `-----BEGIN CERTIFICATE-----
    MIIDLTCCAtKgAwIBAgISESEFJUbpBJovlg7lg3Eb5YTCMAoGCCqGSM49BAMCMIGi
    MQswCQYDVQQGEwJGUjEwMC4GA1UECgwnQWdlbmNlIE5hdGlvbmFsZSBkZXMgVGl0
    cmVzIFPDqWN1cmlzw6lzMRcwFQYDVQQLDA4wMDAyIDEzMDAwMzI2MjE8MDoGA1UE
    AwwzQXV0b3JpdMOpIGRlIENlcnRpZmljYXRpb24gRnJhbmNlIEF0dGVzdGF0aW9u
    cyBJQUNBMQowCAYDVQQFEwExMB4XDTI1MTAxNzAwMDAwMFoXDTM0MTAxNzAwMDAw
    MFowgaIxCzAJBgNVBAYTAkZSMTAwLgYDVQQKDCdBZ2VuY2UgTmF0aW9uYWxlIGRl
    cyBUaXRyZXMgU8OpY3VyaXPDqXMxFzAVBgNVBAsMDjAwMDIgMTMwMDAzMjYyMTww
    OgYDVQQDDDNBdXRvcml0w6kgZGUgQ2VydGlmaWNhdGlvbiBGcmFuY2UgQXR0ZXN0
    YXRpb25zIElBQ0ExCjAIBgNVBAUTATEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
    AASa4ZI0w4Mn4FW6kYdKPUlYYgVbwFf1A6lBDnurRsoPJxM3+dVupbkGl9O+QnJ3
    6wc8ngoXE3oH1hP11flDmWsIo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMB
    Af8ECDAGAQH/AgEAMDAGA1UdEgQpMCeBJWZyYW5jZS1hdHRlc3RhdGlvbnNAaW50
    ZXJpZXVyLmdvdXYuZnIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5hbnRz
    LmdvdXYuZnIvYWNfZnJhbmNlX2F0dGVzdGF0aW9uc19pYWNhXzEuY3JsMB0GA1Ud
    DgQWBBT/dscZoX+tou0+F2dDsFrTPfsMpzAfBgNVHSMEGDAWgBT/dscZoX+tou0+
    F2dDsFrTPfsMpzAKBggqhkjOPQQDAgNJADBGAiEAmMD8Kpgnctmx12gCBYrj98kn
    oKDSPlO5SucThy1EEqwCIQDsYM80Ere4Yw0fHNJQQHl6D1rAITDV3qFKP62Uq7xt
    sQ==
    -----END CERTIFICATE-----`,
                        issuer: "CN=Autorité de Certification France Attestations IACA, C=FR",
                        test: false,
                        active: true,
                    },
                    {
                        name: "Autorité de Certification France Identité IACA",
                        pem: `-----BEGIN CERTIFICATE-----
    MIIDdjCCAxugAwIBAgISESHseuWkt7eIRNVD2TUo+Bu2MAoGCCqGSM49BAMCMIHH
    MQswCQYDVQQGEwJGUjEwMC4GA1UECgwnQWdlbmNlIE5hdGlvbmFsZSBkZXMgVGl0
    cmVzIFPDqWN1cmlzw6lzMRcwFQYDVQQLDA4wMDAyIDEzMDAwMzI2MjEmMCQGA1UE
    CwwdUE9VUiBRVUFMSUZJQ0FUSU9OIFVOSVFVRU1FTlQxOTA3BgNVBAMMMEF1dG9y
    aXTDqSBkZSBDZXJ0aWZpY2F0aW9uIEZyYW5jZSBJZGVudGl0w6kgSUFDQTEKMAgG
    A1UEBRMBMTAeFw0yNTAxMjkwMDAwMDBaFw0zNDAxMjkwMDAwMDBaMIHHMQswCQYD
    VQQGEwJGUjEwMC4GA1UECgwnQWdlbmNlIE5hdGlvbmFsZSBkZXMgVGl0cmVzIFPD
    qWN1cmlzw6lzMRcwFQYDVQQLDA4wMDAyIDEzMDAwMzI2MjEmMCQGA1UECwwdUE9V
    UiBRVUFMSUZJQ0FUSU9OIFVOSVFVRU1FTlQxOTA3BgNVBAMMMEF1dG9yaXTDqSBk
    ZSBDZXJ0aWZpY2F0aW9uIEZyYW5jZSBJZGVudGl0w6kgSUFDQTEKMAgGA1UEBRMB
    MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEWDSW7a1G6Ebbydwncvqx1JXjcL
    p0Uk/OKc5IWXEJCiejLWd3brmKVIrnJNi3GtLPOsokA7Y8I0XJpqQrROvYSjgeQw
    geEwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwLAYDVR0SBCUw
    I4EhZnJhbmNlLWlkZW50aXRlQGludGVyaWV1ci5nb3V2LmZyME0GA1UdHwRGMEQw
    QqBAoD6GPGh0dHA6Ly9jcmwucXVhbGlmLmFudHMuZ291di5mci9hY19mcmFuY2Vf
    aWRlbnRpdGVfaWFjYV8xLmNybDAdBgNVHQ4EFgQU6qGsPka6CBXTy3qGlF/2yRr2
    8aUwHwYDVR0jBBgwFoAU6qGsPka6CBXTy3qGlF/2yRr28aUwCgYIKoZIzj0EAwID
    SQAwRgIhAIWippsk9geJFGe/WInhC6IQpWgBfscynyMb4B2fKcbXAiEA9CFvazbn
    ATTWeV9JY4z4xiazYY5QeBH8Ug8RmFU0zVM=
    -----END CERTIFICATE-----`,
                        issuer: "CN=Autorité de Certification France Identité IACA, C=FR",
                        test: true,
                        active: true,
                    },
                    {
                        name: "France Attestations - Test IACA",
                        pem: `-----BEGIN CERTIFICATE-----
    MIIDUzCCAvmgAwIBAgISESHtNjf+2KAQ0ttWtR9EhAAPMAoGCCqGSM49BAMCMIHF
    MQswCQYDVQQGEwJGUjEwMC4GA1UECgwnQWdlbmNlIE5hdGlvbmFsZSBkZXMgVGl0
    cmVzIFPDqWN1cmlzw6lzMRcwFQYDVQQLDA4wMDAyIDEzMDAwMzI2MjEmMCQGA1UE
    CwwdUE9VUiBRVUFMSUZJQ0FUSU9OIFVOSVFVRU1FTlQxNzA1BgNVBAMMLkF1dG9y
    aXTDqSBkZSBDZXJ0aWZpY2F0aW9uIEZyYW5jZSBBdHRlc3RhdGlvbnMxCjAIBgNV
    BAUTATEwHhcNMjUwMTI5MDAwMDAwWhcNMzAwMTI5MDAwMDAwWjCBxTELMAkGA1UE
    BhMCRlIxMDAuBgNVBAoMJ0FnZW5jZSBOYXRpb25hbGUgZGVzIFRpdHJlcyBTw6lj
    dXJpc8OpczEXMBUGA1UECwwOMDAwMiAxMzAwMDMyNjIxJjAkBgNVBAsMHVBPVVIg
    UVVBTElGSUNBVElPTiBVTklRVUVNRU5UMTcwNQYDVQQDDC5BdXRvcml0w6kgZGUg
    Q2VydGlmaWNhdGlvbiBGcmFuY2UgQXR0ZXN0YXRpb25zMQowCAYDVQQFEwExMFkw
    EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoCYCM9LYS8zUk8I1xL2B2G9voa4yFsko
    qohrsEQkpNEeKb59J3VDHausTqFWCOfwEGUzi6yocLIbE+gfz59pnaOBxjCBwzAO
    BgNVHQ8BAf8EBAMCAQYwMAYDVR0SBCkwJ4ElZnJhbmNlLWF0dGVzdGF0aW9uc0Bp
    bnRlcmlldXIuZ291di5mcjASBgNVHRMBAf8ECDAGAQH/AgEAMEwGA1UdHwRFMEMw
    QaA/oD2GO2h0dHA6Ly9jcmwucXVhbGlmLmFudHMuZ291di5mci9hY19mcmFuY2Vf
    YXR0ZXN0YXRpb25zXzEuY3JsMB0GA1UdDgQWBBR3bIy6PB3fPAlYHOvqk7nftps4
    sDAKBggqhkjOPQQDAgNIADBFAiBrI2HGG1SZNRfEoaIwk3bjAjLBcE9tcKPi1gu0
    oah58AIhAL+KWRF8FwT4JBblyZdmuoVVXJ36LMmAUcs5YwJpMiQW
    -----END CERTIFICATE-----`,
                        issuer: "CN=Autorité de Certification France Attestations, C=FR",
                        test: true,
                        active: true,
                    },
                    {
                        name: "IACA NL mDL",
                        pem: `-----BEGIN CERTIFICATE-----
    MIIChzCCAg6gAwIBAgIUNKLqlwyPhbMOSD0kBpBVr/8nR3wwCgYIKoZIzj0EAwMw
    PjELMAkGA1UEBhMCTkwxDDAKBgNVBAoMA1JEVzELMAkGA1UEBRMCMDExFDASBgNV
    BAMMC0lBQ0EgTkwgbURMMB4XDTIxMTIxNDEzMTMxMFoXDTI5MTIxNDEzMTMwOVow
    PjELMAkGA1UEBhMCTkwxDDAKBgNVBAoMA1JEVzELMAkGA1UEBRMCMDExFDASBgNV
    BAMMC0lBQ0EgTkwgbURMMHowFAYHKoZIzj0CAQYJKyQDAwIIAQELA2IABD0oIkWG
    2SCr1imaAe1b41erTis67NlSA60xehE8IsYPVEzcn6FW5+gWrQ1p8+4ZizqdHFd3
    v84WWSe7W19tjqUurnTFMKG5NxZ2KFxpDc1YZCmB128PgeyJ2KzC2aFZ16OByDCB
    xTASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFNLoPEtlzS8edYK61ZVE
    b0WqBUlAMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly93d3ctZGllbnN0ZW4ucmR3
    Lm5sL2NybC9JQUNBTkxtREwtMDEuY3JsMB0GA1UdDgQWBBTS6DxLZc0vHnWCutWV
    RG9FqgVJQDAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0SBBYwFIYSaHR0cHM6Ly93d3cu
    cmR3Lm5sMAoGCCqGSM49BAMDA2cAMGQCMCG8ctJf3PUfSB2LoYqgoy2iWe1Nqzjo
    0FJxc9ePVPVeFfI2t2Mqe2mo50hJ9EKMqwIwBtek1Tpw/SRjLjI+L0PMBtiE9Tse
    C6oqwQPIIuSJLgUWByKywFFlK+i8EqosLCVT
    -----END CERTIFICATE-----`,
                        issuer: "C=NL, O=RDW, serialNumber=01, CN=IACA NL mDL",
                        test: false,
                        active: true,
                    },
                    {
                        name: "IACA NL mVR",
                        pem: `-----BEGIN CERTIFICATE-----
    MIIChzCCAg6gAwIBAgIUApUuBv6PnHuN+DFrHMXDPCD1eSswCgYIKoZIzj0EAwMw
    PjELMAkGA1UEBhMCTkwxDDAKBgNVBAoMA1JEVzELMAkGA1UEBRMCMDIxFDASBgNV
    BAMMC0lBQ0EgTkwgbVZSMB4XDTIzMTAxMDExMzA1MFoXDTMxMTAxMDExMzA0OVow
    PjELMAkGA1UEBhMCTkwxDDAKBgNVBAoMA1JEVzELMAkGA1UEBRMCMDIxFDASBgNV
    BAMMC0lBQ0EgTkwgbVZSMHowFAYHKoZIzj0CAQYJKyQDAwIIAQELA2IABB9T038B
    YLJ8EEA3WU23Y8uYShK9zvEB7zO6CcyvtpzDZLhefHc7qfibWATbI2Pa7EAtHAmb
    z8HkLqgBNfFg2aDtyfr9fs892dA6yJ9zbVv2Pna7+77rriOjND5doNnhxaOByDCB
    xTASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFEOPFj/6DqRZUGdQH2Ir
    /0wtL/+qMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly93d3ctZGllbnN0ZW4ucmR3
    Lm5sL2NybC9JQUNBTkxtVlItMDEuY3JsMB0GA1UdDgQWBBRDjxY/+g6kWVBnUB9i
    K/9MLS//qjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0SBBYwFIYSaHR0cHM6Ly93d3cu
    cmR3Lm5sMAoGCCqGSM49BAMDA2cAMGQCMEQf7RWdfWBY3SlgyW75xdZNuUmJPaDZ
    /mji/fMCSePodYkY/tg0uLUw/p6dFLytgQIwE4zKx4iQNBFW4jAgHdvfvS9qh0h6
    ryXFc+YMxyMOmThPKdcIKg1FMQZ6ZSaTOxEM
    -----END CERTIFICATE-----`,
                        issuer: "C=NL, O=RDW, serialNumber=02, CN=IACA NL mVR",
                        test: false,
                        active: true,
                    },
];
