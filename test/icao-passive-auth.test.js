// Self-check for js/icao-passive-auth.js: builds a test PKI and EF.SOD with openssl, then runs passive authentication.
// Run: node test/icao-passive-auth.test.js   (needs openssl on PATH)
const assert = require("node:assert");
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");

const JS = path.join(__dirname, "..", "js");
vm.runInThisContext(fs.readFileSync(path.join(JS, "noble-curves.min.js"), "utf8")); // defines the nobleCurves global
const icao = require(path.join(JS, "icao-passive-auth.js"));

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "icao-pa-test-"));
const f = (n) => path.join(dir, n);
const ssl = (...args) => execFileSync("openssl", args, { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });

// Minimal DER encoder for the LDS security object
const len = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]);
const der = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag, ...len(body.length)]), body]);
};
const int = (n) => der(0x02, Buffer.from([n]));
const HASH_OIDS = { sha256: "0609608648016503040201", sha224: "0609608648016503040204" };

const dg1 = der(0x61, der(0x5f, Buffer.from([0x1f])));
const dg2 = der(0x75, crypto.randomBytes(300));
const lds = (hash) =>
  der(
    0x30,
    int(0),
    der(0x30, Buffer.from(HASH_OIDS[hash], "hex")),
    der(0x30, ...[[1, dg1], [2, dg2]].map(([n, v]) => der(0x30, int(n), der(0x04, crypto.createHash(hash).update(v).digest())))),
  );

function pki(name, keyArgs, { hash = "sha256", md = "sha256", signOpts = [] } = {}) {
  fs.writeFileSync(f(`${name}-lds.der`), lds(hash));
  ssl("genpkey", ...keyArgs, "-out", f(`${name}-csca.key`));
  ssl("req", "-x509", "-new", "-key", f(`${name}-csca.key`), `-${md}`, "-subj", "/C=FR/O=Test/CN=CSCA", "-days", "30", "-out", f(`${name}-csca.pem`));
  ssl("genpkey", ...keyArgs, "-out", f(`${name}-dsc.key`));
  ssl("req", "-new", "-key", f(`${name}-dsc.key`), "-subj", "/C=FR/O=Test/CN=DSC", "-out", f(`${name}-dsc.csr`));
  ssl("x509", "-req", "-in", f(`${name}-dsc.csr`), "-CA", f(`${name}-csca.pem`), "-CAkey", f(`${name}-csca.key`), `-${md}`, "-days", "30", "-out", f(`${name}-dsc.pem`));
  ssl("cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-md", md, "-econtent_type", "2.23.136.1.1.1", "-in", f(`${name}-lds.der`), "-signer", f(`${name}-dsc.pem`), "-inkey", f(`${name}-dsc.key`), "-outform", "DER", "-out", f(`${name}.sod`), ...signOpts);
  return {
    sod: der(0x77, fs.readFileSync(f(`${name}.sod`))),
    cscas: icao.readTrustFile(fs.readFileSync(f(`${name}-csca.pem`))),
  };
}

const rsa = ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"];
const cases = {
  brainpool_explicit: [["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1", "-pkeyopt", "ec_param_enc:explicit"]],
  p384_sha224_dgs: [["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"], { hash: "sha224" }],
  brainpool_p320: [["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP320r1"]],
  brainpool_p320_explicit: [["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP320r1", "-pkeyopt", "ec_param_enc:explicit"], { md: "sha224" }],
  rsa: [rsa],
  rsa_sha224: [rsa, { hash: "sha224", md: "sha224" }],
  rsa_pss: [rsa, { signOpts: ["-keyopt", "rsa_padding_mode:pss"] }],
};

(async () => {
  let other;
  for (const [name, [args, opts]] of Object.entries(cases)) {
    const { sod, cscas } = pki(name, args, opts);
    const ok = await icao.passiveAuth({ dataGroups: { 1: dg1, 2: dg2 }, sod }, cscas);
    assert.strictEqual(ok.integrity, "ok", `${name} integrity`);
    assert.strictEqual(ok.documentSigner, "ok", `${name} DSC`);
    assert.strictEqual(ok.csca, "ok", `${name} CSCA`);
    assert.strictEqual(ok.dsc.country, "FR", name);

    const tampered = Buffer.from(dg2);
    tampered[10] ^= 1;
    assert.strictEqual((await icao.passiveAuth({ dataGroups: { 1: dg1, 2: tampered }, sod }, cscas)).integrity, "fail", `${name} tampered DG`);
    assert.strictEqual((await icao.passiveAuth({ dataGroups: { 1: dg1, 2: dg2 }, sod }, [])).csca, "unknown", `${name} unknown CSCA`);
    if (other) assert.strictEqual((await icao.passiveAuth({ dataGroups: { 1: dg1 }, sod }, other)).csca, "unknown", `${name} wrong CSCA`);
    other = cscas;

    const badSig = Buffer.from(sod);
    badSig[badSig.length - 5] ^= 1; // inside the SignerInfo signature
    const bad = await icao.passiveAuth({ dataGroups: { 1: dg1, 2: dg2 }, sod: badSig }, cscas);
    assert.deepStrictEqual([bad.documentSigner, bad.csca], ["fail", "fail"], `${name} bad SOD signature`);
  }
  assert.strictEqual((await icao.passiveAuth({ dataGroups: { 1: dg1 }, sod: Buffer.from("garbage") }, [])).integrity, "fail");

  fs.rmSync(dir, { recursive: true });
  console.log("all checks passed");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
