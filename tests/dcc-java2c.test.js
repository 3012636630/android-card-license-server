const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  loadDccSelectionRegistry,
  resolveDccJava2cProfile
} = require("../server");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("resolves Java2C only for the exact immutable APK hash", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dcc-registry-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, "input.apk");
  fs.writeFileSync(input, "exact-apk");
  const selection = path.join(
    __dirname,
    "..",
    "full-vmprotect",
    "dex_toolchain",
    "selections",
    "v36-java2c-smoke-v1.json"
  );
  const registry = path.join(root, "registry.json");
  fs.writeFileSync(registry, JSON.stringify({
    schema_version: 1,
    profiles: [{
      id: "fixture-java2c-v1",
      input_apk_sha256: sha256(fs.readFileSync(input)),
      selection: "selections/v36-java2c-smoke-v1.json",
      selection_sha256: sha256(fs.readFileSync(selection)),
      library_name: "avmp-dcc",
      android_api: 23
    }]
  }));
  const profile = resolveDccJava2cProfile(input, registry);
  assert.equal(profile.id, "fixture-java2c-v1");
  assert.equal(profile.libraryName, "avmp-dcc");

  fs.appendFileSync(input, "drift");
  assert.equal(resolveDccJava2cProfile(input, registry), null);
});

test("rejects selection hash drift and paths outside dex_toolchain", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dcc-registry-invalid-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const registry = path.join(root, "registry.json");
  fs.writeFileSync(registry, JSON.stringify({
    schema_version: 1,
    profiles: [{
      id: "invalid",
      input_apk_sha256: sha256("apk"),
      selection: "../../outside.json",
      selection_sha256: sha256("selection"),
      library_name: "avmp-dcc",
      android_api: 23
    }]
  }));
  assert.throws(
    () => loadDccSelectionRegistry(registry),
    /must stay inside dex_toolchain/
  );
});

test("processor creates and exports one usable subprocess temp directory", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  assert.match(source, /PRIVATE_ARTIFACTS, PROCESS_TEMP/);
  assert.match(source, /env\.TEMP = PROCESS_TEMP/);
  assert.match(source, /env\.TMP = PROCESS_TEMP/);
  assert.match(source, /env\.TMPDIR = PROCESS_TEMP/);
});
