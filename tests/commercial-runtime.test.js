const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const { writeJavaSources } = require("../server");

function filesBelow(root, suffix) {
  const output = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const item = path.join(root, entry.name);
    if (entry.isDirectory()) output.push(...filesBelow(item, suffix));
    else if (item.endsWith(suffix)) output.push(item);
  }
  return output;
}

function androidJar() {
  const sdk = path.join(process.env.LOCALAPPDATA, "Android", "Sdk", "platforms");
  return fs.readdirSync(sdk)
    .map((name) => path.join(sdk, name, "android.jar"))
    .filter((item) => fs.existsSync(item))
    .sort()
    .at(-1);
}

test("commercial runtime sources include centralized policy and platform controls", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "commercial-runtime-"));
  try {
    writeJavaSources(
      root,
      "com.example.fixture",
      "com.example.fixture.MainActivity",
      "https://license.example.test",
      "fixture-app",
      "RSA4096-AES256-GCM",
      "transport-key",
      "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
      "signing-key",
      "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----",
      "0123456789abcdef0123456789abcdef",
      "0".repeat(64),
      "fixture-card",
      "",
      "",
      "",
      true,
      true,
      [{ name: "classes.dex", sha256: "1".repeat(64) }],
      "license.example.test",
      ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
      { root: "2".repeat(64), count: 4, generatedDexName: "classes2.dex" },
      {
        entries: [{ path: "www/index.html", stored: ".avmp/a.bin", size: 5, sha256: "3".repeat(64) }],
        keyShareA: Buffer.alloc(32, 1).toString("base64"),
        keyShareB: Buffer.alloc(32, 2).toString("base64")
      }
    );
    const dir = path.join(root, "com", "example", "fixture");
    const risk = fs.readFileSync(path.join(dir, "RuntimeRisk.java"), "utf8");
    const runtime = fs.readFileSync(path.join(dir, "VmpRuntime.java"), "utf8");
    const guard = fs.readFileSync(path.join(dir, "GuardRuntime.java"), "utf8");
    const activity = fs.readFileSync(path.join(dir, "LicenseActivity.java"), "utf8");
    const store = fs.readFileSync(path.join(dir, "SecureStore.java"), "utf8");
    const tlsPins = fs.readFileSync(path.join(dir, "TlsPins.java"), "utf8");
    const protectedAssets = fs.readFileSync(path.join(dir, "ProtectedAssets.java"), "utf8");
    const nationalCrypto = fs.readFileSync(path.join(dir, "NationalCrypto.java"), "utf8");
    const playIntegrity = fs.readFileSync(path.join(dir, "PlayIntegrity.java"), "utf8");
    const licenseClient = fs.readFileSync(path.join(dir, "LicenseClient.java"), "utf8");

    assert.match(risk, /TTL=300000L/);
    assert.match(risk, /RESTRICT=50,CHALLENGE=70,END_FLOW=90/);
    assert.match(risk, /TRANSPORT_VPN/);
    assert.match(risk, /ENABLED_ACCESSIBILITY_SERVICES/);
    assert.match(risk, /FLAG_WINDOW_IS_OBSCURED/);
    assert.match(risk, /FLAG_SECURE/);
    assert.match(risk, /TLS_PIN_MISMATCH=1024/);
    assert.match(runtime, /RuntimeRisk\.nativeEvidence/);
    assert.match(runtime, /IMMUTABLE_COUNT = 4/);
    assert.match(runtime, /verifyArchive\(context\)/);
    assert.match(runtime, /Collections\.sort\(names\)/);
    assert.match(runtime, /name\.equals\(GENERATED_DEX\)/);
    assert.match(guard, /RuntimeRisk\.secure\(a\)/);
    assert.match(activity, /RuntimeRisk\.secure\(this\)/);
    assert.match(activity, /setFilterTouchesWhenObscured\(true\)/);
    assert.match(activity, /RuntimeRisk\.touch\(event\)/);
    assert.match(store, /AndroidKeyStore/);
    assert.match(store, /AES\/GCM\/NoPadding/);
    assert.match(tlsPins, /HttpsURLConnection/);
    assert.match(tlsPins, /getServerCertificates/);
    assert.match(tlsPins, /getPublicKey\(\)\.getEncoded\(\)/);
    assert.doesNotMatch(tlsPins, /setHostnameVerifier|setSSLSocketFactory/);
    assert.match(protectedAssets, /AES\/GCM\/NoPadding/);
    assert.match(protectedAssets, /AVMP-ASSET-1/);
    assert.match(protectedAssets, /protected asset rejected/);
    assert.match(protectedAssets, /MessageDigest\.getInstance\("SHA-256"\)/);
    assert.match(protectedAssets, /WipingInputStream/);
    assert.match(protectedAssets, /Arrays\.fill\(buf,\(byte\)0\)/);
    assert.match(nationalCrypto, /66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0/);
    assert.match(nationalCrypto, /static boolean selfTest\(\)/);
    assert.match(playIntegrity, /IntegrityManagerFactory/);
    assert.match(playIntegrity, /setCloudProjectNumber/);
    assert.match(playIntegrity, /PLAY-INTEGRITY-1/);
    assert.match(licenseClient, /NationalCrypto\.bind/);
    assert.match(licenseClient, /PlayIntegrity\.collect/);
    assert.match(licenseClient, /finally\{if\(env!=null\)Arrays\.fill\(env\.key,\(byte\)0\)/);

    const classes = path.join(root, "classes");
    fs.mkdirSync(classes);
    fs.writeFileSync(path.join(dir, "Sm3Probe.java"), `package com.example.fixture;
public final class Sm3Probe {
  public static void main(String[] args) {
    if (!NationalCrypto.selfTest()) throw new AssertionError("SM3 self-test failed");
    String actual = NationalCrypto.bind("abc");
    if (!"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0".equals(actual)) throw new AssertionError(actual);
  }
}
`, "utf8");
    const compiled = spawnSync(
      "javac",
      ["-encoding", "UTF-8", "-source", "8", "-target", "8", "-bootclasspath", androidJar(), "-d", classes, ...filesBelow(root, ".java")],
      { encoding: "utf8" }
    );
    assert.equal(compiled.status, 0, compiled.stderr || compiled.stdout);
    const sm3Probe = spawnSync("java", ["-cp", classes, "com.example.fixture.Sm3Probe"], { encoding: "utf8" });
    assert.equal(sm3Probe.status, 0, sm3Probe.stderr || sm3Probe.stdout);
    const nativeGuard = fs.readFileSync(path.join(__dirname, "..", "native-guard", "license_guard.c"), "utf8");
    assert.match(nativeGuard, /GUARD_IMPORT_TABLE/);
    assert.match(nativeGuard, /check_import_table\(\)/);
    assert.match(nativeGuard, /GUARD_TEXT_IMAGE/);
    assert.match(nativeGuard, /check_text_image\(\)/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
