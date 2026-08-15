const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { execFileSync } = require("node:child_process");

const {
  fullVmprotectReleaseCoverage,
  injectFullVmprotect,
  injectNativeGuard,
  nativeGuardIntegrityEntries,
  prepareFullVmprotectInput,
  sha256File,
  validateFullVmprotectProfile,
  verifyApkSignatureOutput,
  verifyFullVmprotectApkArtifacts
} = require("../server.js");

test("native guard preserves an ARM64-only input ABI set", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "native-guard-abi-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const decoded = path.join(root, "decoded");
  const nativeLibs = path.join(root, "native-libs");
  fs.mkdirSync(path.join(decoded, "lib", "arm64-v8a"), { recursive: true });
  for (const abi of ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]) {
    const abiDir = path.join(nativeLibs, abi);
    fs.mkdirSync(abiDir, { recursive: true });
    fs.writeFileSync(path.join(abiDir, "liblicenseguard.so"), abi);
  }

  injectNativeGuard(decoded, nativeLibs);

  const integrityEntries = nativeGuardIntegrityEntries(decoded);
  assert.deepEqual(integrityEntries, [{
    name: "lib/arm64-v8a/liblicenseguard.so",
    sha256: sha256File(path.join(decoded, "lib", "arm64-v8a", "liblicenseguard.so"))
  }]);

  assert.equal(
    fs.readFileSync(path.join(decoded, "lib", "arm64-v8a", "liblicenseguard.so"), "utf8"),
    "arm64-v8a"
  );
  for (const abi of ["armeabi-v7a", "x86", "x86_64"]) {
    assert.equal(fs.existsSync(path.join(decoded, "lib", abi)), false);
  }
});

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function createApkFixture(fixture, mutateTarget = false) {
  const apkRoot = path.join(fixture.root, "apk-root");
  const abiDir = path.join(apkRoot, "lib", fixture.profile.abi);
  fs.mkdirSync(abiDir, { recursive: true });
  fs.copyFileSync(
    path.join(fixture.profileDir, fixture.profile.runtimeLibrary),
    path.join(abiDir, fixture.profile.runtimeLibrary)
  );
  fs.copyFileSync(
    path.join(fixture.profileDir, fixture.profile.patchedLibrary),
    path.join(abiDir, fixture.profile.sourceLibrary)
  );
  if (mutateTarget) {
    fs.appendFileSync(path.join(abiDir, fixture.profile.sourceLibrary), "tampered");
  }
  const apk = path.join(fixture.root, mutateTarget ? "tampered.apk" : "valid.apk");
  execFileSync("jar", ["cf", apk, "-C", apkRoot, "."]);
  return apk;
}

function createFixture({ releaseReady = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "avmp-profile-test-"));
  const profileDir = path.join(root, "profile");
  const decodedDir = path.join(root, "decoded");
  const abiDir = path.join(decodedDir, "lib", "arm64-v8a");
  fs.mkdirSync(profileDir, { recursive: true });
  fs.mkdirSync(abiDir, { recursive: true });

  const source = Buffer.from("original-arm64-library");
  const patched = Buffer.from("virtualized-arm64-library");
  const runtime = Buffer.from("authenticated-avmp-runtime");
  fs.writeFileSync(path.join(abiDir, "libtarget.so"), source);
  fs.writeFileSync(path.join(profileDir, "libtarget-vmp.so"), patched);
  fs.writeFileSync(path.join(profileDir, "libavmpruntime.so"), runtime);

  const profile = {
    schemaVersion: 1,
    profileId: "test-arm64-profile",
    status: releaseReady ? "release" : "candidate",
    abi: "arm64-v8a",
    sourceLibrary: "libtarget.so",
    sourceLibrarySha256: sha256(source),
    patchedLibrary: "libtarget-vmp.so",
    patchedLibrarySha256: sha256(patched),
    runtimeLibrary: "libavmpruntime.so",
    runtimeLibrarySha256: sha256(runtime),
    installedFunctions: 2,
    virtualizedInstructions: releaseReady ? 100 : 17,
    totalSelectedArm64Instructions: 100,
    fullVirtualizationGatePassed: releaseReady
  };
  fs.writeFileSync(path.join(profileDir, "profile.json"), JSON.stringify(profile), "utf8");
  return { root, profileDir, decodedDir, abiDir, profile };
}

function createPreprotectedFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "avmp-preprotected-test-"));
  const profileDir = path.join(root, "profile");
  const apkRoot = path.join(root, "protected-root");
  const abiDir = path.join(apkRoot, "lib", "arm64-v8a");
  fs.mkdirSync(profileDir, { recursive: true });
  fs.mkdirSync(abiDir, { recursive: true });

  const sourceApk = path.join(root, "source.apk");
  fs.writeFileSync(sourceApk, "source-apk");
  fs.writeFileSync(path.join(apkRoot, "classes.dex"), "protected-dex");
  fs.writeFileSync(path.join(abiDir, "libnmmp.so"), "protected-runtime");
  const protectedApk = path.join(profileDir, "protected.apk");
  execFileSync("jar", ["cf", protectedApk, "-C", apkRoot, "."]);

  const coverage = {
    sourceReportSha256: "7".repeat(64),
    sourceApkSha256: sha256File(sourceApk),
    protectedApkSha256: sha256File(protectedApk),
    verifiedMethods: 2,
    totalMethods: 10,
    verifiedInstructions: 5,
    totalInstructions: 20,
    observedCoveragePercent: 25,
    fullVirtualizationGatePassed: false
  };
  const evidence = {
    target_apk_sha256: coverage.protectedApkSha256,
    differential_target_count: coverage.verifiedMethods,
    differential_instruction_count: coverage.verifiedInstructions,
    restored_ok: true,
    tamper_rejected: true
  };
  const coverageFile = path.join(profileDir, "coverage-summary.json");
  const evidenceFile = path.join(profileDir, "device-evidence.json");
  fs.writeFileSync(coverageFile, JSON.stringify(coverage));
  fs.writeFileSync(evidenceFile, JSON.stringify(evidence));

  const profile = {
    schemaVersion: 2,
    profileType: "preprotected-apk",
    profileId: "stable-test",
    profileVersion: "test-v1",
    status: "current-stable-device-verified",
    abi: "arm64-v8a",
    packageName: "example.test",
    sourceApkSha256: coverage.sourceApkSha256,
    protectedApk: path.basename(protectedApk),
    protectedApkSha256: coverage.protectedApkSha256,
    deviceEvidence: path.basename(evidenceFile),
    deviceEvidenceSha256: sha256File(evidenceFile),
    coverageSummary: path.basename(coverageFile),
    coverageSummarySha256: sha256File(coverageFile),
    sourceCoverageReportSha256: coverage.sourceReportSha256,
    verifiedMethods: coverage.verifiedMethods,
    totalMethods: coverage.totalMethods,
    virtualizedInstructions: coverage.verifiedInstructions,
    totalDexInstructions: coverage.totalInstructions,
    observedCoveragePercent: coverage.observedCoveragePercent,
    fullVirtualizationGatePassed: false,
    coveragePolicy: "fixed-apk-device-observed",
    protectedEntries: [
      { entry: "classes.dex", sha256: sha256File(path.join(apkRoot, "classes.dex")) },
      { entry: "lib/arm64-v8a/libnmmp.so", sha256: sha256File(path.join(abiDir, "libnmmp.so")) }
    ]
  };
  fs.writeFileSync(path.join(profileDir, "profile.json"), JSON.stringify(profile));
  return { root, profileDir, sourceApk, protectedApk, apkRoot, profile };
}

test("rejects profile artifact hash drift", (t) => {
  const fixture = createFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));
  fs.appendFileSync(path.join(fixture.profileDir, fixture.profile.runtimeLibrary), "tampered");
  assert.throws(
    () => validateFullVmprotectProfile(fixture.profileDir),
    /artifact integrity failed/
  );
});

test("accepts UTF-8 BOM-prefixed profile metadata", (t) => {
  const fixture = createFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));
  const profileFile = path.join(fixture.profileDir, "profile.json");
  fs.writeFileSync(profileFile, `\uFEFF${fs.readFileSync(profileFile, "utf8")}`, "utf8");

  assert.equal(
    validateFullVmprotectProfile(fixture.profileDir).profileId,
    fixture.profile.profileId
  );
});

test("rejects an APK source library hash mismatch", (t) => {
  const fixture = createFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(fixture.abiDir, fixture.profile.sourceLibrary), "wrong-input");
  assert.throws(
    () => injectFullVmprotect(fixture.decodedDir, fixture.profileDir),
    /profile input mismatch/
  );
});

test("injects the exact authenticated runtime and patched ELF", (t) => {
  const fixture = createFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));
  const result = injectFullVmprotect(fixture.decodedDir, fixture.profileDir);
  assert.equal(result.profileId, fixture.profile.profileId);
  assert.equal(result.profileStatus, "release");
  assert.equal(result.coveragePolicy, "whole-apk-binary-0-or-100");
  assert.equal(result.releaseCoveragePercent, 100);
  assert.equal(result.instructionCoveragePercent, 100);
  assert.equal(result.diagnosticInstructionCoveragePercent, 100);
  assert.equal(
    sha256File(path.join(fixture.abiDir, fixture.profile.sourceLibrary)),
    fixture.profile.patchedLibrarySha256
  );
  assert.equal(
    sha256File(path.join(fixture.abiDir, fixture.profile.runtimeLibrary)),
    fixture.profile.runtimeLibrarySha256
  );
});

test("rejects a partial profile before APK injection", (t) => {
  const fixture = createFixture({ releaseReady: false });
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));

  assert.throws(
    () => injectFullVmprotect(fixture.decodedDir, fixture.profileDir),
    /release gate failed.*release coverage 0%/
  );
});

test("selects the exact stable preprotected APK and publishes observed evidence", (t) => {
  const fixture = createPreprotectedFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));

  const prepared = prepareFullVmprotectInput(fixture.sourceApk, fixture.profileDir);
  assert.equal(prepared.protectedApk, fixture.protectedApk);
  assert.equal(prepared.summary.profileStatus, "current-stable-device-verified");
  assert.equal(prepared.summary.verifiedMethods, 2);
  assert.equal(prepared.summary.virtualizedInstructions, 5);
  assert.equal(prepared.summary.observedCoveragePercent, 25);
  assert.equal(prepared.summary.fullVirtualizationGatePassed, false);
  assert.equal(prepared.summary.releaseCoveragePercent, 0);
});

test("rejects an APK that does not match the stable profile source hash", (t) => {
  const fixture = createPreprotectedFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));
  fs.appendFileSync(fixture.sourceApk, "-other");

  assert.throws(
    () => prepareFullVmprotectInput(fixture.sourceApk, fixture.profileDir),
    /stable profile input mismatch/
  );
});

test("verifies preserved DEX and runtime entries for a preprotected APK", async (t) => {
  const fixture = createPreprotectedFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));

  const result = await verifyFullVmprotectApkArtifacts(
    fixture.protectedApk,
    fixture.root,
    fixture.profileDir
  );
  assert.equal(result.profileId, "stable-test");
  assert.equal(result.profileType, "preprotected-apk");
  assert.equal(result.entries.length, 2);
});

test("publishes only binary whole-target coverage", () => {
  const partial = {
    fullVirtualizationGatePassed: false,
    virtualizedInstructions: 99,
    totalSelectedArm64Instructions: 100
  };
  const inconsistent = {
    fullVirtualizationGatePassed: true,
    virtualizedInstructions: 99,
    totalSelectedArm64Instructions: 100
  };
  const complete = {
    fullVirtualizationGatePassed: true,
    virtualizedInstructions: 100,
    totalSelectedArm64Instructions: 100
  };

  assert.equal(fullVmprotectReleaseCoverage(partial), 0);
  assert.equal(fullVmprotectReleaseCoverage(inconsistent), 0);
  assert.equal(fullVmprotectReleaseCoverage(complete), 100);
});

test("verifies exact VMProtect artifacts in the final APK", async (t) => {
  const fixture = createFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));
  const apk = createApkFixture(fixture);
  const result = await verifyFullVmprotectApkArtifacts(
    apk,
    fixture.root,
    fixture.profileDir
  );
  assert.equal(result.profileId, fixture.profile.profileId);
  assert.equal(result.entries.length, 2);
});

test("rejects final APK artifact drift", async (t) => {
  const fixture = createFixture();
  t.after(() => fs.rmSync(fixture.root, { recursive: true, force: true }));
  const apk = createApkFixture(fixture, true);
  await assert.rejects(
    verifyFullVmprotectApkArtifacts(apk, fixture.root, fixture.profileDir),
    /Final APK VMProtect artifact integrity failed/
  );
});

test("requires v2, v3, and the expected final signing certificate", () => {
  const digest = "ab".repeat(32);
  const output = [
    "Verified using v2 scheme (APK Signature Scheme v2): true",
    "Verified using v3 scheme (APK Signature Scheme v3): true",
    `Signer #1 certificate SHA-256 digest: ${digest}`
  ].join("\n");
  assert.deepEqual(verifyApkSignatureOutput(output, digest), {
    v2: true,
    v3: true,
    certificateSha256: digest
  });
  assert.throws(
    () => verifyApkSignatureOutput(output.replace("v3): true", "v3): false"), digest),
    /both v2 and v3/
  );
  assert.throws(
    () => verifyApkSignatureOutput(output, "cd".repeat(32)),
    /certificate SHA-256 mismatch/
  );
});
