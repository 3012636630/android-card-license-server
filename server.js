const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const tls = require("tls");
const { spawn } = require("child_process");
const { protectStaticAssets } = require("./asset-protector");
const { instrumentRuntimeSignals, stripReleaseLogs } = require("./smali-hardening");

const ROOT = __dirname;
const TOOLS = path.join(ROOT, "tools");
const WORK = process.env.WORK_DIR || path.join(ROOT, "work");
const OUT = process.env.OUT_DIR || path.join(ROOT, "out");
const DATA = process.env.DATA_DIR || path.join(ROOT, "data");
const NATIVE_LIBS = path.join(ROOT, "native-libs");
const PRIVATE_ARTIFACTS = process.env.PRIVATE_ARTIFACT_DIR || path.join(DATA, "private-artifacts");
const FULL_VMP_PROFILE_DIR = process.env.FULL_VMP_PROFILE_DIR
  || path.join(ROOT, "full-vmprotect", "release", "stable-v20");
const DCC_ROOT = path.join(ROOT, "full-vmprotect");
const DCC_TOOLCHAIN_ROOT = path.join(DCC_ROOT, "dex_toolchain");
const DCC_SELECTION_REGISTRY = process.env.DCC_SELECTION_REGISTRY
  || path.join(DCC_TOOLCHAIN_ROOT, "selection-registry.json");
const CARDS_FILE = path.join(DATA, "cards.json");
const PORT = Number(process.env.PORT || 8789);
const SERVICE_REVISION = process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || "local";
const DEFAULT_SERVER = process.env.DEFAULT_LICENSE_SERVER || "https://android-license-gateway-phone.pages.dev";
const V4_CONFIG_ORIGIN = (process.env.V4_CONFIG_ORIGIN || "").replace(/\/+$/, "");
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/+$/, "");
const PROCESS_TEMP = path.resolve(
  process.env.PROCESS_TEMP_DIR
  || process.env.TMPDIR
  || process.env.TEMP
  || process.env.TMP
  || os.tmpdir()
);
const APKTOOL_VERSION = "3.0.2";
const APKTOOL_URL = `https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar`;
const LICENSE_DEFAULTS = {
  ADMIN_TOKEN: process.env.ADMIN_TOKEN || "change_this_admin_token",
};
const JOBS = new Map();
const JOB_QUEUE = [];
const JOB_TTL_MS = 6 * 60 * 60 * 1000;
let jobRunnerActive = false;

for (const dir of [TOOLS, WORK, OUT, DATA, PRIVATE_ARTIFACTS, PROCESS_TEMP]) fs.mkdirSync(dir, { recursive: true });
if (!fs.existsSync(CARDS_FILE)) fs.writeFileSync(CARDS_FILE, "[]", "utf8");

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === "OPTIONS") {
      res.writeHead(204, corsHeaders());
      return res.end();
    }
    if (req.method === "GET" && url.pathname === "/") return html(res, pageCommercial());
    if (req.method === "GET" && url.pathname === "/health") return json(res, { ok: true, service: "apk-license-packer", revision: SERVICE_REVISION });
    if (req.method === "GET" && url.pathname.startsWith("/out/")) return file(res, path.join(OUT, decodeURIComponent(url.pathname.slice(5))));
    if (req.method === "GET" && url.pathname === "/api/status") return json(res, { ok: true, revision: SERVICE_REVISION, tools: await detectTools(), accessUrls: accessUrls() });
    if (req.method === "GET" && url.pathname.startsWith("/api/jobs/")) return jobStatus(res, decodeURIComponent(url.pathname.slice("/api/jobs/".length)));
    if (req.method === "POST" && url.pathname === "/api/process") return await processUpload(req, res, url);
    if (req.method === "GET" && url.pathname === "/admin/cards") return adminJson(req, res, () => ({ ok: true, cards: listCards(url.searchParams.get("cardName")) }));
    if (req.method === "POST" && url.pathname === "/admin/cards") return adminJson(req, res, async () => createCards(await readJsonBody(req)));
    if (req.method === "DELETE" && url.pathname === "/admin/cards") return adminJson(req, res, () => deleteAllCards(url.searchParams.get("cardName")));
    if (url.pathname.startsWith("/admin/cards/")) return adminJson(req, res, async () => updateCard(url.pathname.slice("/admin/cards/".length), req.method, await readJsonBody(req).catch(() => ({}))));
    return json(res, { ok: false, message: "not found" }, 404);
  } catch (error) {
    return json(res, { ok: false, message: error.message || String(error) }, 500);
  }
});

if (require.main === module) {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`APK drag dashboard listening on 0.0.0.0:${PORT}`);
  });
}

const jobCleanupTimer = setInterval(() => {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of JOBS) {
    if (job.updatedAt < cutoff && (job.status === "done" || job.status === "failed")) JOBS.delete(id);
  }
}, 60 * 1000);
jobCleanupTimer.unref?.();

async function processUpload(req, res, url) {
  const originalName = safeName(url.searchParams.get("fileName") || "input.apk");
  const serverUrl = normalizeUrl(url.searchParams.get("serverUrl") || DEFAULT_SERVER);
  const appId = url.searchParams.get("appId") || "demo_android_app";
  const cardName = normalizeCardName(url.searchParams.get("cardName") || "姒涙顓绘潪顖欐");
  const purchaseUrl = normalizeOptionalUrl(url.searchParams.get("purchaseUrl") || "");
  const jumpText = normalizeOptionalText(url.searchParams.get("jumpText") || "");
  const jumpUrl = normalizeOptionalUrl(url.searchParams.get("jumpUrl") || "");
  const obfuscate = url.searchParams.get("obfuscate") !== "0";
  const fullVmp = url.searchParams.get("fullVmp") === "1" || url.searchParams.get("wholeApp") === "1";
  const useVmp = fullVmp || url.searchParams.get("vmp") === "1";
  const strictGuard = url.searchParams.get("strictGuard") === "1";
  const experimentalProtection = url.searchParams.get("experimentalProtection") === "1";
  const buildId = crypto.randomBytes(16).toString("hex");
  const id = new Date().toISOString().replace(/[-:.TZ]/g, "") + "-" + crypto.randomBytes(3).toString("hex");
  const jobDir = path.join(WORK, id);
  const decodedDir = path.join(jobDir, "decoded");
  const javaDir = path.join(jobDir, "java");
  const classesDir = path.join(jobDir, "classes");
  const dexDir = path.join(jobDir, "dex");
  fs.mkdirSync(jobDir, { recursive: true });

  const inputApk = path.join(jobDir, originalName);
  await saveBody(req, inputApk);

  const now = Date.now();
  const job = {
    id,
    status: "queued",
    progress: "APK 瀹歌弓绗傛导鐙呯礉濮濓絽婀粵澶婄窡娴滄垹顏径鍕倞",
    createdAt: now,
    updatedAt: now,
    config: { originalName, serverUrl, appId, cardName, purchaseUrl, jumpText, jumpUrl, obfuscate, useVmp, fullVmp, strictGuard, experimentalProtection, buildId },
    paths: { jobDir, decodedDir, javaDir, classesDir, dexDir, inputApk }
  };
  JOBS.set(id, job);
  JOB_QUEUE.push(job);
  void runJobQueue();

  return json(res, {
    ok: true,
    queued: true,
    jobId: id,
    status: job.status,
    progress: job.progress,
    statusUrl: `/api/jobs/${encodeURIComponent(id)}`
  }, 202);
}

function jobStatus(res, id) {
  const job = JOBS.get(id);
  if (!job) return json(res, { ok: false, message: "job not found or expired" }, 404);
  return json(res, publicJob(job));
}

function publicJob(job) {
  const payload = {
    ok: job.status !== "failed",
    jobId: job.id,
    status: job.status,
    progress: job.progress,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt
  };
  if (job.status === "done") payload.result = job.result;
  if (job.status === "failed") payload.message = job.message || "APK 婢跺嫮鎮婃径杈Е";
  return payload;
}

function updateJob(job, progress) {
  job.progress = progress;
  job.updatedAt = Date.now();
}

async function runJobQueue() {
  if (jobRunnerActive) return;
  jobRunnerActive = true;
  try {
    while (JOB_QUEUE.length) {
      const job = JOB_QUEUE.shift();
      job.status = "processing";
      job.startedAt = Date.now();
      updateJob(job, "濮濓絽婀崙鍡楊槵 Android 閺嬪嫬缂撳銉ュ徔");
      try {
        job.result = await buildApk(job);
        job.status = "done";
        job.finishedAt = Date.now();
        updateJob(job, "婢跺嫮鎮婄€瑰本鍨氶敍灞藉讲娴犮儰绗呮潪?APK");
      } catch (error) {
        job.status = "failed";
        job.finishedAt = Date.now();
        job.message = error && error.message ? error.message : String(error);
        updateJob(job, "婢跺嫮鎮婃径杈Е");
        console.error(`APK job ${job.id} failed:`, error);
      } finally {
        try { fs.rmSync(job.paths.jobDir, { recursive: true, force: true }); } catch (_) {}
      }
    }
  } finally {
    jobRunnerActive = false;
  }
}

async function buildApk(job) {
  const { id } = job;
  const { originalName, serverUrl, appId, cardName, purchaseUrl, jumpText, jumpUrl, obfuscate, useVmp, fullVmp, strictGuard, experimentalProtection, buildId } = job.config;
  const { jobDir, decodedDir, javaDir, classesDir, dexDir, inputApk } = job.paths;
  let fullVmpProfile = null;
  let fullVmpArtifactVerification = null;
  let java2cProtection = { applied: false, reason: useVmp ? "no-matching-profile" : "vmp-disabled" };
  let assetProtection = { applied: false, reason: "vmp-disabled", entries: [], rewrittenCalls: 0 };
  let resourceProtection = { applied: false, reason: "obfuscation-disabled", collapsedNames: false };
  let logProtection = { applied: false, removedCalls: 0, rewrittenResults: 0, changedFiles: 0 };
  let runtimeSignalInstrumentation = { applied: false, locationCalls: 0, changedFiles: 0 };
  let nativeGuardEntries = [];
  let processingApk = inputApk;

  const tools = await detectTools();
  if (!tools.java || !tools.javac || !tools.d8 || !tools.zipalign || !tools.apksigner || !tools.androidJar) {
    throw new Error("Missing Java or Android SDK tools" );
  }
  const apktool = await ensureApktool();
  if (fullVmp) {
    updateJob(job, "Matching the current stable VMProtect profile");
    const prepared = prepareFullVmprotectInput(inputApk);
    processingApk = prepared.protectedApk;
    fullVmpProfile = prepared.summary;
  }
  updateJob(job, "Fetching V4 RSA-4096 transport configuration");
  const transport = await resolveV4Transport(serverUrl, appId);
  const signing = await ensureSigningKey(tools);
  const signingCertificate = await signingCertificateInfo(tools, signing);
  const signingCertSha256 = signingCertificate.sha256;

  updateJob(job, "濮濓絽婀憴锝嗙€介崢?APK");
  const decodeArgs = ["-jar", apktool, "d", "-f"];
  if (fullVmp && !experimentalProtection) decodeArgs.push("-s");
  decodeArgs.push(processingApk, "-o", decodedDir);
  await run(tools.java, decodeArgs, jobDir);
  const manifestPath = path.join(decodedDir, "AndroidManifest.xml");
  let manifest = fs.readFileSync(manifestPath, "utf8");
  const packageName = readPackageName(manifest);
  const launcher = readLauncherActivity(manifest, packageName);
  manifest = removeLauncherFilters(manifest);
  manifest = addInternetPermission(manifest);
  manifest = configureCleartext(manifest, serverUrl);
  manifest = addLicenseComponents(manifest, packageName);
  if (fullVmp) manifest = hardenManifest(manifest);
  fs.writeFileSync(manifestPath, manifest, "utf8");
  if (useVmp) {
    injectNativeGuard(decodedDir);
    nativeGuardEntries = nativeGuardIntegrityEntries(decodedDir);
  }
  if (useVmp) {
    updateJob(job, "Protecting statically traceable assets and H5 entries");
    assetProtection = protectStaticAssets(decodedDir, packageName, buildId);
    updateJob(job, "Removing release logging calls");
    logProtection = stripReleaseLogs(decodedDir);
    runtimeSignalInstrumentation = instrumentRuntimeSignals(decodedDir, packageName);
  }

  const java2cProfile = useVmp && (!fullVmp || experimentalProtection)
    ? resolveDccJava2cProfile(inputApk)
    : null;
  if (java2cProfile) {
    updateJob(job, `Compiling ${java2cProfile.id} Java2C methods with fixed DCC`);
    java2cProtection = await applyDccJava2c(
      tools,
      inputApk,
      decodedDir,
      jobDir,
      java2cProfile
    );
  }

  updateJob(job, "Decoding input APK");
  const unsignedApk = path.join(jobDir, "unsigned.apk");
  await run(tools.java, ["-jar", apktool, "b", decodedDir, "-o", unsignedApk], jobDir);
  if (obfuscate && (!fullVmp || experimentalProtection)) {
    updateJob(job, "Optimizing and obfuscating compiled Android resources");
    resourceProtection = await optimizeCompiledResources(
      tools,
      unsignedApk,
      decodedDir,
      jobDir,
      buildId,
      undefined,
      fullVmp && experimentalProtection
    );
  } else if (obfuscate && fullVmp) {
    resourceProtection = {
      applied: false,
      reason: "preprotected-profile-resources-preserved",
      collapsedNames: false
    };
  }
  const unsignedEntries = await zipList(unsignedApk);
  const generatedDexName = nextDexEntryName(unsignedEntries);
  const dexHashes = useVmp ? await originalDexHashes(unsignedApk, jobDir) : [];
  const immutableManifest = useVmp ? await immutableApkManifest(unsignedApk, jobDir, generatedDexName) : { root: "", count: 0, generatedDexName };

  writeJavaSources(
    javaDir,
    packageName,
    launcher,
    serverUrl,
    appId,
    transport.suiteId,
    transport.keyId,
    transport.publicKey,
    transport.signingKeyId,
    transport.signingPublicKey,
    buildId,
    signingCertSha256,
    cardName,
    purchaseUrl,
    jumpText,
    jumpUrl,
    useVmp,
    strictGuard,
    dexHashes,
    transport.tlsPinHost,
    transport.tlsPins,
    immutableManifest,
    assetProtection,
    nativeGuardEntries
  );
  updateJob(job, "濮濓絽婀紓鏍槯妤犲矁鐦夌粣妤€褰涢妴浣哥妇鐠哄啿鎷扮€瑰鍙忔导鐘虹翻濡€虫健");
  fs.mkdirSync(classesDir, { recursive: true });
  const javaFiles = listFiles(javaDir).filter((f) => f.endsWith(".java"));
  await run(tools.javac, ["-encoding", "UTF-8", "-source", "8", "-target", "8", "-bootclasspath", tools.androidJar, "-d", classesDir, ...javaFiles], jobDir);
  fs.mkdirSync(dexDir, { recursive: true });
  let obfuscationMessage = "Verification module not obfuscated";
  if (obfuscate && tools.r8 && tools.jar) {
    updateJob(job, "Running R8 obfuscation and VMP+ protection");
    const classesJar = path.join(jobDir, "license-classes.jar");
    const rules = path.join(jobDir, "r8-rules.pro");
    fs.writeFileSync(rules, [
      `-keep public class ${packageName}.LicenseActivity { public <init>(); public void onCreate(android.os.Bundle); }`,
      `-keep public class ${packageName}.LicenseGuardProvider { public <init>(); public boolean onCreate(); }`,
      "-keep class com.android.licenseguard.NativeBridge { *; }",
      "-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod",
      "-dontwarn **"
    ].join("\n"), "utf8");
    await run(tools.jar, ["cf", classesJar, "-C", classesDir, "."], jobDir);
    await run(tools.java, ["-cp", tools.r8, "com.android.tools.r8.R8", "--release", "--min-api", "23", "--lib", tools.androidJar, "--pg-conf", rules, "--output", dexDir, classesJar], jobDir);
    obfuscationMessage = "Verification module obfuscated with R8";
  } else {
    await run(tools.d8, ["--min-api", "23", "--output", dexDir, ...listFiles(classesDir).filter((f) => f.endsWith(".class"))], jobDir);
    if (obfuscate) obfuscationMessage = "R8 unavailable; verification module was injected without obfuscation";
  }

  const withDexApk = path.join(jobDir, "with-license.apk");
  fs.copyFileSync(unsignedApk, withDexApk);
  await addDex(withDexApk, path.join(dexDir, "classes.dex"), generatedDexName);

  const signedName = originalName.replace(/\.apk$/i, "") + `-${id.slice(-6)}` + (fullVmp ? "-license-full-vmp.apk" : useVmp ? "-license-vmp-plus.apk" : "-license.apk");
  const signedApk = path.join(OUT, signedName);
  const alignedApk = path.join(jobDir, "aligned.apk");
  updateJob(job, "濮濓絽婀€靛綊缍堥獮鍫曞櫢閺傛壆顒烽崥?APK");
  await run(tools.zipalign, ["-f", "-p", "4", withDexApk, alignedApk], jobDir);
  await run(tools.apksigner, [
    "sign",
    "--ks", signing.keystore,
    "--ks-pass", `pass:${signing.storepass}`,
    "--key-pass", `pass:${signing.keypass}`,
    "--ks-key-alias", signing.alias,
    "--out", signedApk,
    alignedApk
  ], jobDir);

  updateJob(job, "Rebuilding APK and calculating integrity metadata");
  await run(tools.zipalign, ["-c", "-v", "4", signedApk], jobDir);
  const signatureOutput = await runCapture(
    tools.apksigner,
    ["verify", "--verbose", "--print-certs", signedApk],
    jobDir
  );
  const signatureVerification = verifyApkSignatureOutput(
    signatureOutput,
    signingCertSha256
  );
  if (fullVmp) {
    updateJob(job, "Verifying final APK ARM64 VMProtect artifacts");
    fullVmpArtifactVerification = experimentalProtection
      ? await verifyExperimentalFullVmprotectApkArtifacts(signedApk, jobDir)
      : await verifyFullVmprotectApkArtifacts(signedApk, jobDir);
  }
  if (java2cProtection.applied) {
    updateJob(job, "Verifying final APK Java2C native stubs and ARM64 library");
    java2cProtection = await verifyDccJava2cApk(
      tools,
      signedApk,
      jobDir,
      buildId,
      java2cProtection
    );
  }

  const finalName = signedName;
  const transportMessage = "V4 鐎瑰鍙忔导鐘虹翻閿涙瓓SA-4096-OAEP + AES-256-GCM + HMAC-SHA256 + RSA-PSS-4096 閺堝秴濮熺粩顖滎劮閸氬秶鐓粔鐔哄 + Android Keystore 鐠佹儳顦紒鎴濈暰 + 闂呭繑婧€ IV/nonce/閺冨爼妫块幋鎶芥Щ闁插秵鏂侀敍娑樺讲閸楀繐鏅?SM4-GCM/SM2/SM3 閸ヨ棄鐦戞總妞炬";
  const vmpMessage = fullVmp
    ? `Android VMProtect ${fullVmpProfile.profileStatus} profile ${fullVmpProfile.profileId}: observed coverage ${fullVmpProfile.observedCoveragePercent}% (${fullVmpProfile.verifiedMethods}/${fullVmpProfile.totalMethods} methods, ${fullVmpProfile.virtualizedInstructions}/${fullVmpProfile.totalDexInstructions} instructions); full gate ${fullVmpProfile.fullVirtualizationGatePassed ? "passed" : "pending"}`
    : useVmp
    ? `瀹告彃鎯庨悽銊ュ敶缂?VMP+閿涙岸鍘ょ純顔肩摟缁楋缚瑕嗛崝鐘茬槕閵嗕線娈㈤張鐑樺瘹娴犮倝鐛欑拠浣芥珓閹风喐婧€閵嗕礁寮界拫鍐槸閸?Frida/Xposed/LSPosed 閻╂垶绁撮妴?{dexHashes.length} 娑擃亜甯慨?DEX 鐎瑰本鏆ｉ幀褎鐗庢宀嬬幢鐎瑰牆宕煎Ο鈥崇础閿?{strictGuard ? "娑撱儲鐗? : "閸忕厧顔?}`
    : "VMP+ protection not enabled";
  const cleanTransportMessage = "V4 RSA-4096-OAEP + AES-256-GCM + HMAC-SHA256 + RSA-PSS-4096, timestamp and nonce validation, Android Keystore, and TLS SPKI pinning";
  const cleanVmpMessage = fullVmp
    ? `Android VMProtect ${fullVmpProfile.profileStatus} profile ${fullVmpProfile.profileId}: observed coverage ${fullVmpProfile.observedCoveragePercent}% (${fullVmpProfile.verifiedMethods}/${fullVmpProfile.totalMethods} methods, ${fullVmpProfile.virtualizedInstructions}/${fullVmpProfile.totalDexInstructions} instructions); full gate ${fullVmpProfile.fullVirtualizationGatePassed ? "passed" : "pending"}; ${experimentalProtection ? "experimental Java2C/resource rebuild enabled" : "stable byte-preserving rebuild"}`
    : useVmp
    ? `VMP+ runtime guard, Frida/Xposed/LSPosed detection, ${dexHashes.length} original DEX checks, immutable APK root, ${strictGuard ? "strict" : "balanced"} policy`
    : "VMP+ protection not enabled";
  const cleanSigningMessage = `APK signed with ${signingCertificate.algorithm}-${signingCertificate.keyBits}; certificate SHA-256: ${signingCertSha256}`;

  return {
    ok: true,
    file: `/out/${encodeURIComponent(finalName)}`,
    fileName: finalName,
    packageName,
    launcher,
    serverUrl,
    cardName,
    purchaseUrl,
    jumpText,
    jumpUrl,
    transportMessage: cleanTransportMessage,
    signingMessage: `APK 瀹歌弓濞囬悽?${signingCertificate.algorithm}-${signingCertificate.keyBits} 閸欐垵绔风拠浣峰姛缁涙儳鎮曢敍宀冪槈娑?SHA-256閿?{signingCertSha256}`,
    signingCertificateSha256: signingCertSha256,
    signingMessage: cleanSigningMessage,
    signatureVerification,
    obfuscationMessage,
    vmpMessage: cleanVmpMessage,
    fullVmp,
    fullVmpProfile,
    fullVmpArtifactVerification,
    java2cProtection,
    assetProtection: { applied: assetProtection.applied, reason: assetProtection.reason, entries: assetProtection.entries.length, rewrittenCalls: assetProtection.rewrittenCalls },
    resourceProtection,
    logProtection,
    runtimeSignalInstrumentation,
    strictGuard,
    experimentalProtection,
    experimentalModules: experimentalProtection ? {
      wholeApkVirtualization: { status: "partial", observedCoveragePercent: fullVmpProfile ? fullVmpProfile.observedCoveragePercent : 0 },
      java2c: { status: java2cProtection.applied ? "applied" : "unavailable", ...java2cProtection },
      resourceObfuscation: { status: resourceProtection.applied ? "applied" : "skipped", ...resourceProtection },
      nationalCrypto: { status: "partial", activeSuite: transport.suiteId, implemented: ["SM3-client-self-test", "SM3-request-binding"], pending: ["SM2-client-server", "SM4-GCM-client-server"] },
      playIntegrity: { status: "partial", packaged: true, cloudProjectConfigured: Number(process.env.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER || 0) > 0, backendVerdictGate: false },
      nativeImportIntegrity: { status: "partial", implemented: ["selected-inline-prologues", "libc-origin", "anonymous-rwx", "guard-full-text-image", "guard-all-got-plt-import-targets"] },
      segmentedDecryption: { status: "partial", implemented: ["authenticated-vm-records", "compatible-static-assets", "wiping-asset-streams", "wiping-network-session-keys"] }
    } : null
  };
}

function loadCards() {
  try {
    const parsed = JSON.parse(fs.readFileSync(CARDS_FILE, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

function saveCards(cards) {
  fs.writeFileSync(CARDS_FILE, JSON.stringify(cards, null, 2), "utf8");
}

function publicCard(card) {
  const now = nowSeconds();
  return {
    cardKey: card.cardKey,
    cardName: normalizeCardName(card.cardName),
    status: card.status,
    durationSeconds: card.durationSeconds,
    deviceId: card.deviceId || null,
    createdAt: card.createdAt,
    activatedAt: card.activatedAt || null,
    expiresAt: card.expiresAt || null,
    remainingSeconds: card.expiresAt ? Math.max(0, card.expiresAt - now) : null,
    lastHeartbeatAt: card.lastHeartbeatAt || null,
    appVersion: card.appVersion || "",
    note: card.note || ""
  };
}

function listCards(cardNameRaw = "") {
  const cardName = String(cardNameRaw || "").trim().toLowerCase();
  return filterCardsByName(loadCards(), cardName)
    .map((card) => {
      if (card.status === "active" && card.expiresAt && card.expiresAt <= nowSeconds()) card.status = "expired";
      return publicCard(card);
    })
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
}

function createCards(body) {
  const cards = loadCards();
  const count = Math.max(1, Math.min(200, Math.floor(Number(body.count || 1))));
  const durationSeconds = durationToSeconds(body);
  const cardName = normalizeCardName(body.cardName);
  const created = [];
  for (let i = 0; i < count; i += 1) {
    let cardKey = makeCardKey();
    while (cards.some((card) => card.cardKey === cardKey)) cardKey = makeCardKey();
    const card = {
      cardKey,
      cardName,
      status: "unused",
      durationSeconds,
      deviceId: null,
      createdAt: nowSeconds(),
      activatedAt: null,
      expiresAt: null,
      lastHeartbeatAt: null,
      appVersion: "",
      note: String(body.note || "")
    };
    cards.push(card);
    created.push(publicCard(card));
  }
  saveCards(cards);
  return { ok: true, cards: created };
}

function updateCard(cardKeyRaw, method, body) {
  const cardKey = decodeURIComponent(cardKeyRaw || "").trim().toUpperCase();
  const cards = loadCards();
  const index = cards.findIndex((card) => card.cardKey === cardKey);
  if (index < 0) return { ok: false, message: "card not found" };
  if (method === "DELETE") {
    cards.splice(index, 1);
    saveCards(cards);
    return { ok: true };
  }
  if (method !== "PATCH") return { ok: false, message: "method not allowed" };
  const card = cards[index];
  const action = String(body.action || "");
  if (action === "disable") card.status = "disabled";
  if (action === "enable") card.status = card.activatedAt ? "active" : "unused";
  if (action === "reset") {
    card.status = "unused";
    card.deviceId = null;
    card.activatedAt = null;
    card.expiresAt = null;
    card.lastHeartbeatAt = null;
    card.appVersion = "";
  }
  cards[index] = card;
  saveCards(cards);
  return { ok: true, card: publicCard(card) };
}

function deleteAllCards(cardNameRaw = "") {
  const cardName = String(cardNameRaw || "").trim().toLowerCase();
  const cards = loadCards();
  const result = deleteCardsByName(cards, cardName);
  saveCards(result.kept);
  return { ok: true, deleted: result.deleted, cardName: cardName ? String(cardNameRaw).trim() : "" };
}

function deleteCardsByName(cards, cardNameRaw = "") {
  const cardName = String(cardNameRaw || "").trim().toLowerCase();
  if (!cardName) return { kept: [], deleted: cards.length };
  const kept = cards.filter((card) => normalizeCardName(card.cardName).toLowerCase() !== cardName);
  return { kept, deleted: cards.length - kept.length };
}

function filterCardsByName(cards, cardNameRaw = "") {
  const cardName = String(cardNameRaw || "").trim().toLowerCase();
  return cards.filter((card) => !cardName || normalizeCardName(card.cardName).toLowerCase() === cardName);
}

async function adminJson(req, res, fn) {
  if ((req.headers["x-admin-token"] || "") !== LICENSE_DEFAULTS.ADMIN_TOKEN) return json(res, { ok: false, message: "admin token invalid" }, 401);
  try {
    const result = await fn();
    return json(res, result);
  } catch (error) {
    return json(res, { ok: false, message: error.message || String(error) }, 500);
  }
}

async function readJsonBody(req) {
  const file = path.join(os.tmpdir(), `body-${Date.now()}-${crypto.randomBytes(3).toString("hex")}.json`);
  await saveBody(req, file);
  const text = fs.readFileSync(file, "utf8");
  fs.unlink(file, () => {});
  return text ? JSON.parse(text) : {};
}

async function detectTools() {
  const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || path.join(os.homedir(), "AppData", "Local", "Android", "Sdk");
  const javaHome = process.env.JAVA_HOME || (fs.existsSync("D:\\android\\jbr") ? "D:\\android\\jbr" : "");
  const buildTools = newestDir(path.join(sdk, "build-tools"));
  const platform = newestDir(path.join(sdk, "platforms"));
  const ndk = newestDir(path.join(sdk, "ndk"));
  let fullVmp = "";
  let fullVmpProfile = null;
  try {
    const profile = validateFullVmprotectProfile();
    if (profile.profileType === "preprotected-apk"
        || fullVmprotectReleaseCoverage(profile) === 100) {
      fullVmp = profile.profileId;
      fullVmpProfile = summarizeFullVmprotectProfile(profile);
    }
  } catch (_) {}
  return {
    sdk,
    java: firstExisting([path.join(javaHome, "bin", "java.exe"), path.join(javaHome, "bin", "java"), "java"]),
    javac: firstExisting([path.join(javaHome, "bin", "javac.exe"), path.join(javaHome, "bin", "javac"), "javac"]),
    keytool: firstExisting([path.join(javaHome, "bin", "keytool.exe"), path.join(javaHome, "bin", "keytool"), "keytool"]),
    jar: firstExisting([path.join(javaHome, "bin", "jar.exe"), path.join(javaHome, "bin", "jar"), "jar"]),
    d8: firstExisting([path.join(buildTools || "", "d8.bat"), path.join(buildTools || "", "d8")]),
    aapt2: firstExisting([path.join(buildTools || "", "aapt2.exe"), path.join(buildTools || "", "aapt2")]),
    r8: firstExisting([path.join(buildTools || "", "lib", "d8.jar")]),
    zipalign: firstExisting([path.join(buildTools || "", "zipalign.exe"), path.join(buildTools || "", "zipalign")]),
    apksigner: firstExisting([path.join(buildTools || "", "apksigner.bat"), path.join(buildTools || "", "apksigner")]),
    androidJar: platform ? path.join(platform, "android.jar") : "",
    python: firstExisting([
      process.env.PYTHON,
      path.join(os.homedir(), "AppData", "Local", "Programs", "Python", "Python313", "python.exe"),
      "python3",
      "python"
    ]),
    ndk,
    apktool: fs.existsSync(path.join(TOOLS, `apktool_${APKTOOL_VERSION}.jar`)) ? path.join(TOOLS, `apktool_${APKTOOL_VERSION}.jar`) : "",
    vmp: "builtin-vmp-plus",
    fullVmp,
    fullVmpProfile,
    java2c: fs.existsSync(DCC_SELECTION_REGISTRY) ? "dcc-fixed-registry" : ""
  };
}

async function ensureApktool() {
  const jar = path.join(TOOLS, `apktool_${APKTOOL_VERSION}.jar`);
  if (fs.existsSync(jar)) return jar;
  const response = await fetch(APKTOOL_URL);
  if (!response.ok) throw new Error(`娑撳娴?apktool 婢惰精瑙﹂敍?{response.status}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  fs.writeFileSync(jar, buffer);
  return jar;
}

async function ensureSigningKey(tools) {
  const alias = process.env.APK_SIGNING_KEY_ALIAS || "apkshield";
  const configured = String(process.env.APK_SIGNING_KEYSTORE_B64 || "").trim();
  if (configured) {
    const storepass = String(process.env.APK_SIGNING_STORE_PASSWORD || "");
    const keypass = String(process.env.APK_SIGNING_KEY_PASSWORD || storepass);
    if (!storepass || !keypass) throw new Error("瀹告煡鍘ょ純?APK 缁涙儳鎮曟惔鎿勭礉娴ｅ棛宸辩亸鎴狀劮閸氬秴鐦戦惍?Secret");
    const keystore = path.join(TOOLS, "runtime-release-signing.p12");
    let decoded;
    try {
      decoded = Buffer.from(configured.replace(/\s+/g, ""), "base64");
    } catch (_) {
      throw new Error("APK signing metadata is invalid");
    }
    if (decoded.length < 1024) throw new Error("APK signature content is invalid");
    if (!fs.existsSync(keystore) || !fs.readFileSync(keystore).equals(decoded)) fs.writeFileSync(keystore, decoded, { mode: 0o600 });
    return { keystore, alias, storepass, keypass, source: "environment-secret" };
  }

  const keystore = path.join(TOOLS, "release-signing.p12");
  const metadataFile = path.join(TOOLS, "release-signing.json");
  if (fs.existsSync(keystore) && fs.existsSync(metadataFile)) {
    const metadata = JSON.parse(fs.readFileSync(metadataFile, "utf8"));
    if (!metadata.storepass || !metadata.keypass || !metadata.alias) throw new Error("Signing key metadata is incomplete");
    return { keystore, alias: metadata.alias, storepass: metadata.storepass, keypass: metadata.keypass, source: "local-persistent" };
  }

  const storepass = crypto.randomBytes(32).toString("hex");
  const keypass = storepass;
  await run(tools.keytool, [
    "-genkeypair",
    "-v",
    "-keystore", keystore,
    "-storetype", "PKCS12",
    "-storepass", storepass,
    "-alias", alias,
    "-keypass", keypass,
    "-keyalg", "RSA",
    "-keysize", "3072",
    "-sigalg", "SHA256withRSA",
    "-validity", "36500",
    "-dname", "CN=APK Shield Release,O=Android License Gateway,C=CN"
  ], ROOT);
  fs.writeFileSync(metadataFile, JSON.stringify({ alias, storepass, keypass, keyBits: 3072 }, null, 2), { mode: 0o600 });
  return { keystore, alias, storepass, keypass, source: "local-persistent" };
}

async function resolveV4Transport(serverUrl, expectedAppId) {
  const configOrigin = V4_CONFIG_ORIGIN || normalizeUrl(serverUrl);
  const endpoint = `${configOrigin}/api/v4/config?build=${Date.now()}`;
  let response;
  try {
    response = await fetch(endpoint, {
      headers: { accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(20000)
    });
  } catch (error) {
    throw new Error(`閺冪姵纭剁拠璇插絿瀵搫濮炵€靛棗宕楃拋顔煎彆闁姐儻绱?{error.message || error}`);
  }
  if (!response.ok) throw new Error(`瀵搫濮炵€靛棗宕楃拋顔芥弓閸氼垳鏁ら敍娆籘TP ${response.status}`);
  const config = await response.json();
  if (Number(config.v) !== 4 || config.appId !== expectedAppId || !Array.isArray(config.suites) || !config.preferredSuite) {
    throw new Error("V4 transport configuration is invalid or App ID mismatch");
  }
  const suite = config.suites.find((item) => item && item.id === config.preferredSuite && item.content === "AES-256-GCM");
  if (!suite || !suite.transportKeyId || !suite.transportPublicPem || !suite.signingKeyId || !suite.signingPublicPem) {
    throw new Error("V4 AES/RSA-4096 transport response is invalid");
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(String(suite.transportPublicPem));
  } catch (_) {
    throw new Error("RSA-4096 transport public PEM is invalid");
  }
  const bits = publicKey.asymmetricKeyDetails && publicKey.asymmetricKeyDetails.modulusLength;
  if (publicKey.asymmetricKeyType !== "rsa" || !bits || bits < 4096) {
    throw new Error("閺堝秴濮熼崳銊ょ炊鏉堟挸鐦戦柦銉ュ繁鎼达缚绗夌搾绛圭礉韫囧懘銆忔担璺ㄦ暏 RSA-4096");
  }
  let signingKey;
  try {
    signingKey = crypto.createPublicKey(String(suite.signingPublicPem));
  } catch (_) {
    throw new Error("RSA-PSS-4096 signing PEM is invalid");
  }
  const signingBits = signingKey.asymmetricKeyDetails && signingKey.asymmetricKeyDetails.modulusLength;
  if (signingKey.asymmetricKeyType !== "rsa" || !signingBits || signingBits < 4096) {
    throw new Error("閺堝秴濮熼崳銊ь劮閸氬秴鐦戦柦銉ュ繁鎼达缚绗夌搾绛圭礉韫囧懘銆忔担璺ㄦ暏 RSA-PSS-4096");
  }
  const tlsPinPolicy = await resolveTlsPinPolicy(config, serverUrl);
  return {
    suiteId: String(suite.id),
    keyId: String(suite.transportKeyId),
    publicKey: String(suite.transportPublicPem),
    modulusLength: bits,
    signingKeyId: String(suite.signingKeyId),
    signingPublicKey: String(suite.signingPublicPem),
    tlsPinHost: tlsPinPolicy.host,
    tlsPins: tlsPinPolicy.pins
  };
}

function normalizeSpkiPins(values) {
  const pins = [];
  for (const value of Array.isArray(values) ? values : []) {
    const pin = String(value || "").trim();
    if (/^sha256\/[A-Za-z0-9+/]{43}=$/.test(pin) && !pins.includes(pin)) pins.push(pin);
  }
  return pins;
}

async function resolveTlsPinPolicy(config, serverUrl) {
  const server = new URL(normalizeUrl(serverUrl));
  if (server.protocol !== "https:") return { host: "", pins: [] };
  const configured = config && config.tlsPinPolicy;
  if (configured && String(configured.host || "").toLowerCase() === server.hostname.toLowerCase()) {
    const pins = normalizeSpkiPins(configured.pins);
    if (pins.length >= 2) return { host: server.hostname.toLowerCase(), pins };
  }
  return discoverTlsSpkiPins(server);
}

function discoverTlsSpkiPins(url) {
  return new Promise((resolve, reject) => {
    const pins = [];
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      rejectUnauthorized: true
    });
    const fail = (error) => { socket.destroy(); reject(new Error(`TLS pin discovery failed: ${error.message || error}`)); };
    socket.setTimeout(20000, () => fail(new Error("timeout")));
    socket.once("error", fail);
    socket.once("secureConnect", () => {
      try {
        let certificate = socket.getPeerCertificate(true);
        const visited = new Set();
        while (certificate && certificate.raw) {
          const fingerprint = Buffer.from(certificate.raw).toString("hex");
          if (visited.has(fingerprint)) break;
          visited.add(fingerprint);
          const publicKey = new crypto.X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" });
          const pin = `sha256/${crypto.createHash("sha256").update(publicKey).digest("base64")}`;
          if (!pins.includes(pin)) pins.push(pin);
          if (!certificate.issuerCertificate || certificate.issuerCertificate === certificate) break;
          certificate = certificate.issuerCertificate;
        }
        socket.end();
        if (!pins.length) throw new Error("empty certificate chain");
        resolve({ host: url.hostname.toLowerCase(), pins });
      } catch (error) {
        fail(error);
      }
    });
  });
}

async function signingCertificateInfo(tools, signing) {
  const pem = await runCapture(tools.keytool, [
    "-exportcert",
    "-rfc",
    "-keystore", signing.keystore,
    "-storepass", signing.storepass,
    "-alias", signing.alias
  ], ROOT);
  const cert = new crypto.X509Certificate(pem);
  const details = cert.publicKey.asymmetricKeyDetails || {};
  return {
    sha256: cert.fingerprint256.replace(/:/g, "").toLowerCase(),
    algorithm: String(cert.publicKey.asymmetricKeyType || "unknown").toUpperCase(),
    keyBits: Number(details.modulusLength || 0)
  };
}

function readPackageName(manifest) {
  const match = manifest.match(/<manifest[\s\S]*?\spackage="([^"]+)"/);
  if (!match) throw new Error("Could not read APK package name");
  return match[1];
}

function readLauncherActivity(manifest, packageName) {
  const activityRegex = /<activity\b[\s\S]*?<\/activity>/g;
  let match;
  while ((match = activityRegex.exec(manifest))) {
    const block = match[0];
    if (block.includes("android.intent.action.MAIN") && block.includes("android.intent.category.LAUNCHER")) {
      const name = (block.match(/android:name="([^"]+)"/) || [])[1];
      if (!name) break;
      return normalizeActivityName(name, packageName);
    }
  }
  throw new Error("濞屸剝婀侀幍鎯у煂閸?APP 閸氼垰濮?Activity");
}

function removeLauncherFilters(manifest) {
  return manifest.replace(/<intent-filter>[\s\S]*?android\.intent\.action\.MAIN[\s\S]*?android\.intent\.category\.LAUNCHER[\s\S]*?<\/intent-filter>/g, "");
}

function addInternetPermission(manifest) {
  if (manifest.includes('android.permission.INTERNET')) return manifest;
  return manifest.replace(/<application\b/, '    <uses-permission android:name="android.permission.INTERNET" />\n\n    <application');
}

function configureCleartext(manifest, serverUrl) {
  if (!String(serverUrl || "").startsWith("http://")) return manifest;
  if (/android:usesCleartextTraffic\s*=/.test(manifest)) {
    return manifest.replace(/android:usesCleartextTraffic\s*=\s*"[^"]*"/, 'android:usesCleartextTraffic="true"');
  }
  return manifest.replace(/<application\b/, '<application android:usesCleartextTraffic="true"');
}

function addLicenseComponents(manifest, packageName) {
  const authority = `${packageName}.license.guard.${crypto.createHash("sha256").update(packageName).digest("hex").slice(0, 12)}`;
  const components = `
        <provider android:name=".LicenseGuardProvider" android:authorities="${authority}" android:exported="false" android:initOrder="2147483647" />
        <activity android:name=".LicenseActivity" android:theme="@android:style/Theme.Material.NoActionBar" android:screenOrientation="portrait" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
`;
  return manifest.replace(/<\/application>/, `${components}    </application>`);
}

function hardenManifest(manifest) {
  const cleaned = manifest
    .replace(/\sandroid:debuggable="(?:true|false)"/g, "")
    .replace(/\sandroid:testOnly="(?:true|false)"/g, "")
    .replace(/\sandroid:allowBackup="(?:true|false)"/g, "")
    .replace(/\sandroid:fullBackupContent="[^"]*"/g, "");
  return cleaned.replace(/<application\b/, '<application android:debuggable="false" android:testOnly="false" android:allowBackup="false"');
}

function injectNativeGuard(decodedDir, nativeLibs = NATIVE_LIBS) {
  const supportedAbis = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"];
  const libRoot = path.join(decodedDir, "lib");
  const existingAbis = fs.existsSync(libRoot)
    ? fs.readdirSync(libRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && supportedAbis.includes(entry.name))
      .map((entry) => entry.name)
    : [];
  const abis = existingAbis.length ? existingAbis : supportedAbis;
  for (const abi of abis) {
    const source = path.join(nativeLibs, abi, "liblicenseguard.so");
    if (!fs.existsSync(source)) throw new Error(`缂傚搫鐨?Native 鐎瑰牆宕兼惔鎿勭窗${abi}`);
    const destinationDir = path.join(decodedDir, "lib", abi);
    fs.mkdirSync(destinationDir, { recursive: true });
    fs.copyFileSync(source, path.join(destinationDir, "liblicenseguard.so"));
  }
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function nativeGuardIntegrityEntries(decodedDir) {
  const libRoot = path.join(decodedDir, "lib");
  if (!fs.existsSync(libRoot)) return [];
  return fs.readdirSync(libRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const file = path.join(libRoot, entry.name, "liblicenseguard.so");
      return fs.existsSync(file)
        ? { name: `lib/${entry.name}/liblicenseguard.so`, sha256: sha256File(file) }
        : null;
    })
    .filter(Boolean)
    .sort((left, right) => left.name.localeCompare(right.name));
}

function safeChildPath(root, relative) {
  const base = path.resolve(root);
  const candidate = path.resolve(base, String(relative || ""));
  const relation = path.relative(base, candidate);
  if (!relation || relation.startsWith("..") || path.isAbsolute(relation)) {
    throw new Error("DCC selection path must stay inside dex_toolchain");
  }
  return candidate;
}

function loadDccSelectionRegistry(registryFile = DCC_SELECTION_REGISTRY) {
  if (!fs.existsSync(registryFile)) return { schemaVersion: 1, profiles: [] };
  const parsed = JSON.parse(fs.readFileSync(registryFile, "utf8").replace(/^\uFEFF/, ""));
  if (parsed.schema_version !== 1 || !Array.isArray(parsed.profiles)) {
    throw new Error("Unsupported DCC selection registry");
  }
  const hashes = new Set();
  const profiles = parsed.profiles.map((row) => {
    const id = String(row.id || "");
    const inputApkSha256 = String(row.input_apk_sha256 || "").toLowerCase();
    const selectionSha256 = String(row.selection_sha256 || "").toLowerCase();
    const libraryName = String(row.library_name || "");
    const androidApi = Number(row.android_api);
    if (!/^[A-Za-z0-9_.-]+$/.test(id)
        || !/^[0-9a-f]{64}$/.test(inputApkSha256)
        || !/^[0-9a-f]{64}$/.test(selectionSha256)
        || !/^[A-Za-z0-9_.-]+$/.test(libraryName)
        || !Number.isSafeInteger(androidApi)
        || androidApi < 23
        || androidApi > 36) {
      throw new Error(`Invalid DCC selection profile: ${id || "<missing-id>"}`);
    }
    if (hashes.has(inputApkSha256)) {
      throw new Error(`Duplicate DCC input APK hash: ${inputApkSha256}`);
    }
    hashes.add(inputApkSha256);
    const selection = safeChildPath(DCC_TOOLCHAIN_ROOT, row.selection);
    if (!fs.existsSync(selection) || sha256File(selection) !== selectionSha256) {
      throw new Error(`DCC selection integrity failed: ${id}`);
    }
    return { id, inputApkSha256, selection, selectionSha256, libraryName, androidApi };
  });
  return { schemaVersion: 1, profiles };
}

function resolveDccJava2cProfile(inputApk, registryFile = DCC_SELECTION_REGISTRY) {
  const digest = sha256File(inputApk);
  return loadDccSelectionRegistry(registryFile).profiles.find(
    (profile) => profile.inputApkSha256 === digest
  ) || null;
}

async function applyDccJava2c(tools, inputApk, decodedDir, jobDir, profile) {
  if (!tools.python || !tools.ndk) {
    throw new Error("DCC Java2C requires Python and Android NDK");
  }
  const root = path.join(jobDir, "dcc-java2c");
  const sources = path.join(root, "sources");
  const library = path.join(root, `lib${profile.libraryName}.so`);
  const compileReport = path.join(root, "compile.json");
  const buildReport = path.join(root, "build-arm64.json");
  const patchReport = path.join(root, "patch-decoded.json");
  fs.mkdirSync(root, { recursive: true });
  await run(tools.python, [
    "-B", "-m", "dex_toolchain.dcc_compile", "compile",
    "--input", inputApk,
    "--selection", profile.selection,
    "--out-dir", sources,
    "--report", compileReport
  ], DCC_ROOT);
  await run(tools.python, [
    "-B", "-m", "dex_toolchain.dcc_compile", "build-arm64",
    "--compile-report", compileReport,
    "--source-dir", sources,
    "--output", library,
    "--report", buildReport,
    "--ndk", tools.ndk,
    "--api", String(profile.androidApi)
  ], DCC_ROOT);
  await run(tools.python, [
    "-B", "-m", "dex_toolchain.dcc_compile", "patch-decoded",
    "--decoded-dir", decodedDir,
    "--compile-report", compileReport,
    "--build-report", buildReport,
    "--report", patchReport,
    "--library-name", profile.libraryName
  ], DCC_ROOT);
  const compileEvidence = JSON.parse(fs.readFileSync(compileReport, "utf8"));
  const buildEvidence = JSON.parse(fs.readFileSync(buildReport, "utf8"));
  const patchEvidence = JSON.parse(fs.readFileSync(patchReport, "utf8"));
  if (!compileEvidence.summary.gate_passed
      || !buildEvidence.summary.gate_passed
      || !patchEvidence.summary.gate_passed) {
    throw new Error(`DCC Java2C gate failed: ${profile.id}`);
  }
  return {
    applied: true,
    reason: "fixed-dcc-java2c",
    profileId: profile.id,
    libraryName: profile.libraryName,
    compiledMethods: compileEvidence.summary.compiled_methods,
    librarySha256: buildEvidence.output_sha256,
    compileReport,
    buildReport,
    patchReport
  };
}

async function verifyDccJava2cApk(tools, apk, jobDir, buildId, state) {
  const verifyReport = path.join(jobDir, "dcc-java2c", "verify-apk.json");
  await run(tools.python, [
    "-B", "-m", "dex_toolchain.dcc_compile", "verify-apk",
    "--apk", apk,
    "--compile-report", state.compileReport,
    "--build-report", state.buildReport,
    "--patch-report", state.patchReport,
    "--report", verifyReport
  ], DCC_ROOT);
  const evidence = JSON.parse(fs.readFileSync(verifyReport, "utf8"));
  if (!evidence.summary.gate_passed) {
    throw new Error(`Final APK DCC Java2C gate failed: ${state.profileId}`);
  }
  const reports = [state.compileReport, state.buildReport, state.patchReport, verifyReport];
  const privateReports = reports.map((source) => {
    const name = `${buildId}-dcc-${path.basename(source)}`;
    fs.copyFileSync(source, path.join(PRIVATE_ARTIFACTS, name));
    return { name, sha256: sha256File(source) };
  });
  return {
    applied: true,
    reason: state.reason,
    profileId: state.profileId,
    libraryName: state.libraryName,
    compiledMethods: state.compiledMethods,
    verifiedMethods: evidence.summary.verified_methods,
    librarySha256: state.librarySha256,
    finalGatePassed: true,
    privateReports
  };
}

function fullVmprotectReleaseCoverage(profile) {
  const virtualized = profile.virtualizedInstructions;
  const decoded = profile.totalSelectedArm64Instructions;
  return profile.fullVirtualizationGatePassed === true
    && Number.isSafeInteger(virtualized)
    && Number.isSafeInteger(decoded)
    && decoded > 0
    && virtualized === decoded
    ? 100
    : 0;
}

function summarizeFullVmprotectProfile(profile) {
  if (profile.profileType === "preprotected-apk") {
    return {
      profileId: profile.profileId,
      profileVersion: profile.profileVersion,
      profileStatus: profile.status,
      profileType: profile.profileType,
      abi: profile.abi,
      packageName: profile.packageName,
      verifiedMethods: profile.verifiedMethods,
      totalMethods: profile.totalMethods,
      virtualizedInstructions: profile.virtualizedInstructions,
      totalDexInstructions: profile.totalDexInstructions,
      coveragePolicy: profile.coveragePolicy,
      observedCoveragePercent: profile.observedCoveragePercent,
      releaseCoveragePercent: fullVmprotectReleaseCoverage(profile),
      fullVirtualizationGatePassed: profile.fullVirtualizationGatePassed,
      protectedApkSha256: profile.protectedApkSha256,
      deviceEvidenceSha256: profile.deviceEvidenceSha256,
      sourceCoverageReportSha256: profile.sourceCoverageReportSha256
    };
  }
  const diagnosticInstructionCoveragePercent = Number(
    (profile.virtualizedInstructions * 100 / profile.totalSelectedArm64Instructions).toFixed(8)
  );
  return {
    profileId: profile.profileId,
    profileStatus: profile.status,
    profileType: "native-library",
    abi: profile.abi,
    installedFunctions: profile.installedFunctions,
    virtualizedInstructions: profile.virtualizedInstructions,
    totalSelectedArm64Instructions: profile.totalSelectedArm64Instructions,
    coveragePolicy: "whole-apk-binary-0-or-100",
    observedCoveragePercent: diagnosticInstructionCoveragePercent,
    releaseCoveragePercent: fullVmprotectReleaseCoverage(profile),
    instructionCoveragePercent: fullVmprotectReleaseCoverage(profile),
    diagnosticInstructionCoveragePercent,
    fullVirtualizationGatePassed: profile.fullVirtualizationGatePassed
  };
}

function validateFullVmprotectProfile(profileDir = FULL_VMP_PROFILE_DIR) {
  const profileFile = path.join(profileDir, "profile.json");
  if (!fs.existsSync(profileFile)) {
    throw new Error("Full VMProtect profile metadata is missing");
  }
  const profile = JSON.parse(
    fs.readFileSync(profileFile, "utf8").replace(/^\uFEFF/, "")
  );
  if (![1, 2].includes(profile.schemaVersion) || profile.abi !== "arm64-v8a") {
    throw new Error("Unsupported Full VMProtect profile");
  }
  const preprotected = profile.schemaVersion === 2
    && profile.profileType === "preprotected-apk";
  const artifacts = preprotected
    ? [
        [profile.protectedApk, profile.protectedApkSha256],
        [profile.deviceEvidence, profile.deviceEvidenceSha256],
        [profile.coverageSummary, profile.coverageSummarySha256]
      ]
    : [
        [profile.patchedLibrary, profile.patchedLibrarySha256],
        [profile.runtimeLibrary, profile.runtimeLibrarySha256]
      ];
  for (const [name, expected] of artifacts) {
    if (typeof name !== "string" || !/^[A-Za-z0-9_.+-]+$/.test(name)
        || typeof expected !== "string" || !/^[a-f0-9]{64}$/.test(expected)) {
      throw new Error("Invalid Full VMProtect artifact name");
    }
    const artifact = path.join(profileDir, name);
    if (!fs.existsSync(artifact) || sha256File(artifact) !== expected) {
      throw new Error(`Full VMProtect artifact integrity failed: ${name}`);
    }
  }
  if (preprotected) {
    const safeIntegerFields = [
      "verifiedMethods",
      "totalMethods",
      "virtualizedInstructions",
      "totalDexInstructions"
    ];
    if (!/^[a-f0-9]{64}$/.test(profile.sourceApkSha256 || "")
        || !/^[a-f0-9]{64}$/.test(profile.sourceCoverageReportSha256 || "")
        || safeIntegerFields.some((name) => !Number.isSafeInteger(profile[name]) || profile[name] < 0)
        || profile.verifiedMethods > profile.totalMethods
        || profile.virtualizedInstructions > profile.totalDexInstructions
        || !Array.isArray(profile.protectedEntries)
        || profile.protectedEntries.length === 0) {
      throw new Error("Invalid preprotected APK profile metadata");
    }
    const expectedCoverage = Number(
      (profile.virtualizedInstructions * 100 / profile.totalDexInstructions).toFixed(7)
    );
    if (profile.observedCoveragePercent !== expectedCoverage) {
      throw new Error("Preprotected APK coverage metadata is inconsistent");
    }
    const entryNames = new Set();
    for (const item of profile.protectedEntries) {
      if (!item || typeof item.entry !== "string" || item.entry.startsWith("/")
          || item.entry.includes("..") || entryNames.has(item.entry)
          || !/^[a-f0-9]{64}$/.test(item.sha256 || "")) {
        throw new Error("Invalid preprotected APK entry metadata");
      }
      entryNames.add(item.entry);
    }
    const coverage = JSON.parse(
      fs.readFileSync(path.join(profileDir, profile.coverageSummary), "utf8").replace(/^\uFEFF/, "")
    );
    const evidence = JSON.parse(
      fs.readFileSync(path.join(profileDir, profile.deviceEvidence), "utf8").replace(/^\uFEFF/, "")
    );
    if (coverage.sourceReportSha256 !== profile.sourceCoverageReportSha256
        || coverage.sourceApkSha256 !== profile.sourceApkSha256
        || coverage.protectedApkSha256 !== profile.protectedApkSha256
        || coverage.verifiedMethods !== profile.verifiedMethods
        || coverage.totalMethods !== profile.totalMethods
        || coverage.verifiedInstructions !== profile.virtualizedInstructions
        || coverage.totalInstructions !== profile.totalDexInstructions
        || coverage.observedCoveragePercent !== profile.observedCoveragePercent
        || coverage.fullVirtualizationGatePassed !== profile.fullVirtualizationGatePassed
        || evidence.target_apk_sha256 !== profile.protectedApkSha256
        || evidence.differential_target_count !== profile.verifiedMethods
        || evidence.differential_instruction_count !== profile.virtualizedInstructions
        || evidence.restored_ok !== true
        || evidence.tamper_rejected !== true) {
      throw new Error("Preprotected APK evidence metadata is inconsistent");
    }
  }
  return profile;
}

function prepareFullVmprotectInput(inputApk, profileDir = FULL_VMP_PROFILE_DIR) {
  const profile = validateFullVmprotectProfile(profileDir);
  if (profile.profileType !== "preprotected-apk") {
    throw new Error("Full VMProtect profile is not a preprotected APK profile");
  }
  const inputSha256 = sha256File(inputApk);
  if (inputSha256 !== profile.sourceApkSha256) {
    throw new Error(
      `Full VMProtect stable profile input mismatch: expected ${profile.sourceApkSha256}, got ${inputSha256}`
    );
  }
  return {
    protectedApk: path.join(profileDir, profile.protectedApk),
    summary: summarizeFullVmprotectProfile(profile)
  };
}

function injectFullVmprotect(decodedDir, profileDir = FULL_VMP_PROFILE_DIR) {
  const profile = validateFullVmprotectProfile(profileDir);
  if (profile.profileType === "preprotected-apk") {
    throw new Error("Preprotected APK profiles must be selected before APK decoding");
  }
  const releaseCoveragePercent = fullVmprotectReleaseCoverage(profile);
  if (releaseCoveragePercent !== 100) {
    throw new Error(
      `Full VMProtect release gate failed for ${profile.profileId}: release coverage 0%`
    );
  }
  const abiDir = path.join(decodedDir, "lib", profile.abi);
  const source = path.join(abiDir, profile.sourceLibrary);
  if (!fs.existsSync(source)) {
    throw new Error(`Full VMProtect profile requires ${profile.abi}/${profile.sourceLibrary}`);
  }
  const sourceSha256 = sha256File(source);
  if (sourceSha256 !== profile.sourceLibrarySha256) {
    throw new Error(
      `Full VMProtect profile input mismatch: expected ${profile.sourceLibrarySha256}, got ${sourceSha256}`
    );
  }
  const runtimeSource = path.join(profileDir, profile.runtimeLibrary);
  const patchedSource = path.join(profileDir, profile.patchedLibrary);
  const runtimeDestination = path.join(abiDir, profile.runtimeLibrary);
  const patchedDestination = path.join(abiDir, profile.sourceLibrary);
  fs.copyFileSync(runtimeSource, runtimeDestination);
  fs.copyFileSync(patchedSource, patchedDestination);
  if (sha256File(runtimeDestination) !== profile.runtimeLibrarySha256
      || sha256File(patchedDestination) !== profile.patchedLibrarySha256) {
    throw new Error("Full VMProtect staged artifact integrity failed");
  }
  return summarizeFullVmprotectProfile(profile);
}

async function verifyFullVmprotectApkArtifacts(
  apk,
  jobDir,
  profileDir = FULL_VMP_PROFILE_DIR
) {
  const profile = validateFullVmprotectProfile(profileDir);
  if (profile.profileType !== "preprotected-apk"
      && fullVmprotectReleaseCoverage(profile) !== 100) {
    throw new Error(
      `Full VMProtect release gate failed for ${profile.profileId}: release coverage 0%`
    );
  }
  const expected = profile.profileType === "preprotected-apk"
    ? profile.protectedEntries
    : [
        {
          entry: `lib/${profile.abi}/${profile.runtimeLibrary}`,
          sha256: profile.runtimeLibrarySha256
        },
        {
          entry: `lib/${profile.abi}/${profile.sourceLibrary}`,
          sha256: profile.patchedLibrarySha256
        }
      ];
  const entries = await zipList(apk);
  for (const item of expected) {
    if (entries.filter((entry) => entry === item.entry).length !== 1) {
      throw new Error(`Final APK must contain exactly one ${item.entry}`);
    }
  }
  const extractDir = path.join(jobDir, "full-vmp-final-verification");
  fs.mkdirSync(extractDir, { recursive: true });
  await run(
    jarCommand(),
    ["xf", apk, ...expected.map((item) => item.entry)],
    extractDir
  );
  for (const item of expected) {
    const actual = sha256File(path.join(extractDir, ...item.entry.split("/")));
    if (actual !== item.sha256) {
      throw new Error(`Final APK VMProtect artifact integrity failed: ${item.entry}`);
    }
  }
  return {
    profileId: profile.profileId,
    profileType: profile.profileType || "native-library",
    entries: expected
  };
}

async function verifyExperimentalFullVmprotectApkArtifacts(
  apk,
  jobDir,
  profileDir = FULL_VMP_PROFILE_DIR
) {
  const profile = validateFullVmprotectProfile(profileDir);
  if (profile.profileType !== "preprotected-apk") {
    throw new Error("Experimental Full VMProtect rebuild requires a preprotected APK profile");
  }
  const entries = await zipList(apk);
  assertUniqueArchiveEntries(entries);
  const dexEntries = profile.protectedEntries.filter((item) => /^classes\d*\.dex$/.test(item.entry));
  const nativeEntries = profile.protectedEntries.filter((item) => item.entry.startsWith("lib/"));
  for (const item of [...dexEntries, ...nativeEntries]) {
    if (entries.filter((entry) => entry === item.entry).length !== 1) {
      throw new Error(`Experimental APK must contain exactly one ${item.entry}`);
    }
  }
  const extractDir = path.join(jobDir, "full-vmp-experimental-verification");
  fs.mkdirSync(extractDir, { recursive: true });
  await run(jarCommand(), ["xf", apk, ...nativeEntries.map((item) => item.entry)], extractDir);
  for (const item of nativeEntries) {
    const actual = sha256File(path.join(extractDir, ...item.entry.split("/")));
    if (actual !== item.sha256) {
      throw new Error(`Experimental APK changed native VMProtect artifact: ${item.entry}`);
    }
  }
  return {
    profileId: profile.profileId,
    profileType: profile.profileType,
    evidenceStatus: "experimental-rebuilt-dex-unpromoted",
    dexEntries: dexEntries.map((item) => item.entry),
    nativeEntries
  };
}

function verifyApkSignatureOutput(output, expectedCertificateSha256) {
  const text = String(output || "");
  const v2 = /Verified using v2 scheme \(APK Signature Scheme v2\): true/i.test(text);
  const v3 = /Verified using v3 scheme \(APK Signature Scheme v3\): true/i.test(text);
  if (!v2 || !v3) {
    throw new Error("Final APK must verify with both v2 and v3 signature schemes");
  }
  const match = text.match(/Signer #1 certificate SHA-256 digest:\s*([0-9a-f]{64})/i);
  const actual = match ? match[1].toLowerCase() : "";
  const expected = String(expectedCertificateSha256 || "").toLowerCase();
  if (!actual || actual !== expected) {
    throw new Error("Final APK signing certificate SHA-256 mismatch");
  }
  return { v2, v3, certificateSha256: actual };
}

function normalizeActivityName(name, packageName) {
  if (name.startsWith(".")) return packageName + name;
  if (!name.includes(".")) return packageName + "." + name;
  return name;
}

function normalizeOptionalUrl(value) {
  let u = (value || "").trim();
  if (!u) return "";
  if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;
  return u;
}

function normalizeOptionalText(value) {
  return (value || "").trim().replace(/\s+/g, " ").slice(0, 32);
}

function normalizeCardName(value) {
  return (value || "姒涙顓绘潪顖欐").trim().replace(/\s+/g, " ").slice(0, 48) || "姒涙顓绘潪顖欐";
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function makeCardKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let raw = "";
  for (let i = 0; i < 16; i += 1) raw += alphabet[crypto.randomInt(alphabet.length)];
  return raw.replace(/(.{4})/g, "$1-").replace(/-$/, "");
}

function durationToSeconds(body) {
  if (Number.isFinite(Number(body.durationSeconds)) && Number(body.durationSeconds) > 0) {
    return Math.floor(Number(body.durationSeconds));
  }
  const amount = Math.max(1, Math.floor(Number(body.duration || 1)));
  const unit = String(body.unit || "day");
  const map = { minute: 60, hour: 3600, day: 86400, month: 2592000, year: 31536000 };
  return amount * (map[unit] || map.day);
}

function writeJavaSources(root, packageName, launcher, serverUrl, appId, suiteId, keyId, serverPublicKey, serverSigningKeyId, serverSigningPublicKey, buildId, signingCertSha256, cardName, purchaseUrl, jumpText, jumpUrl, useVmp, strictGuard, dexHashes, tlsPinHost = "", tlsPins = [], immutableManifest = {}, assetProtection = {}, nativeGuardEntries = []) {
  const dir = path.join(root, ...packageName.split("."));
  fs.mkdirSync(dir, { recursive: true });
  const pkg = `package ${packageName};`;
  const stringKey = (crypto.randomBytes(1)[0] || 91) & 255;
  const vmKey = (crypto.randomBytes(1)[0] || 167) & 255;
  const encoded = (value, key = stringKey) => {
    const bytes = Buffer.from(String(value), "utf8");
    for (let i = 0; i < bytes.length; i++) bytes[i] ^= key;
    return bytes.toString("base64");
  };
  const configString = (name, value) => useVmp
    ? `  static final String ${name} = VmpRuntime.s("${encoded(value)}", ${stringKey});`
    : `  static final String ${name} = "${javaString(value)}";`;
  const vmOpcodeValues = new Set();
  while (vmOpcodeValues.size < 5) vmOpcodeValues.add(1 + crypto.randomBytes(1)[0] % 120);
  const [vmOk, vmCode, vmExpiry, vmAnd, vmReturn] = [...vmOpcodeValues];
  const vmProgram = encoded(Buffer.from([vmOk, vmCode, vmAnd, vmExpiry, vmAnd, vmReturn]).toString("latin1"), vmKey);
  const dexNames = (dexHashes || []).map((item) => `"${javaString(item.name)}"`).join(",");
  const dexValues = (dexHashes || []).map((item) => `"${item.sha256}"`).join(",");
  const nativeNames = nativeGuardEntries.map((item) => `"${javaString(item.name)}"`).join(",");
  const nativeValues = nativeGuardEntries.map((item) => `"${item.sha256}"`).join(",");
  const tlsPinValues = normalizeSpkiPins(tlsPins).map((pin) => `"${javaString(pin)}"`).join(",");
  const immutableRoot = String(immutableManifest.root || "");
  const immutableCount = Math.max(0, Number(immutableManifest.count || 0));
  const generatedDexName = String(immutableManifest.generatedDexName || "");
  const assetEntries = Array.isArray(assetProtection.entries) ? assetProtection.entries : [];
  const protectedAssetPaths = assetEntries.map((item) => `"${javaString(item.path)}"`).join(",");
  const protectedAssetFiles = assetEntries.map((item) => `"${javaString(item.stored)}"`).join(",");
  const protectedAssetSizes = assetEntries.map((item) => Math.max(0, Number(item.size || 0))).join(",");
  const protectedAssetHashes = assetEntries.map((item) => `"${javaString(item.sha256)}"`).join(",");
  const playProjectText = String(process.env.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER || "0").trim();
  if (!/^\d{1,20}$/.test(playProjectText)) throw new Error("Play Integrity cloud project number is invalid");
  fs.writeFileSync(path.join(dir, "LicenseResult.java"), `${pkg}
final class LicenseResult {
  final boolean ok; final int code; final String message; final long expiresAt; final long remainingSeconds; final long nextHeartbeatSeconds; final String leaseData; final String leaseSignature;
  LicenseResult(boolean ok, int code, String message, long expiresAt, long remainingSeconds, long nextHeartbeatSeconds, String leaseData, String leaseSignature) {
    this.ok = ok; this.code = code; this.message = message; this.expiresAt = expiresAt; this.remainingSeconds = remainingSeconds; this.nextHeartbeatSeconds = nextHeartbeatSeconds; this.leaseData = leaseData; this.leaseSignature = leaseSignature;
  }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "NationalCrypto.java"), `${pkg}
import java.nio.charset.StandardCharsets;
final class NationalCrypto {
  private static final int[] IV={0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e};
  private static final String ABC="66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
  private NationalCrypto(){}
  static boolean selfTest(){return ABC.equals(hex(digest("abc".getBytes(StandardCharsets.US_ASCII))));}
  static String bind(String value){return hex(digest(value.getBytes(StandardCharsets.UTF_8)));}
  static byte[] digest(byte[] input){
    long bits=((long)input.length)*8L;int total=((input.length+9+63)/64)*64;byte[] padded=new byte[total];System.arraycopy(input,0,padded,0,input.length);padded[input.length]=(byte)0x80;for(int i=0;i<8;i++)padded[total-1-i]=(byte)(bits>>>(8*i));
    int[] v=IV.clone(),w=new int[68],x=new int[64];
    for(int off=0;off<total;off+=64){for(int j=0;j<16;j++){int p=off+j*4;w[j]=((padded[p]&255)<<24)|((padded[p+1]&255)<<16)|((padded[p+2]&255)<<8)|(padded[p+3]&255);}for(int j=16;j<68;j++)w[j]=p1(w[j-16]^w[j-9]^rol(w[j-3],15))^rol(w[j-13],7)^w[j-6];for(int j=0;j<64;j++)x[j]=w[j]^w[j+4];int a=v[0],b=v[1],c=v[2],d=v[3],e=v[4],f=v[5],g=v[6],h=v[7];for(int j=0;j<64;j++){int t=j<16?0x79cc4519:0x7a879d8a;int ss1=rol(rol(a,12)+e+rol(t,j),7),ss2=ss1^rol(a,12);int tt1=ff(a,b,c,j)+d+ss2+x[j],tt2=gg(e,f,g,j)+h+ss1+w[j];d=c;c=rol(b,9);b=a;a=tt1;h=g;g=rol(f,19);f=e;e=p0(tt2);}v[0]^=a;v[1]^=b;v[2]^=c;v[3]^=d;v[4]^=e;v[5]^=f;v[6]^=g;v[7]^=h;}
    byte[] out=new byte[32];for(int i=0;i<8;i++){out[i*4]=(byte)(v[i]>>>24);out[i*4+1]=(byte)(v[i]>>>16);out[i*4+2]=(byte)(v[i]>>>8);out[i*4+3]=(byte)v[i];}return out;
  }
  private static int ff(int x,int y,int z,int j){return j<16?x^y^z:(x&y)|(x&z)|(y&z);}
  private static int gg(int x,int y,int z,int j){return j<16?x^y^z:(x&y)|(~x&z);}
  private static int p0(int x){return x^rol(x,9)^rol(x,17);}private static int p1(int x){return x^rol(x,15)^rol(x,23);}private static int rol(int x,int n){n&=31;return (x<<n)|(x>>>(32-n));}
  static String hex(byte[] data){char[] table="0123456789abcdef".toCharArray(),out=new char[data.length*2];for(int i=0;i<data.length;i++){int v=data[i]&255;out[i*2]=table[v>>>4];out[i*2+1]=table[v&15];}return new String(out);}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "PlayIntegrity.java"), `${pkg}
import android.content.Context; import android.util.Base64; import org.json.JSONObject; import java.lang.reflect.*; import java.nio.charset.StandardCharsets; import java.security.MessageDigest; import java.util.concurrent.TimeUnit;
final class PlayIntegrity {
  private PlayIntegrity(){}
  static JSONObject collect(Context context,String requestNonce,long timestamp){JSONObject out=new JSONObject();try{String binding=bind(requestNonce,timestamp);out.put("binding",binding);if(LicenseConfig.PLAY_CLOUD_PROJECT_NUMBER<=0){out.put("status","unconfigured");return out;}Class<?> factory=Class.forName("com.google.android.play.core.integrity.IntegrityManagerFactory");Class<?> requestClass=Class.forName("com.google.android.play.core.integrity.IntegrityTokenRequest");Object manager=factory.getMethod("create",Context.class).invoke(null,context);Object builder=requestClass.getMethod("builder").invoke(null);builder.getClass().getMethod("setNonce",String.class).invoke(builder,binding);builder.getClass().getMethod("setCloudProjectNumber",long.class).invoke(builder,LicenseConfig.PLAY_CLOUD_PROJECT_NUMBER);Object request=builder.getClass().getMethod("build").invoke(builder);Object task=manager.getClass().getMethod("requestIntegrityToken",requestClass).invoke(manager,request);Class<?> taskClass=Class.forName("com.google.android.gms.tasks.Task");Class<?> tasksClass=Class.forName("com.google.android.gms.tasks.Tasks");Object response=tasksClass.getMethod("await",taskClass,long.class,TimeUnit.class).invoke(null,task,15L,TimeUnit.SECONDS);String token=String.valueOf(response.getClass().getMethod("token").invoke(response));if(token.length()<32)throw new SecurityException("empty token");out.put("status","token");out.put("token",token);return out;}catch(Throwable error){try{out.put("status","unavailable");out.put("reason",root(error).getClass().getSimpleName());}catch(Throwable ignored){}return out;}}
  private static String bind(String nonce,long ts)throws Exception{String value="PLAY-INTEGRITY-1\\n"+LicenseConfig.APP_ID+"\\n"+LicenseConfig.BUILD_ID+"\\n"+ts+"\\n"+nonce;byte[] digest=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));return Base64.encodeToString(digest,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING);}
  private static Throwable root(Throwable error){while(error instanceof InvocationTargetException&&((InvocationTargetException)error).getTargetException()!=null)error=((InvocationTargetException)error).getTargetException();return error;}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "RuntimeRisk.java"), `${pkg}
import android.app.*; import android.content.*; import android.content.pm.*; import android.net.*; import android.os.*; import android.provider.Settings; import android.view.*; import java.io.*; import java.util.*; import java.util.concurrent.*;
public final class RuntimeRisk {
  static final int DEBUGGER=1,HOOK=2,EMULATOR=4,MULTI_INSTANCE=8,DEVICE_MODIFIED=16,VPN_PROXY=32,ACCESSIBILITY=64,OVERLAY=128,MOCK_LOCATION=256,SIMULATED_TOUCH=512,TLS_PIN_MISMATCH=1024,UI_HIJACK=2048;
  static final int OBSERVE=20,RESTRICT=50,CHALLENGE=70,END_FLOW=90; private static final long TTL=300000L;
  private static final ConcurrentHashMap<Integer,Long> SEEN=new ConcurrentHashMap<Integer,Long>(); private static volatile Context APP;
  static final class Decision { final int mask,score,action; Decision(int m,int s,int a){mask=m;score=s;action=a;} boolean restricted(){return action>=RESTRICT;} boolean terminal(){return action>=END_FLOW;} }
  private RuntimeRisk(){}
  static void secure(Activity activity){ if(activity==null)return; activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE); View decor=activity.getWindow().getDecorView(); if(decor!=null)decor.setFilterTouchesWhenObscured(true); }
  static Decision observe(Context context,Activity activity,int eventMask){ if(context!=null)APP=context.getApplicationContext();Context current=context!=null?context:APP;if(activity!=null)secure(activity); int mask=eventMask|collect(current); long now=System.currentTimeMillis(); for(int bit=1;bit<=UI_HIJACK;bit<<=1)if((mask&bit)!=0)SEEN.put(bit,now); int active=0,score=0; for(Map.Entry<Integer,Long> e:SEEN.entrySet()){if(now-e.getValue()>TTL){SEEN.remove(e.getKey(),e.getValue());continue;}active|=e.getKey();score+=weight(e.getKey());} int action=score>=END_FLOW?END_FLOW:score>=CHALLENGE?CHALLENGE:score>=RESTRICT?RESTRICT:score>=OBSERVE?OBSERVE:0; return new Decision(active,score,action); }
  static Decision nativeEvidence(Context context,int nativeFlags){int mapped=0;if((nativeFlags&1)!=0)mapped|=DEBUGGER;if((nativeFlags&~1)!=0)mapped|=HOOK;return observe(context,null,mapped);}
  static int touch(MotionEvent event){if(event==null)return SIMULATED_TOUCH;int flags=event.getFlags();boolean obscured=(flags&MotionEvent.FLAG_WINDOW_IS_OBSCURED)!=0;if(Build.VERSION.SDK_INT>=29)obscured|=(flags&MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)!=0;boolean synthetic=event.getDeviceId()<=0||event.getEventTime()<event.getDownTime()||(event.getActionMasked()==MotionEvent.ACTION_DOWN&&event.getPressure()<=0f);return obscured||synthetic?SIMULATED_TOUCH:0;}
  public static boolean isMockLocation(android.location.Location location){boolean mock=false;if(location!=null){if(Build.VERSION.SDK_INT>=31)mock=location.isMock();else mock=location.isFromMockProvider();}if(mock)observe(null,null,MOCK_LOCATION);return mock;}
  static int focus(Activity activity){return activity!=null&&!activity.hasWindowFocus()?UI_HIJACK:0;}
  private static int collect(Context context){int mask=0;if(Debug.isDebuggerConnected()||Debug.waitingForDebugger()||traced())mask|=DEBUGGER;if(framework()||mappedHook())mask|=HOOK;if(emulator())mask|=EMULATOR;if(context==null)return mask;if(multiInstance(context))mask|=MULTI_INSTANCE;if(modified(context))mask|=DEVICE_MODIFIED;if(networkRisk(context))mask|=VPN_PROXY;if(accessibility(context))mask|=ACCESSIBILITY;if(Build.VERSION.SDK_INT>=23&&Settings.canDrawOverlays(context))mask|=OVERLAY;if(mockLocation(context))mask|=MOCK_LOCATION;return mask;}
  private static int weight(int bit){switch(bit){case DEBUGGER:return 16;case HOOK:return 24;case EMULATOR:return 7;case MULTI_INSTANCE:return 12;case DEVICE_MODIFIED:return 8;case VPN_PROXY:return 12;case ACCESSIBILITY:return 12;case OVERLAY:return 14;case MOCK_LOCATION:return 12;case SIMULATED_TOUCH:return 12;case TLS_PIN_MISMATCH:return 70;case UI_HIJACK:return 20;default:return 0;}}
  private static boolean traced(){try{BufferedReader r=new BufferedReader(new FileReader("/proc/self/status"));String line;while((line=r.readLine())!=null)if(line.startsWith("TracerPid:")){r.close();return Integer.parseInt(line.substring(10).trim())!=0;}r.close();}catch(Throwable ignored){}return false;}
  private static boolean framework(){String[] names={"de.robv.android.xposed.XposedBridge","org.lsposed.lspd.nativebridge.NativeAPI","com.saurik.substrate.MS$2"};for(String name:names)try{Class.forName(name,false,RuntimeRisk.class.getClassLoader());return true;}catch(Throwable ignored){}return false;}
  private static boolean mappedHook(){String[] marks={"frida","gum-js-loop","gmain","linjector","libsubstrate","lsposed","xposed"};try{BufferedReader r=new BufferedReader(new FileReader("/proc/self/maps"));String line;while((line=r.readLine())!=null){String lower=line.toLowerCase(Locale.US);for(String mark:marks)if(lower.contains(mark)){r.close();return true;}}r.close();}catch(Throwable ignored){}return false;}
  private static boolean emulator(){String all=(Build.FINGERPRINT+" "+Build.MODEL+" "+Build.MANUFACTURER+" "+Build.HARDWARE+" "+Build.PRODUCT).toLowerCase(Locale.US);return all.contains("generic")||all.contains("emulator")||all.contains("goldfish")||all.contains("ranchu")||all.contains("sdk_gphone");}
  private static boolean multiInstance(Context context){try{String[] packages=context.getPackageManager().getPackagesForUid(android.os.Process.myUid());if(packages!=null&&packages.length>1)return true;String path=context.getApplicationInfo().dataDir.toLowerCase(Locale.US);return path.contains("virtual")||path.contains("parallel")||path.contains("clone");}catch(Throwable ignored){return false;}}
  private static boolean modified(Context context){try{ApplicationInfo info=context.getApplicationInfo();if((info.flags&(ApplicationInfo.FLAG_DEBUGGABLE|ApplicationInfo.FLAG_TEST_ONLY))!=0)return true;String source=info.sourceDir==null?"":info.sourceDir;return !(source.startsWith("/data/app/")||source.startsWith("/system/")||source.startsWith("/product/"));}catch(Throwable ignored){return false;}}
  private static boolean networkRisk(Context context){if(System.getProperty("http.proxyHost","").length()>0||System.getProperty("https.proxyHost","").length()>0)return true;try{ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);if(cm==null)return false;for(Network network:cm.getAllNetworks()){NetworkCapabilities caps=cm.getNetworkCapabilities(network);if(caps!=null&&caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return true;}}catch(Throwable ignored){}return false;}
  private static boolean accessibility(Context context){try{String value=Settings.Secure.getString(context.getContentResolver(),Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);return value!=null&&!value.trim().isEmpty();}catch(Throwable ignored){return false;}}
  private static boolean mockLocation(Context context){try{if(Build.VERSION.SDK_INT<23)return !"0".equals(Settings.Secure.getString(context.getContentResolver(),Settings.Secure.ALLOW_MOCK_LOCATION));}catch(Throwable ignored){}return false;}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseConfig.java"), `${pkg}
import android.content.Context; import android.content.SharedPreferences; import java.util.*;
final class LicenseConfig {
${configString("DEFAULT_BASE_URL", serverUrl)}
${configString("APP_ID", appId)}
${configString("CRYPTO_SUITE", suiteId)}
${configString("TRANSPORT_KEY_ID", keyId)}
${configString("SERVER_RSA_PUBLIC_PEM", serverPublicKey)}
${configString("SERVER_SIGNING_KEY_ID", serverSigningKeyId)}
${configString("SERVER_SIGNING_PUBLIC_PEM", serverSigningPublicKey)}
${configString("BUILD_ID", buildId)}
${configString("SIGNING_CERT_SHA256", signingCertSha256)}
${configString("CARD_NAME", cardName)}
${configString("PURCHASE_URL", purchaseUrl)}
${configString("JUMP_TEXT", jumpText)}
${configString("JUMP_URL", jumpUrl)}
${configString("TLS_PIN_HOST", tlsPinHost)}
  static final String[] TLS_SPKI_PINS = new String[]{${tlsPinValues}};
  static final long PLAY_CLOUD_PROJECT_NUMBER = ${playProjectText}L;
  static final String APP_VERSION = "1.0";
  private static final String PREFS = "license_config"; private static final String KEY_BASE_URL = "base_url";
  static String getBaseUrl(Context c){ return normalize(c.getSharedPreferences(PREFS,0).getString(KEY_BASE_URL, DEFAULT_BASE_URL)); }
  static void saveBaseUrl(Context c, String v){ c.getSharedPreferences(PREFS,0).edit().putString(KEY_BASE_URL, normalize(v)).apply(); }
  static List<String> getBaseUrls(Context c){ ArrayList<String> u = new ArrayList<>(); add(u, getBaseUrl(c)); add(u, DEFAULT_BASE_URL); return u; }
  private static void add(ArrayList<String> u, String v){ if(v.length()>0 && !u.contains(v)) u.add(v); }
  private static String normalize(String v){ String u = v == null ? "" : v.trim(); if(u.length()==0) u = DEFAULT_BASE_URL; if(!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u; while(u.endsWith("/")) u = u.substring(0,u.length()-1); return u; }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "TlsPins.java"), `${pkg}
import android.content.Context; import android.util.Base64; import java.net.*; import java.security.*; import java.security.cert.Certificate; import java.util.*; import javax.net.ssl.*;
final class TlsPins {
  private TlsPins(){}
  static void connectAndVerify(Context context,HttpURLConnection connection,URL url)throws Exception{
    if(LicenseConfig.TLS_SPKI_PINS.length==0)return;
    if(!(connection instanceof HttpsURLConnection)){RuntimeRisk.observe(context,null,RuntimeRisk.TLS_PIN_MISMATCH);throw new SSLPeerUnverifiedException("HTTPS required");}
    String host=url.getHost()==null?"":url.getHost().toLowerCase(Locale.US);
    if(!constantEquals(host,LicenseConfig.TLS_PIN_HOST.toLowerCase(Locale.US))){RuntimeRisk.observe(context,null,RuntimeRisk.TLS_PIN_MISMATCH);throw new SSLPeerUnverifiedException("TLS pin host mismatch");}
    HttpsURLConnection https=(HttpsURLConnection)connection; https.connect(); Certificate[] chain=https.getServerCertificates(); MessageDigest digest=MessageDigest.getInstance("SHA-256");
    for(Certificate certificate:chain){String actual="sha256/"+Base64.encodeToString(digest.digest(certificate.getPublicKey().getEncoded()),Base64.NO_WRAP);for(String expected:LicenseConfig.TLS_SPKI_PINS)if(constantEquals(actual,expected))return;}
    RuntimeRisk.observe(context,null,RuntimeRisk.TLS_PIN_MISMATCH);throw new SSLPeerUnverifiedException("TLS SPKI pin mismatch");
  }
  private static boolean constantEquals(String a,String b){return MessageDigest.isEqual(a.getBytes(java.nio.charset.StandardCharsets.US_ASCII),b.getBytes(java.nio.charset.StandardCharsets.US_ASCII));}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "ProtectedAssets.java"), `${pkg}
import android.content.res.AssetManager; import android.util.Base64; import java.io.*; import java.nio.charset.StandardCharsets; import java.security.*; import java.util.*; import javax.crypto.*; import javax.crypto.spec.*;
public final class ProtectedAssets {
  private static final String[] PATHS=new String[]{${protectedAssetPaths}};
  private static final String[] FILES=new String[]{${protectedAssetFiles}};
  private static final int[] SIZES=new int[]{${protectedAssetSizes}};
  private static final String[] HASHES=new String[]{${protectedAssetHashes}};
  private static final String SHARE_A="${javaString(assetProtection.keyShareA || "")}";
  private static final String SHARE_B="${javaString(assetProtection.keyShareB || "")}";
  private ProtectedAssets(){}
  public static InputStream open(AssetManager manager,String name)throws IOException{return openInternal(manager,name,AssetManager.ACCESS_STREAMING);}
  public static InputStream open(AssetManager manager,String name,int mode)throws IOException{return openInternal(manager,name,mode);}
  private static InputStream openInternal(AssetManager manager,String name,int mode)throws IOException{
    int index=index(name);if(index<0)return manager.open(name,mode);
    try{byte[] envelope=read(manager.open(FILES[index],AssetManager.ACCESS_STREAMING),SIZES[index]+36);if(envelope.length<36||envelope[0]!='A'||envelope[1]!='V'||envelope[2]!='M'||envelope[3]!='1')throw new GeneralSecurityException("asset envelope");int size=((envelope[4]&255)<<24)|((envelope[5]&255)<<16)|((envelope[6]&255)<<8)|(envelope[7]&255);if(size!=SIZES[index]||envelope.length!=size+36)throw new GeneralSecurityException("asset size");byte[] iv=Arrays.copyOfRange(envelope,8,20),tag=Arrays.copyOfRange(envelope,20,36),sealed=new byte[size+16];System.arraycopy(envelope,36,sealed,0,size);System.arraycopy(tag,0,sealed,size,16);byte[] key=key();Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));cipher.updateAAD(("AVMP-ASSET-1\\n"+LicenseConfig.BUILD_ID+"\\n"+PATHS[index]+"\\n"+size).getBytes(StandardCharsets.UTF_8));byte[] clear=cipher.doFinal(sealed);Arrays.fill(key,(byte)0);if(!HASHES[index].equals(hex(MessageDigest.getInstance("SHA-256").digest(clear)))){Arrays.fill(clear,(byte)0);throw new GeneralSecurityException("asset digest");}return new WipingInputStream(clear);}catch(IOException error){throw error;}catch(Exception error){throw new IOException("protected asset rejected",error);}
  }
  private static int index(String name){for(int i=0;i<PATHS.length;i++)if(PATHS[i].equals(name))return i;return -1;}
  private static byte[] key()throws GeneralSecurityException{byte[] a=Base64.decode(SHARE_A,Base64.DEFAULT),b=Base64.decode(SHARE_B,Base64.DEFAULT);if(a.length!=32||b.length!=32)throw new GeneralSecurityException("asset key");for(int i=0;i<32;i++)a[i]^=b[i];Arrays.fill(b,(byte)0);return a;}
  private static byte[] read(InputStream in,int expected)throws IOException{try{if(expected<36||expected>8*1024*1024+36)throw new IOException("asset bound");ByteArrayOutputStream out=new ByteArrayOutputStream(expected);byte[] buffer=new byte[8192];int count,total=0;while((count=in.read(buffer))>=0){if(count==0)continue;total+=count;if(total>expected)throw new IOException("asset overflow");out.write(buffer,0,count);}return out.toByteArray();}finally{in.close();}}
  private static final class WipingInputStream extends ByteArrayInputStream{WipingInputStream(byte[] data){super(data);}public void close()throws IOException{Arrays.fill(buf,(byte)0);pos=count;super.close();}}
  private static String hex(byte[] value){StringBuilder out=new StringBuilder(value.length*2);for(byte b:value)out.append(String.format(Locale.US,"%02x",b&255));return out.toString();}
}
`, "utf8");
  if (useVmp) {
    fs.writeFileSync(path.join(dir, "VmpRuntime.java"), `${pkg}
import android.content.*; import android.content.pm.*; import android.os.*; import android.util.Base64; import com.android.licenseguard.NativeBridge; import java.io.*; import java.security.*; import java.util.*; import java.util.zip.*;
final class VmpRuntime {
  private static final String VM = "${vmProgram}"; private static final int VM_KEY = ${vmKey};
  private static final boolean STRICT_GUARD = ${strictGuard ? "true" : "false"};
  private static final String[] DEX_NAMES = new String[]{${dexNames}};
  private static final String[] DEX_HASHES = new String[]{${dexValues}};
  private static final String[] NATIVE_NAMES = new String[]{${nativeNames}};
  private static final String[] NATIVE_HASHES = new String[]{${nativeValues}};
  private static final String IMMUTABLE_ROOT = "${javaString(immutableRoot)}";
  private static final int IMMUTABLE_COUNT = ${immutableCount};
  private static final String GENERATED_DEX = "${javaString(generatedDexName)}";
  private static volatile int integrityState; private static volatile boolean monitorStarted;
  static String s(String value, int key){ return new String(bytes(value,key), java.nio.charset.StandardCharsets.UTF_8); }
  private static byte[] bytes(String value,int key){ byte[] data=Base64.decode(value,Base64.DEFAULT); for(int i=0;i<data.length;i++)data[i]=(byte)(data[i]^key); return data; }
  static boolean check(Context context){
    if(!NationalCrypto.selfTest()){android.util.Log.e("AVMPStartup","SM3 self-test failed");return false;}
    int nativeFlags=NativeBridge.probe(); int compromise=compromiseFlags(nativeFlags); RuntimeRisk.Decision risk=RuntimeRisk.nativeEvidence(context,nativeFlags);
    if(risk.restricted()||(STRICT_GUARD&&compromise!=0)){android.util.Log.e("LicenseGuard","runtime policy rejected");return false;}
    if(integrityState==0){ synchronized(VmpRuntime.class){ if(integrityState==0){boolean signature=verifySignature(context),dex=verifyDex(context),nativeCode=verifyNative(context),archive=verifyArchive(context);integrityState=(signature&&dex&&nativeCode&&archive)?1:-1;if(integrityState<0)android.util.Log.e("AVMPStartup","integrity signature="+signature+" dex="+dex+" native="+nativeCode+" archive="+archive);}}}
    if(integrityState==1)startMonitor(context.getApplicationContext());
    return integrityState==1;
  }
  private static boolean compromised(){ return compromiseFlags(NativeBridge.probe())!=0; }
  private static int compromiseFlags(int nativeFlags){int flags=0;if(Debug.isDebuggerConnected()||Debug.waitingForDebugger())flags|=1;if(traced())flags|=2;if(activeHooked())flags|=4;if(nativeFlags!=0)flags|=8;if(frameworkPresent())flags|=16;return flags;}
  private static boolean traced(){ try{ BufferedReader r=new BufferedReader(new FileReader("/proc/self/status")); String line; while((line=r.readLine())!=null){ if(line.startsWith("TracerPid:")){ r.close(); return Integer.parseInt(line.substring(10).trim())!=0; } } r.close(); }catch(Exception ignored){} return false; }
  private static boolean frameworkPresent(){
    String[] classes={"de.robv.android.xposed.XposedBridge","com.saurik.substrate.MS$2","org.lsposed.lspd.nativebridge.NativeAPI"};
    for(String name:classes){try{Class.forName(name,false,VmpRuntime.class.getClassLoader());return true;}catch(Throwable ignored){}}
    try{BufferedReader r=new BufferedReader(new FileReader("/proc/net/unix"));String line;while((line=r.readLine())!=null){String lower=line.toLowerCase(Locale.US);if(lower.contains("frida")||lower.contains("substrate")){r.close();return true;}}r.close();}catch(Throwable ignored){}
    return false;
  }
  private static boolean activeHooked(){
    String[] marks={"frida","gum-js-loop","gmain","libsubstrate","linjector"};
    try{BufferedReader r=new BufferedReader(new FileReader("/proc/self/maps"));String line;while((line=r.readLine())!=null){String lower=line.toLowerCase(Locale.US);for(String mark:marks)if(lower.contains(mark)){r.close();return true;}}r.close();}catch(Throwable ignored){}
    return false;
  }
  private static void startMonitor(final Context context){ if(monitorStarted)return; synchronized(VmpRuntime.class){if(monitorStarted)return;monitorStarted=true;Thread t=new Thread(new Runnable(){public void run(){while(true){try{Thread.sleep(2500);}catch(InterruptedException ignored){}int nativeFlags=NativeBridge.probe();RuntimeRisk.Decision risk=RuntimeRisk.nativeEvidence(context,nativeFlags);if(risk.terminal()||(STRICT_GUARD&&compromiseFlags(nativeFlags)!=0)){integrityState=-1;android.os.Process.killProcess(android.os.Process.myPid());return;}if(risk.restricted()){integrityState=-1;return;}}}},"runtime-integrity");t.setDaemon(true);t.start();} }
  private static boolean verifySignature(Context context){
    try{PackageManager pm=context.getPackageManager(); android.content.pm.Signature[] signatures; if(Build.VERSION.SDK_INT>=28){PackageInfo info=pm.getPackageInfo(context.getPackageName(),PackageManager.GET_SIGNING_CERTIFICATES);signatures=info.signingInfo.getApkContentsSigners();}else{PackageInfo info=pm.getPackageInfo(context.getPackageName(),PackageManager.GET_SIGNATURES);signatures=info.signatures;} if(signatures==null||signatures.length!=1)return false;MessageDigest md=MessageDigest.getInstance("SHA-256");String actual=hex(md.digest(signatures[0].toByteArray()));return LicenseConfig.SIGNING_CERT_SHA256.equalsIgnoreCase(actual);}catch(Throwable e){return false;}
  }
  private static boolean verifyDex(Context context){
    if(DEX_NAMES.length==0)return true;
    try{ ZipFile zip=new ZipFile(context.getApplicationInfo().sourceDir); for(int i=0;i<DEX_NAMES.length;i++){ ZipEntry e=zip.getEntry(DEX_NAMES[i]); if(e==null){zip.close();return false;} InputStream in=zip.getInputStream(e); String actual=sha256(in); in.close(); if(!DEX_HASHES[i].equalsIgnoreCase(actual)){zip.close();return false;} } zip.close(); return true; }catch(Exception e){return false;}
  }
  private static boolean verifyNative(Context context){
    try{ ZipFile zip=new ZipFile(context.getApplicationInfo().sourceDir); for(int i=0;i<NATIVE_NAMES.length;i++){ ZipEntry e=zip.getEntry(NATIVE_NAMES[i]); if(e==null){zip.close();return false;} InputStream in=zip.getInputStream(e); String actual=sha256(in); in.close(); if(!NATIVE_HASHES[i].equalsIgnoreCase(actual)){zip.close();return false;} } zip.close(); return !STRICT_GUARD||(context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE)==0; }catch(Exception e){return false;}
  }
  private static boolean verifyArchive(Context context){
    if(IMMUTABLE_ROOT.length()==0)return true;
    try{ZipFile zip=new ZipFile(context.getApplicationInfo().sourceDir);ArrayList<String> names=new ArrayList<String>();Enumeration<? extends ZipEntry> all=zip.entries();while(all.hasMoreElements()){ZipEntry entry=all.nextElement();String name=entry.getName();if(!entry.isDirectory()&&immutable(name))names.add(name);}Collections.sort(names);if(names.size()!=IMMUTABLE_COUNT){zip.close();return false;}MessageDigest root=MessageDigest.getInstance("SHA-256");for(String name:names){ZipEntry entry=zip.getEntry(name);InputStream in=zip.getInputStream(entry);String digest=sha256(in);in.close();String record=name+"\\u0000"+entry.getSize()+"\\u0000"+digest+"\\n";root.update(record.getBytes(java.nio.charset.StandardCharsets.UTF_8));}zip.close();return IMMUTABLE_ROOT.equalsIgnoreCase(hex(root.digest()));}catch(Throwable ignored){return false;}
  }
  private static boolean immutable(String name){if(name.equals(GENERATED_DEX))return false;if(name.matches("classes(?:[0-9]+)?\\\\.dex"))return true;if(name.equals("resources.arsc"))return true;if(name.startsWith("res/")||name.startsWith("assets/"))return true;return name.startsWith("lib/")&&name.endsWith(".so");}
  private static String sha256(InputStream in)throws Exception{ MessageDigest md=MessageDigest.getInstance("SHA-256"); byte[] buf=new byte[8192]; int n; while((n=in.read(buf))>0)md.update(buf,0,n); StringBuilder out=new StringBuilder(); for(byte b:md.digest())out.append(String.format(Locale.US,"%02x",b&255)); return out.toString(); }
  private static String hex(byte[] data){StringBuilder out=new StringBuilder(data.length*2);for(byte b:data)out.append(String.format(Locale.US,"%02x",b&255));return out.toString();}
  static boolean accept(boolean ok,int code,long expiresAt){
    byte[] program=bytes(VM,VM_KEY); long[] stack=new long[8]; int sp=0;
    for(int pc=0;pc<program.length;pc++){ switch(program[pc]&255){
      case ${vmOk}: stack[sp++]=ok?1:0; break;
      case ${vmCode}: stack[sp++]=code==0?1:0; break;
      case ${vmExpiry}: stack[sp++]=(expiresAt<=0||expiresAt>System.currentTimeMillis()/1000L)?1:0; break;
      case ${vmAnd}: if(sp<2)return false; stack[sp-2]=(stack[sp-2]!=0&&stack[sp-1]!=0)?1:0; sp--; break;
      case ${vmReturn}: return sp==1&&stack[0]!=0;
      default: return false;
    }} return false;
  }
}
`, "utf8");
    const nativeDir = path.join(root, "com", "android", "licenseguard");
    fs.mkdirSync(nativeDir, { recursive: true });
    fs.writeFileSync(path.join(nativeDir, "NativeBridge.java"), `package com.android.licenseguard;
public final class NativeBridge {
  private static final boolean LOADED;
  static { boolean loaded=false; try { System.loadLibrary("licenseguard"); loaded=true; } catch(Throwable ignored){} LOADED=loaded; }
  private NativeBridge(){}
  private static native int nativeProbe();
  public static int probe(){ try { return LOADED ? nativeProbe() : 63; } catch(Throwable ignored){ return 63; } }
  public static boolean trusted(){ return probe()==0; }
}
`, "utf8");
  }
  fs.writeFileSync(path.join(dir, "DeviceKey.java"), `${pkg}
import android.content.*; import android.os.*; import android.security.*; import android.security.keystore.*; import android.util.Base64; import java.math.*; import java.security.*; import java.security.cert.*; import java.util.*; import javax.security.auth.x500.*;
final class DeviceKey {
  private static final String ALIAS="license_device_"+LicenseConfig.APP_ID.replaceAll("[^A-Za-z0-9_]","_");
  private static synchronized KeyPair pair(Context context) throws Exception {
    KeyStore store=KeyStore.getInstance("AndroidKeyStore"); store.load(null);
    if(store.containsAlias(ALIAS)){ PrivateKey key=(PrivateKey)store.getKey(ALIAS,null); java.security.cert.Certificate cert=store.getCertificate(ALIAS); return new KeyPair(cert.getPublicKey(),key); }
    KeyPairGenerator gen=KeyPairGenerator.getInstance("EC","AndroidKeyStore");
    if(Build.VERSION.SDK_INT>=23){
      KeyGenParameterSpec spec=new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_SIGN|KeyProperties.PURPOSE_VERIFY).setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build();
      gen.initialize(spec);
    } else {
      Calendar start=Calendar.getInstance(), end=Calendar.getInstance(); end.add(Calendar.YEAR,30);
      KeyPairGeneratorSpec spec=new KeyPairGeneratorSpec.Builder(context).setAlias(ALIAS).setKeyType("EC").setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1")).setSubject(new X500Principal("CN=License Device Key")).setSerialNumber(BigInteger.ONE).setStartDate(start.getTime()).setEndDate(end.getTime()).build();
      gen.initialize(spec);
    }
    return gen.generateKeyPair();
  }
  static String publicKey(Context context) throws Exception { return b64(pair(context).getPublic().getEncoded()); }
  static String digest(Context context) throws Exception { return b64(MessageDigest.getInstance("SHA-256").digest(pair(context).getPublic().getEncoded())); }
  static String sign(Context context,String value) throws Exception { Signature s=Signature.getInstance("SHA256withECDSA"); s.initSign(pair(context).getPrivate()); s.update(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)); return b64(derToRaw(s.sign())); }
  private static byte[] derToRaw(byte[] der) throws Exception { int p=0; if((der[p++]&255)!=48)throw new GeneralSecurityException("bad ECDSA signature"); int seq=der[p++]&255; if((seq&128)!=0)p+=(seq&127); if((der[p++]&255)!=2)throw new GeneralSecurityException("bad ECDSA R"); int rl=der[p++]&255; int rs=p; p+=rl; if((der[p++]&255)!=2)throw new GeneralSecurityException("bad ECDSA S"); int sl=der[p++]&255; int ss=p; byte[] raw=new byte[64]; copyInt(der,rs,rl,raw,0); copyInt(der,ss,sl,raw,32); return raw; }
  private static void copyInt(byte[] src,int off,int len,byte[] out,int dst){ while(len>32&&src[off]==0){off++;len--;} int n=Math.min(32,len); System.arraycopy(src,off+len-n,out,dst+32-n,n); }
  private static String b64(byte[] data){ return Base64.encodeToString(data,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING); }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseClient.java"), `${pkg}
import android.content.*; import android.util.Base64; import org.json.*; import java.io.*; import java.net.*; import java.nio.charset.*; import java.security.*; import java.security.spec.*; import java.util.*; import javax.crypto.*; import javax.crypto.spec.*;
final class LicenseClient {
  private final Context context; private final SecureRandom random=new SecureRandom();
  LicenseClient(Context c){ context=c.getApplicationContext(); }
  LicenseResult activate(String cardKey,String deviceId,String appVersion)throws Exception{ JSONObject p=new JSONObject().put("cardKey",cardKey).put("cardName",LicenseConfig.CARD_NAME).put("deviceId",deviceId).put("appVersion",appVersion).put("buildId",LicenseConfig.BUILD_ID); LicenseResult r=request("/api/v4/activate",p); if(r.ok&&!LeaseVerifier.verify(context,cardKey,r.leaseData,r.leaseSignature))throw new GeneralSecurityException("authorization lease invalid"); return r; }
  LicenseResult heartbeat(String cardKey,String deviceId,String appVersion)throws Exception{ JSONObject p=new JSONObject().put("cardKey",cardKey).put("cardName",LicenseConfig.CARD_NAME).put("deviceId",deviceId).put("appVersion",appVersion).put("buildId",LicenseConfig.BUILD_ID); LicenseResult r=request("/api/v4/heartbeat",p); if(r.ok&&!LeaseVerifier.verify(context,cardKey,r.leaseData,r.leaseSignature))throw new GeneralSecurityException("authorization lease invalid"); return r; }
  private LicenseResult request(String path,JSONObject payload)throws Exception{ ${useVmp ? 'if(!VmpRuntime.check(context))throw new SecurityException("runtime integrity check failed"); ' : ''}Exception last=null; for(String base:LicenseConfig.getBaseUrls(context)){ Envelope env=null;try{env=seal(path,payload);return once(base,path,env);}catch(Exception e){last=e;}finally{if(env!=null)Arrays.fill(env.key,(byte)0);} } throw last==null?new IllegalStateException("network verify failed"):last; }
  private LicenseResult once(String base,String path,Envelope env)throws Exception{ RuntimeRisk.Decision risk=RuntimeRisk.observe(context,null,0);if(risk.restricted())throw new SecurityException("network risk policy");URL url=new URL(base+path);HttpURLConnection c=(HttpURLConnection)url.openConnection(); c.setRequestMethod("POST"); c.setConnectTimeout(20000); c.setReadTimeout(20000); c.setDoOutput(true); c.setRequestProperty("Content-Type","application/json; charset=utf-8"); c.setRequestProperty("Cache-Control","no-store"); TlsPins.connectAndVerify(context,c,url);OutputStream o=c.getOutputStream(); o.write(env.body.toString().getBytes(StandardCharsets.UTF_8)); o.close(); int status=c.getResponseCode(); InputStream in=status>=400?c.getErrorStream():c.getInputStream(); String text=readAll(in); if(status>=400){ try{throw new IllegalStateException(new JSONObject(text).optString("message","server rejected request"));}catch(JSONException ignored){throw new IllegalStateException("server rejected request: "+status);} } JSONObject data=open(path,new JSONObject(text),env); boolean ok=data.optBoolean("ok",false); int code=data.optInt("code",-1); long expiresAt=data.optLong("expiresAt",0); JSONObject lease=data.optJSONObject("lease"); String leaseData=lease==null?"":lease.optString("data",""); String leaseSig=lease==null?"":lease.optString("signature",""); if(ok&&(lease==null||!LicenseConfig.SERVER_SIGNING_KEY_ID.equals(lease.optString("keyId"))))throw new GeneralSecurityException("lease key mismatch"); ${useVmp ? 'ok=VmpRuntime.accept(ok,code,expiresAt); ' : ''}return new LicenseResult(ok,code,data.optString("message",""),expiresAt,data.optLong("remainingSeconds",0),data.optLong("nextHeartbeatSeconds",180),leaseData,leaseSig); }
  private Envelope seal(String path,JSONObject payload)throws Exception{ long ts=System.currentTimeMillis()/1000L; String nonce=randomB64(18); byte[] key=new byte[32],iv=new byte[12]; random.nextBytes(key); random.nextBytes(iv); payload.put("ts",ts);payload.put("sm3",NationalCrypto.bind(path+"\\n"+ts+"\\n"+nonce+"\\n"+payload.toString()));payload.put("playIntegrity",PlayIntegrity.collect(context,nonce,ts)); String aad=aad(path,ts,nonce,"request"); Cipher aes=Cipher.getInstance("AES/GCM/NoPadding"); aes.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv)); aes.updateAAD(aad.getBytes(StandardCharsets.UTF_8)); String data=b64(aes.doFinal(payload.toString().getBytes(StandardCharsets.UTF_8))); PublicKey rsa=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unpem(LicenseConfig.SERVER_RSA_PUBLIC_PEM))); Cipher wrap=Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); wrap.init(Cipher.ENCRYPT_MODE,rsa,new OAEPParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,PSource.PSpecified.DEFAULT)); String wrapped=b64(wrap.doFinal(key)),ivText=b64(iv),deviceKey=DeviceKey.publicKey(context); String authenticated=aad+"\\n"+wrapped+"\\n"+ivText+"\\n"+data+"\\n"+deviceKey; String mac=b64(hmac(macKey(key),authenticated)); String deviceSig=DeviceKey.sign(context,authenticated+"\\n"+mac); JSONObject body=new JSONObject().put("v",4).put("suite",LicenseConfig.CRYPTO_SUITE).put("appId",LicenseConfig.APP_ID).put("keyId",LicenseConfig.TRANSPORT_KEY_ID).put("ts",ts).put("nonce",nonce).put("key",wrapped).put("iv",ivText).put("data",data).put("mac",mac).put("deviceKey",deviceKey).put("deviceSig",deviceSig); return new Envelope(body,key); }
  private JSONObject open(String requestPath,JSONObject e,Envelope env)throws Exception{ if(e.optInt("v")!=4||!LicenseConfig.CRYPTO_SUITE.equals(e.optString("suite"))||!LicenseConfig.APP_ID.equals(e.optString("appId"))||!LicenseConfig.TRANSPORT_KEY_ID.equals(e.optString("keyId"))||!LicenseConfig.SERVER_SIGNING_KEY_ID.equals(e.optString("signingKeyId")))throw new GeneralSecurityException("server identity mismatch"); long ts=e.optLong("ts"); if(Math.abs(System.currentTimeMillis()/1000L-ts)>300)throw new GeneralSecurityException("server timestamp invalid"); String nonce=e.optString("nonce"),iv=e.optString("iv"),data=e.optString("data"),mac=e.optString("mac"),serverSig=e.optString("serverSig"); String aad=aad(requestPath+":response",ts,nonce,"response"); String authenticated=aad+"\\n"+iv+"\\n"+data; if(!MessageDigest.isEqual(unb64(mac),hmac(macKey(env.key),authenticated)))throw new GeneralSecurityException("server HMAC invalid"); if(!verifyServer(authenticated+"\\n"+mac,serverSig))throw new GeneralSecurityException("server signature invalid"); Cipher aes=Cipher.getInstance("AES/GCM/NoPadding"); aes.init(Cipher.DECRYPT_MODE,new SecretKeySpec(env.key,"AES"),new GCMParameterSpec(128,unb64(iv))); aes.updateAAD(aad.getBytes(StandardCharsets.UTF_8)); JSONObject payload=new JSONObject(new String(aes.doFinal(unb64(data)),StandardCharsets.UTF_8)); if(payload.optLong("ts")!=ts)throw new GeneralSecurityException("response timestamp mismatch"); return payload; }
  private boolean verifyServer(String value,String signatureText)throws Exception{ PublicKey key=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unpem(LicenseConfig.SERVER_SIGNING_PUBLIC_PEM))); Signature signature=pss(); signature.initVerify(key); signature.setParameter(new PSSParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,32,1)); signature.update(value.getBytes(StandardCharsets.UTF_8)); return signature.verify(unb64(signatureText)); }
  private static Signature pss()throws Exception{ try{return Signature.getInstance("RSASSA-PSS");}catch(NoSuchAlgorithmException e){return Signature.getInstance("SHA256withRSA/PSS");} }
  private String aad(String path,long ts,String nonce,String direction){ return "4\\n"+LicenseConfig.CRYPTO_SUITE+"\\n"+LicenseConfig.APP_ID+"\\n"+LicenseConfig.TRANSPORT_KEY_ID+"\\n"+path+"\\n"+ts+"\\n"+nonce+"\\n"+direction; }
  private static byte[] macKey(byte[] key)throws Exception{ MessageDigest d=MessageDigest.getInstance("SHA-256"); d.update(key); d.update("android-license-v4-aes-hmac".getBytes(StandardCharsets.UTF_8)); return d.digest(); }
  private static byte[] hmac(byte[] key,String value)throws Exception{ Mac m=Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(key,"HmacSHA256")); return m.doFinal(value.getBytes(StandardCharsets.UTF_8)); }
  private String randomB64(int size){ byte[] b=new byte[size]; random.nextBytes(b); return b64(b); }
  private static String readAll(InputStream in)throws Exception{ if(in==null)return ""; BufferedReader r=new BufferedReader(new InputStreamReader(in,StandardCharsets.UTF_8)); StringBuilder b=new StringBuilder(); String l; while((l=r.readLine())!=null)b.append(l); r.close(); return b.toString(); }
  private static byte[] unpem(String text){String clean=text.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----","").replace("\\r","").replace("\\n","").replace(" ","").replace("\\t","");return Base64.decode(clean,Base64.DEFAULT);}
  private static String b64(byte[] data){ return Base64.encodeToString(data,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING); }
  private static byte[] unb64(String text){ return Base64.decode(text,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING); }
  private static final class Envelope{ final JSONObject body; final byte[] key; Envelope(JSONObject b,byte[] k){body=b;key=k;} }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LeaseVerifier.java"), `${pkg}
import android.content.*; import android.util.Base64; import org.json.*; import java.nio.charset.*; import java.security.*; import java.security.spec.*;
final class LeaseVerifier {
  static boolean verify(Context context,String card,String data,String rawSignature){
    try{
      if(data==null||data.length()==0||rawSignature==null||rawSignature.length()==0)return false;
      PublicKey key=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unpem(LicenseConfig.SERVER_SIGNING_PUBLIC_PEM)));
      Signature signature=pss(); signature.initVerify(key); signature.setParameter(new PSSParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,32,1)); signature.update(data.getBytes(StandardCharsets.UTF_8));
      if(!signature.verify(unb64(rawSignature)))return false;
      JSONObject lease=new JSONObject(new String(unb64(data),StandardCharsets.UTF_8)); long now=System.currentTimeMillis()/1000L;
      if(lease.optInt("v")!=4||!LicenseConfig.CRYPTO_SUITE.equals(lease.optString("suite"))||!LicenseConfig.APP_ID.equals(lease.optString("appId"))||!LicenseConfig.BUILD_ID.equals(lease.optString("buildId")))return false;
      if(!LicenseConfig.CARD_NAME.equals(lease.optString("cardName")))return false;
      if(!digest(card.trim().toUpperCase()).equals(lease.optString("cardDigest")))return false;
      if(!DeviceKey.digest(context).equals(lease.optString("deviceKeyDigest")))return false;
      long issuedAt=lease.optLong("issuedAt"),notAfter=lease.optLong("notAfter"),expiresAt=lease.optLong("expiresAt");
      return issuedAt>0&&issuedAt<=now+300&&notAfter>now&&expiresAt>now&&notAfter<=expiresAt;
    }catch(Throwable ignored){return false;}
  }
  static long notAfter(String data){ try{return new JSONObject(new String(unb64(data),StandardCharsets.UTF_8)).optLong("notAfter");}catch(Throwable ignored){return 0;} }
  private static String digest(String value)throws Exception{return b64(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}
  private static Signature pss()throws Exception{try{return Signature.getInstance("RSASSA-PSS");}catch(NoSuchAlgorithmException e){return Signature.getInstance("SHA256withRSA/PSS");}}
  private static byte[] unpem(String text){String clean=text.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----","").replace("\\r","").replace("\\n","").replace(" ","").replace("\\t","");return Base64.decode(clean,Base64.DEFAULT);}
  private static String b64(byte[] data){return Base64.encodeToString(data,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING);}
  private static byte[] unb64(String text){return Base64.decode(text,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING);}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "SecureStore.java"), `${pkg}
import android.content.*; import android.security.keystore.*; import android.util.Base64; import org.json.*; import java.nio.charset.*; import java.security.*; import javax.crypto.*; import javax.crypto.spec.*;
final class SecureStore {
  private static final String PREFS="license_session_"+LicenseConfig.BUILD_ID.substring(0,12); private static final String ENTRY="sealed_session"; private static final String ALIAS="license_session_key_"+LicenseConfig.BUILD_ID;
  static synchronized void save(Context context,String card,LicenseResult result)throws Exception{ JSONObject value=new JSONObject().put("card",card.trim().toUpperCase()).put("leaseData",result.leaseData).put("leaseSignature",result.leaseSignature); prefs(context).edit().putString(ENTRY,seal(value.toString())).commit(); }
  static synchronized JSONObject read(Context context){ try{String value=prefs(context).getString(ENTRY,"");return value.length()==0?null:new JSONObject(open(value));}catch(Throwable ignored){return null;} }
  static String card(Context context){JSONObject value=read(context);return value==null?"":value.optString("card","");}
  static String leaseData(Context context){JSONObject value=read(context);return value==null?"":value.optString("leaseData","");}
  static String leaseSignature(Context context){JSONObject value=read(context);return value==null?"":value.optString("leaseSignature","");}
  static boolean hasSession(Context context){return prefs(context).contains(ENTRY);}
  static void clear(Context context){prefs(context).edit().remove(ENTRY).commit();}
  private static android.content.SharedPreferences prefs(Context context){return context.getSharedPreferences(PREFS,Context.MODE_PRIVATE);}
  private static SecretKey key()throws Exception{KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);if(store.containsAlias(ALIAS))return (SecretKey)store.getKey(ALIAS,null);KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");generator.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build());return generator.generateKey();}
  private static String seal(String clear)throws Exception{Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());byte[] iv=cipher.getIV(),encrypted=cipher.doFinal(clear.getBytes(StandardCharsets.UTF_8)),all=new byte[iv.length+encrypted.length];System.arraycopy(iv,0,all,0,iv.length);System.arraycopy(encrypted,0,all,iv.length,encrypted.length);return Base64.encodeToString(all,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING);}
  private static String open(String value)throws Exception{byte[] all=Base64.decode(value,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING);if(all.length<29)throw new GeneralSecurityException("bad session");byte[] iv=new byte[12],encrypted=new byte[all.length-12];System.arraycopy(all,0,iv,0,12);System.arraycopy(all,12,encrypted,0,encrypted.length);Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,iv));return new String(cipher.doFinal(encrypted),StandardCharsets.UTF_8);}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "GuardRuntime.java"), `${pkg}
import android.app.*; import android.content.*; import android.os.*; import android.provider.Settings; import java.util.concurrent.atomic.*;
final class GuardRuntime {
  private static final AtomicBoolean STARTED=new AtomicBoolean(); private static volatile boolean authorized;
  static void init(final Context source){
    final Context context=source.getApplicationContext(); RuntimeRisk.Decision initialRisk=RuntimeRisk.observe(context,null,0);boolean integrityOk=integrity(context);if(initialRisk.terminal()||!integrityOk){android.util.Log.e("AVMPStartup","startup mask="+initialRisk.mask+" score="+initialRisk.score+" action="+initialRisk.action+" integrity="+integrityOk);terminate();return;}
    authorized=validLease(context);
    if(!STARTED.compareAndSet(false,true))return;
    if(context instanceof Application)((Application)context).registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks(){
      public void onActivityCreated(Activity a,Bundle b){RuntimeRisk.secure(a);RuntimeRisk.observe(context,a,0);} public void onActivityStarted(Activity a){} public void onActivityPaused(Activity a){} public void onActivityStopped(Activity a){} public void onActivitySaveInstanceState(Activity a,Bundle b){} public void onActivityDestroyed(Activity a){}
      public void onActivityResumed(final Activity activity){ RuntimeRisk.Decision risk=RuntimeRisk.observe(context,activity,0);activity.getWindow().getDecorView().postDelayed(new Runnable(){public void run(){RuntimeRisk.observe(context,activity,RuntimeRisk.focus(activity));}},500L);if(risk.terminal()){terminate();return;}if(activity instanceof LicenseActivity)return; if(!integrity(context)){terminate();return;} if(risk.restricted()||!validLease(context)){authorized=false; Intent i=new Intent(activity,LicenseActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP|Intent.FLAG_ACTIVITY_NEW_TASK);activity.startActivity(i);activity.finish();}else authorized=true; }
    });
    Thread monitor=new Thread(new Runnable(){public void run(){for(;;){try{Thread.sleep(45000);}catch(InterruptedException ignored){}RuntimeRisk.Decision risk=RuntimeRisk.observe(context,null,0);if(risk.terminal()||!integrity(context)){terminate();return;}if(risk.restricted())authorized=false;String card=SecureStore.card(context);if(card.length()==0)continue;long remaining=LeaseVerifier.notAfter(SecureStore.leaseData(context))-System.currentTimeMillis()/1000L;if(remaining<150){try{LicenseResult result=new LicenseClient(context).heartbeat(card,deviceId(context),LicenseConfig.APP_VERSION);if(result.ok&&!risk.restricted()){SecureStore.save(context,card,result);authorized=true;}else authorized=false;}catch(Throwable ignored){if(remaining<=0)authorized=false;}}}}},"license-lease-monitor");monitor.setDaemon(true);monitor.start();
  }
  static void accept(Context context,String card,LicenseResult result)throws Exception{SecureStore.save(context,card,result);authorized=validLease(context);if(!authorized)throw new SecurityException("lease rejected");}
  static boolean validLease(Context context){String card=SecureStore.card(context);return card.length()>0&&LeaseVerifier.verify(context,card,SecureStore.leaseData(context),SecureStore.leaseSignature(context));}
  static boolean authorized(Context context){return authorized&&validLease(context)&&integrity(context);}
  private static boolean integrity(Context context){return ${useVmp ? 'VmpRuntime.check(context)' : 'true'};}
  private static String deviceId(Context context){String id=Settings.Secure.getString(context.getContentResolver(),Settings.Secure.ANDROID_ID);return id==null||id.trim().length()==0?"unknown-device":id;}
  private static void terminate(){android.os.Process.killProcess(android.os.Process.myPid());System.exit(173);}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseGuardProvider.java"), `${pkg}
import android.content.*; import android.database.Cursor; import android.net.Uri;
public class LicenseGuardProvider extends ContentProvider {
  public boolean onCreate(){GuardRuntime.init(getContext());return true;}
  public Cursor query(Uri u,String[] p,String s,String[] a,String o){return null;} public String getType(Uri u){return null;} public Uri insert(Uri u,ContentValues v){return null;} public int delete(Uri u,String s,String[] a){return 0;} public int update(Uri u,ContentValues v,String s,String[] a){return 0;}
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseActivity.java.legacy-invalid"), `${pkg}
import android.app.*; import android.os.*; import android.content.*; import android.graphics.Color; import android.graphics.drawable.*; import android.provider.Settings; import android.view.*; import android.widget.*;
public class LicenseActivity extends Activity {
  EditText cardInput; TextView statusText; Button button; boolean loading=false;
  public void onCreate(Bundle b){ super.onCreate(b); RuntimeRisk.secure(this); GuardRuntime.init(this); ${useVmp ? 'if(!VmpRuntime.check(this)){ finish(); return; } ' : ''}requestWindowFeature(Window.FEATURE_NO_TITLE); getWindow().setBackgroundDrawable(new ColorDrawable(Color.rgb(3,14,24))); if(Build.VERSION.SDK_INT>=21){ getWindow().setStatusBarColor(Color.rgb(14,18,35)); getWindow().setNavigationBarColor(Color.rgb(3,14,24)); } getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE); buildUi(); cardInput.setFilterTouchesWhenObscured(true);button.setFilterTouchesWhenObscured(true);View.OnTouchListener touchGuard=new View.OnTouchListener(){public boolean onTouch(View view,MotionEvent event){int signal=RuntimeRisk.touch(event);if(signal==0)return false;return RuntimeRisk.observe(LicenseActivity.this,LicenseActivity.this,signal).restricted();}};cardInput.setOnTouchListener(touchGuard);button.setOnTouchListener(touchGuard);cardInput.setText(SecureStore.card(this)); button.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ activate(); }}); if(cardInput.getText().toString().trim().length()>0) heartbeat(); }
  void buildUi(){ FrameLayout screen=new FrameLayout(this); GradientDrawable bg=new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,new int[]{Color.rgb(14,18,35),Color.rgb(3,14,24)}); screen.setBackground(bg); LinearLayout root=new LinearLayout(this); root.setGravity(Gravity.CENTER); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(22),0,dp(22),0); LinearLayout box=new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL); box.setPadding(dp(22),dp(22),dp(22),dp(22)); GradientDrawable panel=new GradientDrawable(); panel.setColor(Color.rgb(22,29,47)); panel.setStroke(dp(1),Color.rgb(49,68,90)); panel.setCornerRadius(dp(10)); box.setBackground(panel); TextView title=t("閸椻€崇槕妤犲矁鐦?,26,Color.rgb(243,255,249),true); cardInput=input("XXXX-XXXX-XXXX-XXXX",18); button=new Button(this); button.setText("妤犲矁鐦夐獮鎯扮箻閸?); button.setTextColor(Color.rgb(6,18,15)); button.setTextSize(17); button.setAllCaps(false); GradientDrawable bb=new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,new int[]{Color.rgb(81,231,197),Color.rgb(255,238,97)}); bb.setCornerRadius(dp(10)); button.setBackground(bb); statusText=t("",14,Color.rgb(215,255,245),false); statusText.setVisibility(View.GONE); box.addView(title); add(box,cardInput,24,58); add(box,button,18,60); add(box,statusText,16,-2); int w=getResources().getDisplayMetrics().widthPixels - dp(44); if(w>dp(520)) w=dp(520); if(w<dp(260)) w=dp(260); root.addView(box,new LinearLayout.LayoutParams(w,-2)); screen.addView(root,new FrameLayout.LayoutParams(-1,-1)); addLinks(screen); setContentView(screen,new ViewGroup.LayoutParams(-1,-1)); }
  TextView t(String s,int sp,int c,boolean bold){ TextView v=new TextView(this); v.setText(s); v.setTextSize(sp); v.setTextColor(c); if(bold)v.setTypeface(null,1); return v; }
  EditText input(String h,int sp){ EditText e=new EditText(this); e.setHint(h); e.setSingleLine(true); e.setTextColor(Color.WHITE); e.setHintTextColor(Color.rgb(120,144,156)); e.setTextSize(sp); e.setPadding(dp(14),0,dp(14),0); GradientDrawable d=new GradientDrawable(); d.setColor(Color.rgb(27,40,60)); d.setStroke(dp(1),Color.rgb(48,72,99)); d.setCornerRadius(dp(10)); e.setBackground(d); return e; }
  void add(LinearLayout box, View v, int top, int height){ LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1, height < 0 ? -2 : dp(height)); lp.topMargin=dp(top); box.addView(v,lp); }
  void addLinks(FrameLayout screen){ LinearLayout links=new LinearLayout(this); links.setOrientation(LinearLayout.VERTICAL); links.setGravity(Gravity.RIGHT); int count=0; count+=addLink(links,LicenseConfig.JUMP_TEXT,LicenseConfig.JUMP_URL); count+=addLink(links,"閸椻€崇槕鐠愵厺鎷遍崷鏉挎絻",LicenseConfig.PURCHASE_URL); if(count==0)return; FrameLayout.LayoutParams lp=new FrameLayout.LayoutParams(-2,-2,Gravity.RIGHT|Gravity.BOTTOM); lp.setMargins(dp(12),0,dp(12),dp(12)); screen.addView(links,lp); }
  int addLink(LinearLayout links,String text,final String url){ if(text==null||text.trim().length()==0||url==null||url.trim().length()==0)return 0; TextView v=t(text,13,Color.rgb(215,255,245),false); v.setPadding(dp(10),dp(6),dp(10),dp(6)); v.setGravity(Gravity.RIGHT); v.setOnClickListener(new View.OnClickListener(){ public void onClick(View view){ try { startActivity(new Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url))); } catch(Exception e){ toast("閺冪姵纭堕幍鎾崇磻闁剧偓甯?); } }}); links.addView(v,new LinearLayout.LayoutParams(-2,-2)); return 1; }
  int dp(int v){ return (int)(v*getResources().getDisplayMetrics().density+0.5f); }
  void activate(){ if(loading) return; final String card=cardInput.getText().toString().trim(); if(card.length()==0){ setLoading(false,"鐠囩柉绶崗銉ュ幢鐎?); return; } setLoading(true,"妤犲矁鐦夋稉?.."); new Thread(new Runnable(){ public void run(){ try { LicenseResult r=new LicenseClient(LicenseActivity.this).activate(card, deviceId(), LicenseConfig.APP_VERSION); if(r.ok){ GuardRuntime.accept(LicenseActivity.this,card,r); runOnUiThread(new Runnable(){ public void run(){ enterMain(); }}); } else { final String msg=r.message; runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"妤犲矁鐦夋径杈Е閿? + msg); }}); } } catch(final Exception e){ runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"妤犲矁鐦夋径杈Е閿? + (e.getMessage()==null?"缂冩垹绮舵宀冪槈婢惰精瑙?:e.getMessage())); }}); } }}).start(); }
  void heartbeat(){ setLoading(true,"濮濓絽婀宀冪槈..."); new Thread(new Runnable(){ public void run(){ try { String card=cardInput.getText().toString().trim(); LicenseResult r=new LicenseClient(LicenseActivity.this).heartbeat(card, deviceId(), LicenseConfig.APP_VERSION); if(r.ok) { GuardRuntime.accept(LicenseActivity.this,card,r); runOnUiThread(new Runnable(){ public void run(){ enterMain(); }}); } else { final String msg=r.message; runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"妤犲矁鐦夋径杈Е閿? + msg); }}); } } catch(final Exception e){ runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"妤犲矁鐦夋径杈Е閿? + (e.getMessage()==null?"韫囧啳鐑︽宀冪槈婢惰精瑙?:e.getMessage())); }}); } }}).start(); }
  String deviceId(){ String id=Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID); return id==null||id.trim().length()==0?"unknown-device":id; }
  void setLoading(boolean l,String m){ loading=l; cardInput.setEnabled(!l); button.setEnabled(!l); statusText.setText(m == null ? "" : m); statusText.setVisibility(m == null || m.length()==0 ? View.GONE : View.VISIBLE); }
  void toast(String m){ Toast.makeText(this,m,Toast.LENGTH_SHORT).show(); }
  void enterMain(){ try { if(!GuardRuntime.authorized(this))throw new SecurityException("閹哄牊娼堢粔鐔哄閺冪姵鏅?); startActivity(new Intent(this, Class.forName("${javaString(launcher)}"))); finish(); } catch(Exception e){ setLoading(false,"閸樼喎鎯庨崝銊┿€夐幍鎾崇磻婢惰精瑙﹂敍? + e.getMessage()); } }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseActivity.java"), `${pkg}
import android.app.*; import android.os.*; import android.content.*; import android.graphics.Color; import android.graphics.drawable.*; import android.provider.Settings; import android.view.*; import android.widget.*;
public class LicenseActivity extends Activity {
  EditText cardInput; TextView statusText; Button button; boolean loading=false;
  public void onCreate(Bundle b){ super.onCreate(b); RuntimeRisk.secure(this); GuardRuntime.init(this); ${useVmp ? 'if(!VmpRuntime.check(this)){ finish(); return; } ' : ''}requestWindowFeature(Window.FEATURE_NO_TITLE); getWindow().setBackgroundDrawable(new ColorDrawable(Color.rgb(3,14,24))); if(Build.VERSION.SDK_INT>=21){ getWindow().setStatusBarColor(Color.rgb(14,18,35)); getWindow().setNavigationBarColor(Color.rgb(3,14,24)); } getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE); buildUi(); cardInput.setFilterTouchesWhenObscured(true); button.setFilterTouchesWhenObscured(true); View.OnTouchListener touchGuard=new View.OnTouchListener(){public boolean onTouch(View view,MotionEvent event){int signal=RuntimeRisk.touch(event); if(signal==0)return false; return RuntimeRisk.observe(LicenseActivity.this,LicenseActivity.this,signal).restricted();}}; cardInput.setOnTouchListener(touchGuard); button.setOnTouchListener(touchGuard); cardInput.setText(SecureStore.card(this)); button.setOnClickListener(new View.OnClickListener(){public void onClick(View v){activate();}}); if(cardInput.getText().toString().trim().length()>0)heartbeat(); }
  void buildUi(){ FrameLayout screen=new FrameLayout(this); GradientDrawable bg=new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,new int[]{Color.rgb(14,18,35),Color.rgb(3,14,24)}); screen.setBackground(bg); LinearLayout root=new LinearLayout(this); root.setGravity(Gravity.CENTER); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(22),0,dp(22),0); LinearLayout box=new LinearLayout(this); box.setOrientation(LinearLayout.VERTICAL); box.setPadding(dp(22),dp(22),dp(22),dp(22)); GradientDrawable panel=new GradientDrawable(); panel.setColor(Color.rgb(22,29,47)); panel.setStroke(dp(1),Color.rgb(49,68,90)); panel.setCornerRadius(dp(10)); box.setBackground(panel); TextView title=t("Card verification",26,Color.rgb(243,255,249),true); cardInput=input("XXXX-XXXX-XXXX-XXXX",18); button=new Button(this); button.setText("Verify and continue"); button.setTextColor(Color.rgb(6,18,15)); button.setTextSize(17); button.setAllCaps(false); GradientDrawable bb=new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,new int[]{Color.rgb(81,231,197),Color.rgb(255,238,97)}); bb.setCornerRadius(dp(10)); button.setBackground(bb); statusText=t("",14,Color.rgb(215,255,245),false); statusText.setVisibility(View.GONE); box.addView(title); add(box,cardInput,24,58); add(box,button,18,60); add(box,statusText,16,-2); int w=getResources().getDisplayMetrics().widthPixels-dp(44); if(w>dp(520))w=dp(520); if(w<dp(260))w=dp(260); root.addView(box,new LinearLayout.LayoutParams(w,-2)); screen.addView(root,new FrameLayout.LayoutParams(-1,-1)); addLinks(screen); setContentView(screen,new ViewGroup.LayoutParams(-1,-1)); }
  TextView t(String s,int sp,int c,boolean bold){TextView v=new TextView(this); v.setText(s); v.setTextSize(sp); v.setTextColor(c); if(bold)v.setTypeface(null,1); return v;}
  EditText input(String h,int sp){EditText e=new EditText(this); e.setHint(h); e.setSingleLine(true); e.setTextColor(Color.WHITE); e.setHintTextColor(Color.rgb(120,144,156)); e.setTextSize(sp); e.setPadding(dp(14),0,dp(14),0); GradientDrawable d=new GradientDrawable(); d.setColor(Color.rgb(27,40,60)); d.setStroke(dp(1),Color.rgb(48,72,99)); d.setCornerRadius(dp(10)); e.setBackground(d); return e;}
  void add(LinearLayout box,View v,int top,int height){LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1,height<0?-2:dp(height)); lp.topMargin=dp(top); box.addView(v,lp);}
  void addLinks(FrameLayout screen){LinearLayout links=new LinearLayout(this); links.setOrientation(LinearLayout.VERTICAL); links.setGravity(Gravity.RIGHT); int count=0; count+=addLink(links,LicenseConfig.JUMP_TEXT,LicenseConfig.JUMP_URL); count+=addLink(links,"Purchase license",LicenseConfig.PURCHASE_URL); if(count==0)return; FrameLayout.LayoutParams lp=new FrameLayout.LayoutParams(-2,-2,Gravity.RIGHT|Gravity.BOTTOM); lp.setMargins(dp(12),0,dp(12),dp(12)); screen.addView(links,lp);}
  int addLink(LinearLayout links,String text,final String url){if(text==null||text.trim().length()==0||url==null||url.trim().length()==0)return 0; TextView v=t(text,13,Color.rgb(215,255,245),false); v.setPadding(dp(10),dp(6),dp(10),dp(6)); v.setGravity(Gravity.RIGHT); v.setOnClickListener(new View.OnClickListener(){public void onClick(View view){try{startActivity(new Intent(Intent.ACTION_VIEW,android.net.Uri.parse(url)));}catch(Exception e){toast("Unable to open link");}}}); links.addView(v,new LinearLayout.LayoutParams(-2,-2)); return 1;}
  int dp(int v){return (int)(v*getResources().getDisplayMetrics().density+0.5f);}
  void activate(){if(loading)return; final String card=cardInput.getText().toString().trim(); if(card.length()==0){setLoading(false,"Enter a license key"); return;} setLoading(true,"Verifying..."); new Thread(new Runnable(){public void run(){try{LicenseResult r=new LicenseClient(LicenseActivity.this).activate(card,deviceId(),LicenseConfig.APP_VERSION); if(r.ok){GuardRuntime.accept(LicenseActivity.this,card,r); runOnUiThread(new Runnable(){public void run(){enterMain();}});}else{final String msg=r.message; runOnUiThread(new Runnable(){public void run(){setLoading(false,"Verification failed: "+msg);}});}}catch(final Exception e){runOnUiThread(new Runnable(){public void run(){setLoading(false,"Verification failed: "+(e.getMessage()==null?"Network error":e.getMessage()));}});}}}).start();}
  void heartbeat(){setLoading(true,"Checking authorization..."); new Thread(new Runnable(){public void run(){try{String card=cardInput.getText().toString().trim(); LicenseResult r=new LicenseClient(LicenseActivity.this).heartbeat(card,deviceId(),LicenseConfig.APP_VERSION); if(r.ok){GuardRuntime.accept(LicenseActivity.this,card,r); runOnUiThread(new Runnable(){public void run(){enterMain();}});}else{final String msg=r.message; runOnUiThread(new Runnable(){public void run(){setLoading(false,"Verification failed: "+msg);}});}}catch(final Exception e){runOnUiThread(new Runnable(){public void run(){setLoading(false,"Verification failed: "+(e.getMessage()==null?"Network error":e.getMessage()));}});}}}).start();}
  String deviceId(){String id=Settings.Secure.getString(getContentResolver(),Settings.Secure.ANDROID_ID); return id==null||id.trim().length()==0?"unknown-device":id;}
  void setLoading(boolean l,String m){loading=l; cardInput.setEnabled(!l); button.setEnabled(!l); statusText.setText(m==null?"":m); statusText.setVisibility(m==null||m.length()==0?View.GONE:View.VISIBLE);}
  void toast(String m){Toast.makeText(this,m,Toast.LENGTH_SHORT).show();}
  void enterMain(){try{if(!GuardRuntime.authorized(this))throw new SecurityException("Authorization expired"); startActivity(new Intent(this,Class.forName("${javaString(launcher)}"))); finish();}catch(Exception e){setLoading(false,"Unable to start app: "+e.getMessage());}}
}
`, "utf8");
}

async function addDex(apk, dexPath, entryName) {
  const name = entryName || nextDexEntryName(await zipList(apk));
  const entryDir = path.join(path.dirname(apk), "dex-entry");
  fs.rmSync(entryDir, { recursive: true, force: true });
  fs.mkdirSync(entryDir, { recursive: true });
  fs.copyFileSync(dexPath, path.join(entryDir, name));
  try {
    await run(jarCommand(), ["uf", apk, "-C", entryDir, name], path.dirname(apk));
  } finally {
    fs.rmSync(entryDir, { recursive: true, force: true });
  }
}

function nextDexEntryName(entries) {
  let n = 2;
  while (entries.includes(`classes${n}.dex`)) n++;
  return `classes${n}.dex`;
}

async function zipList(apk) {
  const out = await runCapture(jarCommand(), ["tf", apk], path.dirname(apk));
  return out.split(/\r?\n/).filter(Boolean);
}

async function originalDexHashes(apk, jobDir) {
  const names = (await zipList(apk)).filter((name) => /^classes(?:\d+)?\.dex$/.test(name));
  const extractDir = path.join(jobDir, "vmp-original-dex");
  fs.rmSync(extractDir, { recursive: true, force: true });
  fs.mkdirSync(extractDir, { recursive: true });
  const result = [];
  try {
    for (const name of names) {
      await run(jarCommand(), ["xf", apk, name], extractDir);
      const file = path.join(extractDir, name);
      result.push({ name, sha256: crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex") });
    }
    return result;
  } finally {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
}

function isImmutableApkEntry(name, generatedDexName) {
  if (!name || name.endsWith("/") || name === generatedDexName) return false;
  if (/^classes(?:\d+)?\.dex$/.test(name) || name === "resources.arsc") return true;
  if (name.startsWith("res/") || name.startsWith("assets/")) return true;
  return name.startsWith("lib/") && name.endsWith(".so");
}

async function immutableApkManifest(apk, jobDir, generatedDexName) {
  const names = (await zipList(apk))
    .filter((name) => isImmutableApkEntry(name, generatedDexName))
    .sort();
  for (const name of names) {
    if (name.startsWith("/") || name.includes("../") || name.includes("..\\")) throw new Error("Unsafe APK entry in integrity manifest");
  }
  const extractDir = path.join(jobDir, "immutable-apk-manifest");
  fs.rmSync(extractDir, { recursive: true, force: true });
  fs.mkdirSync(extractDir, { recursive: true });
  const root = crypto.createHash("sha256");
  try {
    await run(jarCommand(), ["xf", apk], extractDir);
    for (const name of names) {
      const file = path.join(extractDir, ...name.split("/"));
      const stat = fs.statSync(file);
      const digest = sha256File(file);
      root.update(`${name}\0${stat.size}\0${digest}\n`, "utf8");
    }
    return { schema: 1, root: root.digest("hex"), count: names.length, generatedDexName };
  } finally {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }
}

function hasDynamicResourceLookup(decodedDir) {
  for (const entry of fs.readdirSync(decodedDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^smali(?:_classes\d+)?$/.test(entry.name)) continue;
    for (const file of listFiles(path.join(decodedDir, entry.name)).filter((item) => item.endsWith(".smali"))) {
      if (fs.readFileSync(file, "utf8").includes("Landroid/content/res/Resources;->getIdentifier")) return true;
    }
  }
  return false;
}

function resourceOptimizeArgs(inputApk, outputApk, mapFile, collapseNames, preservePaths = false) {
  const args = ["optimize"];
  if (!preservePaths) args.push("--shorten-resource-paths");
  args.push("--deduplicate-entry-values");
  if (collapseNames) args.push("--collapse-resource-names");
  args.push("--save-obfuscation-map", mapFile, "-o", outputApk, inputApk);
  return args;
}

function assertUniqueArchiveEntries(entries) {
  const seen = new Set();
  const portable = new Map();
  const duplicates = new Set();
  const caseCollisions = new Set();
  for (const entry of entries) {
    if (seen.has(entry)) duplicates.add(entry);
    seen.add(entry);
    const folded = entry.toLowerCase();
    const previous = portable.get(folded);
    if (previous && previous !== entry) caseCollisions.add(`${previous} <> ${entry}`);
    else portable.set(folded, entry);
  }
  if (duplicates.size) {
    throw new Error(`APK contains duplicate ZIP entries: ${[...duplicates].slice(0, 8).join(", ")}`);
  }
  if (caseCollisions.size) {
    throw new Error(`APK contains case-colliding ZIP entries: ${[...caseCollisions].slice(0, 8).join(", ")}`);
  }
  return { entries: entries.length, uniqueEntries: seen.size, portableUniqueEntries: portable.size };
}

async function canonicalizeApkArchive(tools, inputApk, outputApk, reportFile, cwd) {
  if (!tools.python) throw new Error("Canonical APK rebuilding requires Python");
  await run(tools.python, [
    "-B",
    path.join(ROOT, "tools", "canonicalize_zip.py"),
    "--input", inputApk,
    "--output", outputApk,
    "--report", reportFile
  ], cwd);
  const report = JSON.parse(fs.readFileSync(reportFile, "utf8"));
  if (!report.gate_passed || report.output_entries !== report.unique_output_entries) {
    throw new Error("Canonical APK duplicate-entry gate failed");
  }
  assertUniqueArchiveEntries(await zipList(outputApk));
  return report;
}

async function optimizeCompiledResources(tools, unsignedApk, decodedDir, jobDir, buildId, collapseNamesOverride, preservePaths = false) {
  if (!tools.aapt2) return { applied: false, reason: "aapt2-unavailable", collapsedNames: false };
  const collapseNames = typeof collapseNamesOverride === "boolean"
    ? collapseNamesOverride
    : !hasDynamicResourceLookup(decodedDir);
  const optimized = path.join(jobDir, "resources-obfuscated.apk");
  const canonical = path.join(jobDir, "resources-obfuscated-canonical.apk");
  const canonicalReport = path.join(jobDir, "resource-canonicalization.json");
  const mapFile = path.join(jobDir, "resource-obfuscation-map.txt");
  await run(tools.aapt2, resourceOptimizeArgs(unsignedApk, optimized, mapFile, collapseNames, preservePaths), jobDir);
  if (!fs.existsSync(optimized) || fs.statSync(optimized).size < 1024) throw new Error("aapt2 resource optimization produced no APK");
  const archive = await canonicalizeApkArchive(tools, optimized, canonical, canonicalReport, jobDir);
  fs.copyFileSync(canonical, unsignedApk);
  const privateMap = path.join(PRIVATE_ARTIFACTS, `${buildId}-resource-obfuscation-map.txt`);
  if (fs.existsSync(mapFile)) fs.copyFileSync(mapFile, privateMap);
  return {
    applied: true,
    reason: preservePaths
      ? (collapseNames ? "names-obfuscated-paths-preserved" : "resource-values-deduplicated-paths-preserved")
      : (collapseNames ? "paths-and-names-obfuscated" : "paths-obfuscated-names-kept-for-dynamic-lookup"),
    collapsedNames: collapseNames,
    pathsPreserved: preservePaths,
    privateMap: path.basename(privateMap),
    duplicateEntriesRemoved: archive.duplicate_entries_removed,
    canonicalArchiveSha256: archive.output_sha256
  };
}

function jarCommand() {
  const javaHome = process.env.JAVA_HOME || (fs.existsSync("D:\\android\\jbr") ? "D:\\android\\jbr" : "");
  return firstExisting([path.join(javaHome, "bin", "jar.exe"), path.join(javaHome, "bin", "jar"), "jar"]) || "jar";
}

function newestDir(parent) {
  if (!fs.existsSync(parent)) return "";
  const dirs = fs.readdirSync(parent).filter((d) => fs.statSync(path.join(parent, d)).isDirectory()).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
  return dirs[0] ? path.join(parent, dirs[0]) : "";
}

function firstExisting(candidates) {
  const commands = new Set(["java", "javac", "python", "python3"]);
  for (const c of candidates) if (c && (commands.has(c) || fs.existsSync(c))) return c;
  return "";
}

function accessUrls() {
  const urls = PUBLIC_URL ? [PUBLIC_URL] : [`http://127.0.0.1:${PORT}`];
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family === "IPv4" && !entry.internal) urls.push(`http://${entry.address}:${PORT}`);
    }
  }
  return [...new Set(urls)];
}

function listFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? listFiles(full) : full;
  });
}

function saveBody(req, filePath) {
  return new Promise((resolve, reject) => {
    const out = fs.createWriteStream(filePath);
    req.pipe(out);
    req.on("error", reject);
    out.on("finish", resolve);
    out.on("error", reject);
  });
}

function run(command, args, cwd) {
  return new Promise((resolve, reject) => {
    const useShell = /\.(bat|cmd)$/i.test(command);
    const env = { ...process.env };
    if (!env.JAVA_HOME && fs.existsSync("D:\\android\\jbr")) env.JAVA_HOME = "D:\\android\\jbr";
    env.TEMP = PROCESS_TEMP;
    env.TMP = PROCESS_TEMP;
    env.TMPDIR = PROCESS_TEMP;
    const child = spawn(command, args, { cwd, shell: useShell, env });
    let text = "";
    child.stdout.on("data", (d) => text += d.toString());
    child.stderr.on("data", (d) => text += d.toString());
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(text) : reject(new Error(`${path.basename(command)} failed (${code})\n${text.slice(-3000)}`)));
  });
}

async function runCapture(command, args, cwd) {
  return run(command, args, cwd);
}

function normalizeUrl(url) {
  let value = String(url || "").trim();
  if (!value) value = DEFAULT_SERVER;
  if (!/^https?:\/\//i.test(value)) value = "https://" + value;
  return value.replace(/\/+$/, "");
}

function safeName(name) {
  return String(name).replace(/[\\/:*?"<>|]/g, "_").replace(/\s+/g, "_").slice(0, 120) || "input.apk";
}

function javaString(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
}

function ps(value) {
  return String(value).replace(/'/g, "''");
}

function json(res, body, status = 200) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...corsHeaders() });
  res.end(JSON.stringify(body));
}

function html(res, body) {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...corsHeaders() });
  res.end(body);
}

function file(res, filePath) {
  if (!filePath.startsWith(OUT) || !fs.existsSync(filePath)) return json(res, { ok: false, message: "file not found" }, 404);
  res.writeHead(200, { "content-type": "application/vnd.android.package-archive", "content-disposition": `attachment; filename="${path.basename(filePath)}"`, ...corsHeaders() });
  fs.createReadStream(filePath).pipe(res);
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "*",
    "access-control-allow-private-network": "true"
  };
}

function pageCommercial() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Android License Shield</title><link rel="icon" href="data:,">
<style>
:root{color-scheme:dark;--bg:#0b0d10;--band:#12161b;--panel:#181e25;--line:#303944;--text:#f4f7f9;--muted:#9ca8b3;--green:#44d19d;--yellow:#f1c75b;--red:#ff756d}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,"Segoe UI","Microsoft YaHei",sans-serif;letter-spacing:0}button,input,select{font:inherit}header{height:62px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 max(18px,env(safe-area-inset-left));background:#0e1115;position:sticky;top:0;z-index:5}header strong{font-size:17px}header span{margin-left:auto;color:var(--green);font-size:13px}.tabs{display:flex;gap:4px;padding:14px max(18px,calc((100vw - 1120px)/2));border-bottom:1px solid var(--line);background:var(--band)}.tab{border:0;background:transparent;color:var(--muted);height:38px;padding:0 16px;cursor:pointer;border-bottom:2px solid transparent}.tab.active{color:var(--text);border-color:var(--green)}main{width:min(1120px,100%);margin:0 auto;padding:22px 18px 64px}.view{display:none}.view.active{display:block}.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:18px}.toolbar h1{font-size:20px;margin:0}.toolbar .spacer{flex:1}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;margin-bottom:16px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.wide{grid-column:1/-1}label{display:grid;gap:7px;color:var(--muted);font-size:13px}input,select{width:100%;height:44px;border:1px solid var(--line);border-radius:6px;background:#0f1318;color:var(--text);padding:0 12px;outline:none}input:focus,select:focus{border-color:var(--green)}.drop{height:148px;border:1px dashed #52606d;border-radius:7px;display:grid;place-items:center;text-align:center;cursor:pointer;background:#10151a;color:var(--muted)}.drop.drag{border-color:var(--green);color:var(--text);background:#10221d}.drop strong{display:block;color:var(--text);margin-bottom:6px}.checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px}.check{display:flex;align-items:center;gap:9px;color:var(--text);height:40px}.check input{width:18px;height:18px;accent-color:var(--green)}button.action{height:42px;border:0;border-radius:6px;padding:0 16px;background:var(--green);color:#06130e;font-weight:700;cursor:pointer}button.secondary{background:#2a333d;color:var(--text)}button.danger{background:var(--red);color:#210504}button:disabled{opacity:.45;cursor:not-allowed}.status{min-height:78px;white-space:pre-wrap;background:#0f1318;border:1px solid var(--line);border-radius:6px;padding:13px;color:#c9d3da;font:13px/1.6 Consolas,monospace;overflow-wrap:anywhere}.download{display:inline-flex;margin-top:12px;color:#06130e;background:var(--yellow);padding:10px 14px;border-radius:6px;text-decoration:none;font-weight:700}.card-controls{display:grid;grid-template-columns:1.2fr .7fr .7fr .7fr;gap:10px;align-items:end}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:7px}table{width:100%;border-collapse:collapse;min-width:820px}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);font-size:13px}th{color:var(--muted);font-weight:600;background:#11161b;position:sticky;top:0}td code{color:var(--yellow)}.empty{text-align:center;color:var(--muted);padding:30px}.pill{display:inline-block;padding:3px 7px;border-radius:4px;background:#263039;color:#d9e2e8}.pill.active{background:#163d31;color:#72e7bb}.pill.disabled,.pill.expired{background:#462522;color:#ff9b93}@media(max-width:720px){header{height:56px}.grid,.checks,.card-controls{grid-template-columns:1fr}.wide{grid-column:auto}.panel{padding:14px}main{padding:16px 12px 48px}.tabs{padding-left:12px}.toolbar{align-items:flex-start;flex-wrap:wrap}.toolbar .spacer{display:none}.toolbar button{flex:1}.drop{height:126px}}
</style></head><body>
<header><strong>Android License Shield</strong><span id="health">连接中</span></header>
<nav class="tabs"><button class="tab active" data-view="protector">APK 保护</button><button class="tab" data-view="cards">卡密后台</button></nav>
<main>
<section id="protector" class="view active"><div class="toolbar"><h1>APK 保护与验证</h1><span class="spacer"></span><button id="check" class="action secondary">检查工具</button></div>
<div class="panel"><div id="drop" class="drop"><div><strong id="fileName">选择或拖入 APK</strong><span>仅支持 .apk</span></div></div><input id="file" type="file" accept=".apk,application/vnd.android.package-archive" hidden></div>
<div class="panel"><div class="grid">
<label>验证服务器<input id="server" value="${javaString(DEFAULT_SERVER)}"></label><label>App ID<input id="appId" value="demo_android_app"></label>
<label>卡密名称<input id="cardName" value="default"></label><label>卡密购买地址<input id="purchaseUrl" placeholder="https://"></label>
<label>跳转文字<input id="jumpText" maxlength="32"></label><label>跳转地址<input id="jumpUrl" placeholder="https://"></label>
</div><div class="checks"><label class="check"><input id="obfuscate" type="checkbox" checked>R8 与资源混淆</label><label class="check"><input id="vmp" type="checkbox" checked>VMP+ 与运行时保护</label><label class="check"><input id="strictGuard" type="checkbox">严格风险策略</label><label class="check"><input id="fullVmp" type="checkbox" checked>Android VMProtect 当前稳定版</label><label class="check"><input id="experimentalProtection" type="checkbox" checked>实验保护组合（Java2C/资源重封/SM3/Play Integrity 桥）</label></div></div>
<div class="toolbar"><button id="start" class="action" disabled>开始处理</button></div><div class="panel"><div id="status" class="status">等待 APK</div><div id="download"></div></div></section>
<section id="cards" class="view"><div class="toolbar"><h1>卡密后台</h1><span class="spacer"></span><button id="refreshCards" class="action secondary">刷新</button><button id="deleteFiltered" class="action danger">删除筛选结果</button></div>
<div class="panel"><div class="grid"><label>管理令牌<input id="adminToken" type="password" autocomplete="current-password"></label><label>名称筛选<input id="cardFilter" placeholder="留空显示全部"></label></div></div>
<div class="panel"><div class="card-controls"><label>卡密名称<input id="newCardName" value="default"></label><label>时长<input id="duration" type="number" min="1" value="1"></label><label>单位<select id="unit"><option value="minute">分钟</option><option value="hour">小时</option><option value="day" selected>天</option><option value="month">月</option><option value="year">年</option></select></label><label>数量<input id="count" type="number" min="1" max="200" value="1"></label></div><div class="toolbar" style="margin:14px 0 0"><button id="generateCards" class="action">生成卡密</button></div></div>
<div class="table-wrap"><table><thead><tr><th>卡密</th><th>名称</th><th>状态</th><th>时长</th><th>到期时间</th><th>设备</th></tr></thead><tbody id="cardRows"><tr><td class="empty" colspan="6">尚未加载</td></tr></tbody></table></div></section>
</main><script>
const q=(s)=>document.querySelector(s),qa=(s)=>Array.from(document.querySelectorAll(s));let selected=null;
qa('.tab').forEach((button)=>button.onclick=()=>{qa('.tab').forEach((x)=>x.classList.toggle('active',x===button));qa('.view').forEach((x)=>x.classList.toggle('active',x.id===button.dataset.view));if(button.dataset.view==='cards')loadCards();});
const statusBox=q('#status');function log(value){statusBox.textContent=value}function choose(file){if(!file||!file.name.toLowerCase().endsWith('.apk')){log('请选择 APK 文件');return}selected=file;q('#fileName').textContent=file.name;q('#start').disabled=false;log('已选择 '+file.name)}
q('#drop').onclick=()=>q('#file').click();q('#file').onchange=()=>choose(q('#file').files[0]);q('#drop').ondragover=(e)=>{e.preventDefault();q('#drop').classList.add('drag')};q('#drop').ondragleave=()=>q('#drop').classList.remove('drag');q('#drop').ondrop=(e)=>{e.preventDefault();q('#drop').classList.remove('drag');choose(e.dataTransfer.files[0])};
async function check(){try{const body=await fetch('/api/status',{cache:'no-store'}).then((r)=>r.json());q('#health').textContent=body.ok?'服务正常':'服务异常';q('#fullVmp').disabled=!body.tools.fullVmp;log('Java: '+Boolean(body.tools.java)+'\\nR8: '+Boolean(body.tools.r8)+'\\naapt2: '+Boolean(body.tools.aapt2)+'\\nFull VMP: '+(body.tools.fullVmp||'门禁未通过'))}catch(e){q('#health').textContent='连接失败';log(e.message)}}q('#check').onclick=check;check();
async function waitJob(id){for(let i=0;i<600;i++){await new Promise((r)=>setTimeout(r,2000));const response=await fetch('/api/jobs/'+encodeURIComponent(id),{cache:'no-store'});const job=await response.json();log((job.progress||job.status)+'\\n任务 '+id);if(job.status==='failed')throw new Error(job.message||'处理失败');if(job.status==='done')return job.result}throw new Error('处理超时')}
q('#start').onclick=async()=>{if(!selected)return;q('#start').disabled=true;q('#download').innerHTML='';try{const params=new URLSearchParams({fileName:selected.name,serverUrl:q('#server').value,appId:q('#appId').value,cardName:q('#cardName').value,purchaseUrl:q('#purchaseUrl').value,jumpText:q('#jumpText').value,jumpUrl:q('#jumpUrl').value,obfuscate:q('#obfuscate').checked?'1':'0',vmp:q('#vmp').checked?'1':'0',strictGuard:q('#strictGuard').checked?'1':'0',fullVmp:q('#fullVmp').checked?'1':'0',experimentalProtection:q('#experimentalProtection').checked?'1':'0'});const first=await fetch('/api/process?'+params,{method:'POST',body:selected}).then((r)=>r.json());if(!first.ok)throw new Error(first.message||'提交失败');const result=first.queued?await waitJob(first.jobId):first;const modules=result.experimentalModules?'实验模块: '+JSON.stringify(result.experimentalModules,null,2):'';log([result.transportMessage,result.signingMessage,result.obfuscationMessage,result.vmpMessage,'资源: '+result.resourceProtection.reason,'Assets: '+result.assetProtection.reason,modules].filter(Boolean).join('\\n'));const link=document.createElement('a');link.className='download';link.href=result.file;link.textContent='下载 '+result.fileName;q('#download').appendChild(link)}catch(e){log('处理失败\\n'+e.message)}finally{q('#start').disabled=false}};
function headers(){return {'content-type':'application/json','x-admin-token':q('#adminToken').value}}function fmtTime(value){return value?new Date(value*1000).toLocaleString():'-'}function fmtDuration(value){if(!value)return '-';if(value%86400===0)return value/86400+' 天';if(value%3600===0)return value/3600+' 小时';return Math.ceil(value/60)+' 分钟'}
async function loadCards(){try{const name=q('#cardFilter').value.trim();const response=await fetch('/admin/cards?cardName='+encodeURIComponent(name),{headers:headers(),cache:'no-store'});const body=await response.json();if(!response.ok||!body.ok)throw new Error(body.message||'加载失败');const rows=q('#cardRows');rows.innerHTML='';if(!body.cards.length){rows.innerHTML='<tr><td class="empty" colspan="6">没有匹配的卡密</td></tr>';return}body.cards.forEach((card)=>{const tr=document.createElement('tr');[card.cardKey,card.cardName,card.status,fmtDuration(card.durationSeconds),fmtTime(card.expiresAt),card.deviceId||'-'].forEach((value,index)=>{const td=document.createElement('td');if(index===0){const code=document.createElement('code');code.textContent=value;td.appendChild(code)}else if(index===2){const span=document.createElement('span');span.className='pill '+value;span.textContent=value;td.appendChild(span)}else td.textContent=value;tr.appendChild(td)});rows.appendChild(tr)})}catch(e){q('#cardRows').innerHTML='<tr><td class="empty" colspan="6">'+String(e.message).replace(/[<>]/g,'')+'</td></tr>'}}
q('#refreshCards').onclick=loadCards;q('#cardFilter').onchange=loadCards;q('#generateCards').onclick=async()=>{try{const body=await fetch('/admin/cards',{method:'POST',headers:headers(),body:JSON.stringify({cardName:q('#newCardName').value,duration:Number(q('#duration').value),unit:q('#unit').value,count:Number(q('#count').value)})}).then((r)=>r.json());if(!body.ok)throw new Error(body.message||'生成失败');q('#cardFilter').value=q('#newCardName').value;await loadCards()}catch(e){alert(e.message)}};q('#deleteFiltered').onclick=async()=>{const name=q('#cardFilter').value.trim();if(!confirm(name?'删除名称为 '+name+' 的全部卡密？':'删除全部卡密？'))return;try{const body=await fetch('/admin/cards?cardName='+encodeURIComponent(name),{method:'DELETE',headers:headers()}).then((r)=>r.json());if(!body.ok)throw new Error(body.message||'删除失败');await loadCards()}catch(e){alert(e.message)}};
</script></body></html>`;
}

function pageV2() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>APK 妤犲矁鐦夋稉搴濈箽閹?/title>
  <style>
    :root{color-scheme:light;--bg:#f4f6f8;--panel:#fff;--text:#1f2933;--muted:#667085;--line:#d9e0e7;--brand:#1769aa;--ok:#087f5b;--terminal:#111827}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,"Microsoft YaHei",sans-serif}.wrap{max-width:980px;margin:auto;padding:22px 14px 40px}h1{font-size:26px;margin:0 0 6px}h2{font-size:18px;margin:0 0 14px}.muted{color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin-top:14px}.protocol{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.protocol span{border:1px solid #b9dccf;color:var(--ok);background:#f1fbf7;border-radius:6px;padding:6px 8px;font-size:13px}.drop{border:2px dashed #8aa4c4;border-radius:8px;padding:30px 16px;text-align:center;background:#f8fbff;cursor:pointer}.drop.drag{background:#eaf4ff}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.wide{grid-column:1/-1}label{display:block;font-size:14px;font-weight:700}input{width:100%;height:40px;margin-top:6px;border:1px solid var(--line);border-radius:6px;padding:8px 10px;background:#fff;color:var(--text)}.checks{display:grid;gap:8px;margin-top:14px}.checks label{font-weight:400}.checks input{width:auto;height:auto;margin:0 7px 0 0}.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:14px}button{min-height:40px;border:0;border-radius:6px;background:var(--brand);color:#fff;font-weight:700;padding:0 14px;cursor:pointer}button:disabled{opacity:.55;cursor:not-allowed}.ghost{background:#fff;color:var(--text);border:1px solid var(--line)}.status{white-space:pre-wrap;background:var(--terminal);color:#d7fff5;padding:14px;border-radius:8px;min-height:120px;line-height:1.55}.download{display:inline-block;margin-top:12px;color:var(--brand);font-weight:700}@media(max-width:720px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}.wrap{padding:14px 10px 28px}button{min-height:44px;width:100%}}
  </style>
</head>
<body><main class="wrap">
  <h1>APK 妤犲矁鐦夋稉搴濈箽閹?/h1>
  <div class="muted">娑撳﹣绱跺鑼椽鐠?APK閿涘矁鍤滈崝銊ュ閸忋儱宕辩€靛棝鐛欑拠浣歌嫙閹稿灏柊宥囨畱 ARM64 profile 閹笛嗩攽娣囨繃濮㈤妴?/div>
  <div class="protocol"><span>RSA-4096-OAEP</span><span>AES-256-GCM</span><span>RSA-PSS-4096</span><span>SM4/SM2/SM3</span><span>闂呭繑婧€ IV 闂冩煡鍣搁弨?/span></div>

  <section class="panel">
    <h2>闁瀚?APK</h2>
    <div id="drop" class="drop"><b id="fileName">閻愮懓鍤柅澶嬪閹存牗瀚嬮崗?APK</b><div class="muted" style="margin-top:6px">閺傚洣娆㈤崣顏勫絺闁礁鍩岃ぐ鎾冲 APK 婢跺嫮鎮婇張宥呭</div><input id="file" type="file" accept=".apk" hidden></div>
  </section>

  <section class="panel">
    <h2>妤犲矁鐦夐柊宥囩枂</h2>
    <div class="grid">
      <label class="wide">妤犲矁鐦夐崥搴″酱閸︽澘娼?input id="server" value="${DEFAULT_SERVER}"></label>
      <label>App ID<input id="appId" value="demo_android_app"></label>
      <label>閸椻€崇槕閸氬秶袨<input id="cardName" value="姒涙顓绘潪顖欐"></label>
      <label>閸椻€崇槕鐠愵厺鎷遍崷鏉挎絻<input id="purchaseUrl" placeholder="娑撳秴锝為崚娆庣瑝閺勫墽銇?></label>
      <label>鐠哄疇娴嗛弬鍥х摟<input id="jumpText" placeholder="娓氬顩ч敍姘暭閺傚湱缍夌粩?></label>
      <label class="wide">鐠哄疇娴嗙純鎴濇絻<input id="jumpUrl" placeholder="娑撳秴锝為崚娆庣瑝閺勫墽銇?></label>
    </div>
    <div class="checks">
      <label><input id="obfuscate" type="checkbox" checked>R8 濞ｉ攱绌宀冪槈濡€虫健</label>
      <label><input id="vmp" type="checkbox" checked>鏉╂劘顢戦弮璺虹暚閺佸瓨鈧佲偓浣稿冀鐠嬪啳鐦崪灞藉冀 Hook 娣囨繃濮?/label>
      <label><input id="strictGuard" type="checkbox">娑撱儲鐗搁崣宥嗘暈閸忋儻绱欏鍡樼仸閻滎垰顣ㄦ稊鐔稿閹搭亷绱?/label>
      <label><input id="fullVmp" type="checkbox" checked>Android VMProtect current stable profile</label>
    </div>
    <div class="bar"><button id="start" disabled>瀵偓婵顦╅悶?APK</button><button id="check" class="ghost" type="button">濡偓濞村顦╅悶鍡欏箚婢?/button></div>
  </section>

  <section class="panel"><h2>婢跺嫮鎮婇悩鑸碘偓?/h2><div id="status" class="status">缁涘绶?APK...</div><div id="download"></div></section>
</main>
<script>
const q=(s)=>document.querySelector(s);let selected=null;
const drop=q('#drop'),file=q('#file'),start=q('#start'),statusBox=q('#status'),download=q('#download');
function log(text){statusBox.textContent=text}
function choose(input){if(!input||!input.name.toLowerCase().endsWith('.apk')){log('鐠囩兘鈧瀚?APK 閺傚洣娆?);return}selected=input;q('#fileName').textContent=input.name;start.disabled=false;log('瀹告煡鈧瀚ㄩ敍?+input.name+'\\n閻愮懓鍤垾婊冪磻婵顦╅悶?APK閳ユ繄鎴风紒顓溾偓?)}
drop.onclick=()=>file.click();file.onchange=()=>choose(file.files[0]);drop.ondragover=(e)=>{e.preventDefault();drop.classList.add('drag')};drop.ondragleave=()=>drop.classList.remove('drag');drop.ondrop=(e)=>{e.preventDefault();drop.classList.remove('drag');choose(e.dataTransfer.files[0])};
async function waitJob(id){for(let i=0;i<600;i++){await new Promise((resolve)=>setTimeout(resolve,2000));const response=await fetch('/api/jobs/'+encodeURIComponent(id),{cache:'no-store'});const job=await response.json();if(!response.ok)throw new Error(job.message||'鐠囪褰囨禒璇插婢惰精瑙?);log((job.progress||'娴滄垹顏锝呮躬婢跺嫮鎮?APK')+'\\n\\n娴犺濮熼崣鍑ょ窗'+id);if(job.status==='done'&&job.result)return job.result;if(job.status==='failed')throw new Error(job.message||'APK 婢跺嫮鎮婃径杈Е')}throw new Error('APK 婢跺嫮鎮婄搾鍛扮箖 20 閸掑棝鎸?)}
q('#check').onclick=async()=>{log('濮濓絽婀Λ鈧ù瀣槱閻炲棛骞嗘晶?..');try{const response=await fetch('/api/status',{cache:'no-store'});const body=await response.json();if(!body.ok)throw new Error(body.message||'濡偓濞村銇戠拹?);const tools=body.tools||{};log('婢跺嫮鎮婇崳銊︻劀鐢珕\nR8閿?+(tools.r8?'閸欘垳鏁?:'娑撳秴褰查悽?)+'\\n妤犲矁鐦夊Ο鈥虫健娣囨繃濮㈤敍?+(tools.vmp?'閸欘垳鏁?:'娑撳秴褰查悽?)+'\\nARM64 Full VMProtect閿?+(tools.fullVmp?tools.fullVmp:'娑撳秴褰查悽?))}catch(error){log('濡偓濞村銇戠拹銉窗'+(error.message||error))}};
start.onclick=async()=>{if(!selected)return;start.disabled=true;download.innerHTML='';log('濮濓絽婀稉濠佺炊 APK...');const params=new URLSearchParams({fileName:selected.name,serverUrl:q('#server').value,appId:q('#appId').value,cardName:q('#cardName').value,purchaseUrl:q('#purchaseUrl').value,jumpText:q('#jumpText').value,jumpUrl:q('#jumpUrl').value,obfuscate:q('#obfuscate').checked?'1':'0',vmp:q('#vmp').checked?'1':'0',strictGuard:q('#strictGuard').checked?'1':'0',fullVmp:q('#fullVmp').checked?'1':'0'});try{const response=await fetch('/api/process?'+params.toString(),{method:'POST',body:selected});const first=await response.json();if(!response.ok||!first.ok)throw new Error(first.message||'閹绘劒姘︽径杈Е');const body=first.queued?await waitJob(first.jobId):first;log('婢跺嫮鎮婄€瑰本鍨歕\n閸栧懎鎮曢敍?+body.packageName+'\\n閸樼喎鎯庨崝銊┿€夐敍?+body.launcher+'\\n'+(body.transportMessage||'V4 閸欏苯顨滄禒璺虹暔閸忋劋绱舵潏鎾冲嚒閸氼垳鏁?)+'\\n'+(body.signingMessage||'')+'\\n'+body.obfuscationMessage+'\\n'+body.vmpMessage);const link=document.createElement('a');link.className='download';link.href=body.file;link.textContent='娑撳娴?'+body.fileName;download.appendChild(link)}catch(error){log('婢跺嫮鎮婃径杈Е閿涙瓡\n'+(error.message||error))}finally{start.disabled=false}};
</script></body></html>`;
}

module.exports = {
  assertUniqueArchiveEntries,
  buildApk,
  canonicalizeApkArchive,
  deleteCardsByName,
  filterCardsByName,
  fullVmprotectReleaseCoverage,
  injectFullVmprotect,
  injectNativeGuard,
  loadDccSelectionRegistry,
  nativeGuardIntegrityEntries,
  prepareFullVmprotectInput,
  resolveDccJava2cProfile,
  resourceOptimizeArgs,
  sha256File,
  summarizeFullVmprotectProfile,
  validateFullVmprotectProfile,
  verifyApkSignatureOutput,
  verifyExperimentalFullVmprotectApkArtifacts,
  verifyFullVmprotectApkArtifacts,
  writeJavaSources
};
