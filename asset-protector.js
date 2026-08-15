const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const OPEN = /^(\s*)invoke-virtual\s+\{([^}]+)\},\s+Landroid\/content\/res\/AssetManager;->open\(Ljava\/lang\/String;\)Ljava\/io\/InputStream;\s*$/;
const OPEN_MODE = /^(\s*)invoke-virtual\s+\{([^}]+)\},\s+Landroid\/content\/res\/AssetManager;->open\(Ljava\/lang\/String;I\)Ljava\/io\/InputStream;\s*$/;
const CONST_STRING = /^\s*const-string(?:\/jumbo)?\s+([vp]\d+),\s+"((?:\\.|[^"\\])*)"\s*$/;

function listFiles(root, suffix) {
  if (!fs.existsSync(root)) return [];
  const output = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name);
    if (entry.isDirectory()) output.push(...listFiles(file, suffix));
    else if (!suffix || file.endsWith(suffix)) output.push(file);
  }
  return output;
}

function decodeSmaliString(value) {
  return value.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t")
    .replace(/\\"/g, '"').replace(/\\\\/g, "\\");
}

function registerWritten(line, register) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith(".") || trimmed.startsWith(":")) return false;
  return new RegExp(`^(?:move(?:-[^ ]+)?|move-result(?:-[^ ]+)?|const(?:-[^ ]+)?|new-instance|new-array|iget(?:-[^ ]+)?|sget(?:-[^ ]+)?|array-length|check-cast)\\s+${register}(?:,|\\s)`).test(trimmed);
}

function findConstant(lines, index, register) {
  for (let i = index - 1; i >= 0 && i >= index - 24; i -= 1) {
    if (lines[i].trim().startsWith(".method")) break;
    const match = lines[i].match(CONST_STRING);
    if (match && match[1] === register) return decodeSmaliString(match[2]);
    if (registerWritten(lines[i], register)) break;
  }
  return null;
}

function parseRegisters(value) {
  if (value.includes("..")) return null;
  const registers = value.split(",").map((item) => item.trim());
  return registers.every((item) => /^[vp]\d+$/.test(item)) ? registers : null;
}

function analyzeSmali(file) {
  const text = fs.readFileSync(file, "utf8");
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(/\r?\n/);
  const calls = [];
  let dynamic = false;
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(OPEN) || lines[index].match(OPEN_MODE);
    if (!match) continue;
    const registers = parseRegisters(match[2]);
    const expected = lines[index].match(OPEN_MODE) ? 3 : 2;
    if (!registers || registers.length !== expected) { dynamic = true; continue; }
    const asset = findConstant(lines, index, registers[1]);
    if (asset === null) { dynamic = true; continue; }
    calls.push({ index, indent: match[1], registers, asset, mode: expected === 3 });
  }
  return { file, lines, eol, calls, dynamic };
}

function safeAssetPath(value) {
  const normalized = String(value || "").replace(/\\/g, "/").replace(/^\/+/, "");
  if (!normalized || normalized.includes("../") || normalized.includes("\0")) return "";
  return normalized;
}

function encryptEntry(clear, key, buildId, asset) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from(`AVMP-ASSET-1\n${buildId}\n${asset}\n${clear.length}`, "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(clear), cipher.final()]);
  const tag = cipher.getAuthTag();
  const header = Buffer.alloc(20);
  header.write("AVM1", 0, "ascii");
  header.writeUInt32BE(clear.length, 4);
  iv.copy(header, 8);
  return Buffer.concat([header, tag, ciphertext]);
}

function protectStaticAssets(decodedDir, packageName, buildId) {
  const smaliFiles = fs.readdirSync(decodedDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^smali(?:_classes\d+)?$/.test(entry.name))
    .flatMap((entry) => listFiles(path.join(decodedDir, entry.name), ".smali"));
  const analyses = smaliFiles.map(analyzeSmali);
  const calls = analyses.flatMap((item) => item.calls);
  if (analyses.some((item) => item.dynamic)) return { applied: false, reason: "dynamic-asset-call-present", entries: [], rewrittenCalls: 0 };
  if (!calls.length) return { applied: false, reason: "no-static-asset-calls", entries: [], rewrittenCalls: 0 };

  const assetsRoot = path.join(decodedDir, "assets");
  const selected = [...new Set(calls.map((call) => safeAssetPath(call.asset)).filter(Boolean))]
    .filter((asset) => fs.existsSync(path.join(assetsRoot, ...asset.split("/"))));
  if (!selected.length) return { applied: false, reason: "referenced-assets-not-packaged", entries: [], rewrittenCalls: 0 };
  const selectedSet = new Set(selected);
  if (calls.some((call) => !selectedSet.has(safeAssetPath(call.asset)))) {
    return { applied: false, reason: "mixed-platform-or-missing-assets", entries: [], rewrittenCalls: 0 };
  }

  const key = crypto.randomBytes(32);
  const shareA = crypto.randomBytes(32);
  const shareB = Buffer.alloc(32);
  for (let i = 0; i < 32; i += 1) shareB[i] = key[i] ^ shareA[i];
  const outputDir = path.join(assetsRoot, ".avmp");
  const entries = [];
  for (const asset of selected) {
    const size = fs.statSync(path.join(assetsRoot, ...asset.split("/"))).size;
    if (size > 8 * 1024 * 1024) return { applied: false, reason: "asset-exceeds-authenticated-buffer-limit", entries: [], rewrittenCalls: 0 };
  }
  fs.mkdirSync(outputDir, { recursive: true });
  for (const asset of selected.sort()) {
    const source = path.join(assetsRoot, ...asset.split("/"));
    const clear = fs.readFileSync(source);
    const id = crypto.createHash("sha256").update(buildId).update("\0").update(asset).digest("hex").slice(0, 32);
    const stored = `.avmp/${id}.bin`;
    fs.writeFileSync(path.join(assetsRoot, ...stored.split("/")), encryptEntry(clear, key, buildId, asset));
    fs.rmSync(source);
    entries.push({ path: asset, stored, size: clear.length, sha256: crypto.createHash("sha256").update(clear).digest("hex") });
  }

  let rewrittenCalls = 0;
  const owner = `L${packageName.replace(/\./g, "/")}/ProtectedAssets;`;
  for (const analysis of analyses) {
    let changed = false;
    for (const call of analysis.calls) {
      if (!selectedSet.has(safeAssetPath(call.asset))) continue;
      const args = call.registers.join(", ");
      const signature = call.mode
        ? "open(Landroid/content/res/AssetManager;Ljava/lang/String;I)Ljava/io/InputStream;"
        : "open(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/InputStream;";
      analysis.lines[call.index] = `${call.indent}invoke-static {${args}}, ${owner}->${signature}`;
      rewrittenCalls += 1;
      changed = true;
    }
    if (changed) fs.writeFileSync(analysis.file, analysis.lines.join(analysis.eol), "utf8");
  }
  return {
    applied: true,
    reason: "authenticated-static-assets",
    entries,
    rewrittenCalls,
    keyShareA: shareA.toString("base64"),
    keyShareB: shareB.toString("base64"),
    buildId
  };
}

module.exports = { analyzeSmali, decryptEntryForTest, protectStaticAssets };

function decryptEntryForTest(stored, key, buildId, asset) {
  if (stored.length < 36 || stored.subarray(0, 4).toString("ascii") !== "AVM1") throw new Error("invalid asset envelope");
  const size = stored.readUInt32BE(4);
  const iv = stored.subarray(8, 20);
  const tag = stored.subarray(20, 36);
  const ciphertext = stored.subarray(36);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(`AVMP-ASSET-1\n${buildId}\n${asset}\n${size}`, "utf8"));
  decipher.setAuthTag(tag);
  const clear = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (clear.length !== size) throw new Error("asset size mismatch");
  return clear;
}
