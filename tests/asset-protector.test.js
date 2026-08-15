const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { decryptEntryForTest, protectStaticAssets } = require("../asset-protector");

test("encrypts statically traced assets and rewrites AssetManager.open", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "asset-protector-"));
  try {
    const smali = path.join(root, "smali", "com", "example", "Main.smali");
    const asset = path.join(root, "assets", "www", "index.html");
    fs.mkdirSync(path.dirname(smali), { recursive: true });
    fs.mkdirSync(path.dirname(asset), { recursive: true });
    fs.writeFileSync(asset, "<h1>protected</h1>");
    fs.writeFileSync(smali, [
      ".class public Lcom/example/Main;",
      ".method public load(Landroid/content/res/AssetManager;)Ljava/io/InputStream;",
      "    .locals 1",
      "    const-string v0, \"www/index.html\"",
      "    invoke-virtual {p1, v0}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;",
      "    move-result-object v0",
      "    return-object v0",
      ".end method"
    ].join("\n"));

    const result = protectStaticAssets(root, "com.example.fixture", "build-fixture");
    assert.equal(result.applied, true);
    assert.equal(result.rewrittenCalls, 1);
    assert.equal(fs.existsSync(asset), false);
    const changed = fs.readFileSync(smali, "utf8");
    assert.match(changed, /ProtectedAssets;->open/);
    const encrypted = fs.readFileSync(path.join(root, "assets", ...result.entries[0].stored.split("/")));
    const a = Buffer.from(result.keyShareA, "base64");
    const b = Buffer.from(result.keyShareB, "base64");
    const key = Buffer.alloc(32);
    for (let i = 0; i < key.length; i += 1) key[i] = a[i] ^ b[i];
    const clear = decryptEntryForTest(encrypted, key, result.buildId, result.entries[0].path);
    assert.equal(clear.toString(), "<h1>protected</h1>");
    assert.equal(result.entries[0].sha256, crypto.createHash("sha256").update(clear).digest("hex"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("skips all resource changes when an AssetManager path is dynamic", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "asset-protector-dynamic-"));
  try {
    const smali = path.join(root, "smali", "Main.smali");
    fs.mkdirSync(path.dirname(smali), { recursive: true });
    fs.writeFileSync(smali, "    invoke-virtual {p1, p2}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;\n");
    const result = protectStaticAssets(root, "com.example.fixture", "build-fixture");
    assert.equal(result.applied, false);
    assert.equal(result.reason, "dynamic-asset-call-present");
    assert.doesNotMatch(fs.readFileSync(smali, "utf8"), /ProtectedAssets/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
