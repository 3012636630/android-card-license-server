const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { instrumentRuntimeSignals, stripReleaseLogs } = require("../smali-hardening");

test("removes Android Log calls and preserves result register typing", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "smali-logs-"));
  try {
    const file = path.join(root, "smali", "Fixture.smali");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, [
      "    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I",
      "    move-result v2",
      "    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I",
      "    return-void"
    ].join("\n"));
    const result = stripReleaseLogs(root);
    assert.deepEqual(result, { applied: true, removedCalls: 2, rewrittenResults: 1, changedFiles: 1 });
    const changed = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(changed, /Landroid\/util\/Log/);
    assert.match(changed, /const\/4 v2, 0x0/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("routes mock-location checks through the centralized risk collector", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "smali-location-"));
  try {
    const file = path.join(root, "smali", "Fixture.smali");
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "    invoke-virtual {v3}, Landroid/location/Location;->isFromMockProvider()Z\n    move-result v0\n");
    const result = instrumentRuntimeSignals(root, "com.example.fixture");
    assert.deepEqual(result, { applied: true, locationCalls: 1, changedFiles: 1 });
    assert.match(fs.readFileSync(file, "utf8"), /Lcom\/example\/fixture\/RuntimeRisk;->isMockLocation/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
