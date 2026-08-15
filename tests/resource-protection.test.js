const assert = require("node:assert/strict");
const test = require("node:test");

const { assertUniqueArchiveEntries, resourceOptimizeArgs } = require("../server");

test("uses aapt2 path shortening and name collapsing for static resource lookups", () => {
  const args = resourceOptimizeArgs("input.apk", "output.apk", "map.txt", true);
  assert.deepEqual(args, [
    "optimize",
    "--shorten-resource-paths",
    "--deduplicate-entry-values",
    "--collapse-resource-names",
    "--save-obfuscation-map",
    "map.txt",
    "-o",
    "output.apk",
    "input.apk"
  ]);
});

test("keeps resource names when runtime getIdentifier lookup exists", () => {
  const args = resourceOptimizeArgs("input.apk", "output.apk", "map.txt", false);
  assert.equal(args.includes("--shorten-resource-paths"), true);
  assert.equal(args.includes("--collapse-resource-names"), false);
});

test("can preserve paths while collapsing resource names for portable Full VMP rebuilds", () => {
  const args = resourceOptimizeArgs("input.apk", "output.apk", "map.txt", true, true);
  assert.equal(args.includes("--shorten-resource-paths"), false);
  assert.equal(args.includes("--collapse-resource-names"), true);
  assert.equal(args.includes("--deduplicate-entry-values"), true);
});

test("rejects duplicate APK entries before immutable-root generation", () => {
  assert.deepEqual(
    assertUniqueArchiveEntries(["classes.dex", "res/a.xml"]),
    { entries: 2, uniqueEntries: 2, portableUniqueEntries: 2 }
  );
  assert.throws(
    () => assertUniqueArchiveEntries(["classes.dex", "res/a.xml", "res/a.xml"]),
    /duplicate ZIP entries: res\/a\.xml/
  );
  assert.throws(
    () => assertUniqueArchiveEntries(["res/a.xml", "res/A.xml"]),
    /case-colliding ZIP entries/
  );
});
