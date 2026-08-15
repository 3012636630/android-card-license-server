const fs = require("fs");
const path = require("path");

const LOG_CALL = /^(\s*)invoke-static(?:\/range)?\s+\{[^}]*\},\s+Landroid\/util\/Log;->(?:v|d|i|w|e|wtf|println|isLoggable)\([^)]*\)[IZ]\s*$/;
const MOVE_RESULT = /^(\s*)move-result\s+([vp]\d+)\s*$/;
const MOCK_LOCATION = /^(\s*)invoke-virtual\s+\{([vp]\d+)\},\s+Landroid\/location\/Location;->isFromMockProvider\(\)Z\s*$/;

function listSmali(root) {
  const output = [];
  if (!fs.existsSync(root)) return output;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name);
    if (entry.isDirectory()) output.push(...listSmali(file));
    else if (file.endsWith(".smali")) output.push(file);
  }
  return output;
}

function stripReleaseLogs(decodedDir) {
  let removedCalls = 0;
  let rewrittenResults = 0;
  let changedFiles = 0;
  for (const entry of fs.readdirSync(decodedDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^smali(?:_classes\d+)?$/.test(entry.name)) continue;
    for (const file of listSmali(path.join(decodedDir, entry.name))) {
      const text = fs.readFileSync(file, "utf8");
      const eol = text.includes("\r\n") ? "\r\n" : "\n";
      const lines = text.split(/\r?\n/);
      let changed = false;
      for (let i = 0; i < lines.length; i += 1) {
        const call = lines[i].match(LOG_CALL);
        if (!call) continue;
        lines[i] = `${call[1]}nop`;
        removedCalls += 1;
        changed = true;
        let next = i + 1;
        while (next < lines.length && (!lines[next].trim() || lines[next].trim().startsWith("#"))) next += 1;
        const result = next < lines.length ? lines[next].match(MOVE_RESULT) : null;
        if (result) {
          lines[next] = `${result[1]}const/4 ${result[2]}, 0x0`;
          rewrittenResults += 1;
        }
      }
      if (changed) {
        fs.writeFileSync(file, lines.join(eol), "utf8");
        changedFiles += 1;
      }
    }
  }
  return { applied: true, removedCalls, rewrittenResults, changedFiles };
}

function instrumentRuntimeSignals(decodedDir, packageName) {
  const owner = "L" + packageName.replace(/\./g, "/") + "/RuntimeRisk;";
  let locationCalls = 0;
  let changedFiles = 0;
  for (const entry of fs.readdirSync(decodedDir, { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^smali(?:_classes\d+)?$/.test(entry.name)) continue;
    for (const file of listSmali(path.join(decodedDir, entry.name))) {
      const text = fs.readFileSync(file, "utf8");
      const eol = text.includes("\r\n") ? "\r\n" : "\n";
      const lines = text.split(/\r?\n/);
      let changed = false;
      for (let i = 0; i < lines.length; i += 1) {
        const match = lines[i].match(MOCK_LOCATION);
        if (!match) continue;
        lines[i] = match[1] + "invoke-static {" + match[2] + "}, " + owner + "->isMockLocation(Landroid/location/Location;)Z";
        locationCalls += 1;
        changed = true;
      }
      if (changed) {
        fs.writeFileSync(file, lines.join(eol), "utf8");
        changedFiles += 1;
      }
    }
  }
  return { applied: true, locationCalls, changedFiles };
}

module.exports = { instrumentRuntimeSignals, stripReleaseLogs };
