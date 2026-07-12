const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawn } = require("child_process");

const ROOT = __dirname;
const TOOLS = path.join(ROOT, "tools");
const WORK = path.join(ROOT, "work");
const OUT = path.join(ROOT, "out");
const PORT = Number(process.env.PORT || 8789);
const DEFAULT_SERVER = process.env.DEFAULT_LICENSE_SERVER || "https://android-license-gateway-phone.pages.dev";
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/+$/, "");
const APKTOOL_VERSION = "3.0.2";
const APKTOOL_URL = `https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar`;

for (const dir of [TOOLS, WORK, OUT]) fs.mkdirSync(dir, { recursive: true });

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (req.method === "OPTIONS") {
      res.writeHead(204, corsHeaders());
      return res.end();
    }
    if (req.method === "GET" && url.pathname === "/") return html(res, page());
    if (req.method === "GET" && url.pathname === "/health") return json(res, { ok: true, service: "apk-license-packer" });
    if (req.method === "GET" && url.pathname.startsWith("/out/")) return file(res, path.join(OUT, decodeURIComponent(url.pathname.slice(5))));
    if (req.method === "GET" && url.pathname === "/api/status") return json(res, { ok: true, tools: await detectTools(), accessUrls: accessUrls() });
    if (req.method === "POST" && url.pathname === "/api/process") return await processUpload(req, res, url);
    return json(res, { ok: false, message: "not found" }, 404);
  } catch (error) {
    return json(res, { ok: false, message: error.message || String(error) }, 500);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`APK drag dashboard listening on 0.0.0.0:${PORT}`);
});

async function processUpload(req, res, url) {
  const originalName = safeName(url.searchParams.get("fileName") || "input.apk");
  const serverUrl = normalizeUrl(url.searchParams.get("serverUrl") || DEFAULT_SERVER);
  const appId = url.searchParams.get("appId") || "demo_android_app";
  const appSecret = url.searchParams.get("appSecret") || "change_this_app_secret";
  const rc4Key = url.searchParams.get("rc4Key") || "change_this_rc4_key";
  const obfuscate = url.searchParams.get("obfuscate") !== "0";
  const useVmp = url.searchParams.get("vmp") === "1";
  const id = new Date().toISOString().replace(/[-:.TZ]/g, "") + "-" + crypto.randomBytes(3).toString("hex");
  const jobDir = path.join(WORK, id);
  const decodedDir = path.join(jobDir, "decoded");
  const javaDir = path.join(jobDir, "java");
  const classesDir = path.join(jobDir, "classes");
  const dexDir = path.join(jobDir, "dex");
  fs.mkdirSync(jobDir, { recursive: true });

  const inputApk = path.join(jobDir, originalName);
  await saveBody(req, inputApk);

  const tools = await detectTools();
  if (!tools.java || !tools.javac || !tools.d8 || !tools.zipalign || !tools.apksigner || !tools.androidJar) {
    throw new Error("缺少 Java 或 Android SDK 工具，请先安装 Android Studio/SDK。");
  }
  const apktool = await ensureApktool();

  await run(tools.java, ["-jar", apktool, "d", "-f", inputApk, "-o", decodedDir], jobDir);
  const manifestPath = path.join(decodedDir, "AndroidManifest.xml");
  let manifest = fs.readFileSync(manifestPath, "utf8");
  const packageName = readPackageName(manifest);
  const launcher = readLauncherActivity(manifest, packageName);
  manifest = removeLauncherFilters(manifest);
  manifest = addInternetPermission(manifest);
  manifest = addLicenseActivity(manifest);
  fs.writeFileSync(manifestPath, manifest, "utf8");

  writeJavaSources(javaDir, packageName, launcher, serverUrl, appId, appSecret, rc4Key);
  fs.mkdirSync(classesDir, { recursive: true });
  const javaFiles = listFiles(javaDir).filter((f) => f.endsWith(".java"));
  await run(tools.javac, ["-encoding", "UTF-8", "-source", "8", "-target", "8", "-bootclasspath", tools.androidJar, "-d", classesDir, ...javaFiles], jobDir);
  fs.mkdirSync(dexDir, { recursive: true });
  let obfuscationMessage = "验证模块未混淆";
  if (obfuscate && tools.r8 && tools.jar) {
    const classesJar = path.join(jobDir, "license-classes.jar");
    const rules = path.join(jobDir, "r8-rules.pro");
    fs.writeFileSync(rules, [
      `-keep public class ${packageName}.LicenseActivity { public <init>(); public void onCreate(android.os.Bundle); }`,
      "-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod",
      "-dontwarn **"
    ].join("\n"), "utf8");
    await run(tools.jar, ["cf", classesJar, "-C", classesDir, "."], jobDir);
    await run(tools.java, ["-cp", tools.r8, "com.android.tools.r8.R8", "--release", "--min-api", "23", "--lib", tools.androidJar, "--pg-conf", rules, "--output", dexDir, classesJar], jobDir);
    obfuscationMessage = "验证模块已使用 R8 混淆";
  } else {
    await run(tools.d8, ["--min-api", "23", "--output", dexDir, ...listFiles(classesDir).filter((f) => f.endsWith(".class"))], jobDir);
    if (obfuscate) obfuscationMessage = "未找到 R8，验证框已注入但未混淆";
  }

  const unsignedApk = path.join(jobDir, "unsigned.apk");
  await run(tools.java, ["-jar", apktool, "b", decodedDir, "-o", unsignedApk], jobDir);
  const withDexApk = path.join(jobDir, "with-license.apk");
  fs.copyFileSync(unsignedApk, withDexApk);
  await addDex(withDexApk, path.join(dexDir, "classes.dex"));

  const alignedApk = path.join(jobDir, "aligned.apk");
  await run(tools.zipalign, ["-f", "-p", "4", withDexApk, alignedApk], jobDir);
  const keystore = await ensureKeystore(tools);
  const signedName = originalName.replace(/\.apk$/i, "") + "-license.apk";
  const signedApk = path.join(OUT, signedName);
  await run(tools.apksigner, [
    "sign",
    "--ks", keystore,
    "--ks-pass", "pass:android",
    "--key-pass", "pass:android",
    "--ks-key-alias", "androiddebugkey",
    "--out", signedApk,
    alignedApk
  ], jobDir);

  let finalName = signedName;
  let vmpMessage = "未启用 VMP 壳";
  if (useVmp) {
    const vmp = findVmpPacker();
    if (vmp) {
      finalName = originalName.replace(/\.apk$/i, "") + "-license-vmp.apk";
      await run(vmp, [signedApk, path.join(OUT, finalName)], jobDir);
      vmpMessage = "已调用 VMP 壳";
    } else {
      vmpMessage = "未找到 VMP 工具，已输出注入验证框并签名的 APK";
    }
  }

  return json(res, {
    ok: true,
    file: `/out/${encodeURIComponent(finalName)}`,
    fileName: finalName,
    packageName,
    launcher,
    serverUrl,
    obfuscationMessage,
    vmpMessage
  });
}

async function detectTools() {
  const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || path.join(os.homedir(), "AppData", "Local", "Android", "Sdk");
  const javaHome = process.env.JAVA_HOME || (fs.existsSync("D:\\android\\jbr") ? "D:\\android\\jbr" : "");
  const buildTools = newestDir(path.join(sdk, "build-tools"));
  const platform = newestDir(path.join(sdk, "platforms"));
  return {
    sdk,
    java: firstExisting([path.join(javaHome, "bin", "java.exe"), path.join(javaHome, "bin", "java"), "java"]),
    javac: firstExisting([path.join(javaHome, "bin", "javac.exe"), path.join(javaHome, "bin", "javac"), "javac"]),
    keytool: firstExisting([path.join(javaHome, "bin", "keytool.exe"), path.join(javaHome, "bin", "keytool"), "keytool"]),
    jar: firstExisting([path.join(javaHome, "bin", "jar.exe"), path.join(javaHome, "bin", "jar"), "jar"]),
    d8: firstExisting([path.join(buildTools || "", "d8.bat"), path.join(buildTools || "", "d8")]),
    r8: firstExisting([path.join(buildTools || "", "lib", "d8.jar")]),
    zipalign: firstExisting([path.join(buildTools || "", "zipalign.exe"), path.join(buildTools || "", "zipalign")]),
    apksigner: firstExisting([path.join(buildTools || "", "apksigner.bat"), path.join(buildTools || "", "apksigner")]),
    androidJar: platform ? path.join(platform, "android.jar") : "",
    apktool: fs.existsSync(path.join(TOOLS, `apktool_${APKTOOL_VERSION}.jar`)) ? path.join(TOOLS, `apktool_${APKTOOL_VERSION}.jar`) : "",
    vmp: findVmpPacker() || ""
  };
}

async function ensureApktool() {
  const jar = path.join(TOOLS, `apktool_${APKTOOL_VERSION}.jar`);
  if (fs.existsSync(jar)) return jar;
  const response = await fetch(APKTOOL_URL);
  if (!response.ok) throw new Error(`下载 apktool 失败：${response.status}`);
  const buffer = Buffer.from(await response.arrayBuffer());
  fs.writeFileSync(jar, buffer);
  return jar;
}

async function ensureKeystore(tools) {
  const keystore = path.join(TOOLS, "debug.keystore");
  if (fs.existsSync(keystore)) return keystore;
  await run(tools.keytool, [
    "-genkeypair",
    "-v",
    "-keystore", keystore,
    "-storepass", "android",
    "-alias", "androiddebugkey",
    "-keypass", "android",
    "-keyalg", "RSA",
    "-keysize", "2048",
    "-validity", "10000",
    "-dname", "CN=Android Debug,O=Android,C=US"
  ], ROOT);
  return keystore;
}

function readPackageName(manifest) {
  const match = manifest.match(/<manifest[\s\S]*?\spackage="([^"]+)"/);
  if (!match) throw new Error("无法读取 APK 包名");
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
  throw new Error("没有找到原 APP 启动 Activity");
}

function removeLauncherFilters(manifest) {
  return manifest.replace(/<intent-filter>[\s\S]*?android\.intent\.action\.MAIN[\s\S]*?android\.intent\.category\.LAUNCHER[\s\S]*?<\/intent-filter>/g, "");
}

function addInternetPermission(manifest) {
  if (manifest.includes('android.permission.INTERNET')) return manifest;
  return manifest.replace(/<application\b/, '    <uses-permission android:name="android.permission.INTERNET" />\n\n    <application');
}

function addLicenseActivity(manifest) {
  const activity = `
        <activity android:name=".LicenseActivity" android:screenOrientation="portrait" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
`;
  return manifest.replace(/<\/application>/, `${activity}    </application>`);
}

function normalizeActivityName(name, packageName) {
  if (name.startsWith(".")) return packageName + name;
  if (!name.includes(".")) return packageName + "." + name;
  return name;
}

function writeJavaSources(root, packageName, launcher, serverUrl, appId, appSecret, rc4Key) {
  const dir = path.join(root, ...packageName.split("."));
  fs.mkdirSync(dir, { recursive: true });
  const pkg = `package ${packageName};`;
  fs.writeFileSync(path.join(dir, "LicenseResult.java"), `${pkg}
final class LicenseResult {
  final boolean ok; final int code; final String message; final long expiresAt; final long remainingSeconds; final long nextHeartbeatSeconds;
  LicenseResult(boolean ok, int code, String message, long expiresAt, long remainingSeconds, long nextHeartbeatSeconds) {
    this.ok = ok; this.code = code; this.message = message; this.expiresAt = expiresAt; this.remainingSeconds = remainingSeconds; this.nextHeartbeatSeconds = nextHeartbeatSeconds;
  }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseConfig.java"), `${pkg}
import android.content.Context; import android.content.SharedPreferences; import java.util.*;
final class LicenseConfig {
  static final String DEFAULT_BASE_URL = "${javaString(serverUrl)}";
  static final String APP_ID = "${javaString(appId)}";
  static final String APP_SECRET = "${javaString(appSecret)}";
  static final String RC4_KEY = "${javaString(rc4Key)}";
  static final String APP_VERSION = "1.0";
  private static final String PREFS = "license_config"; private static final String KEY_BASE_URL = "base_url";
  static String getBaseUrl(Context c){ return normalize(c.getSharedPreferences(PREFS,0).getString(KEY_BASE_URL, DEFAULT_BASE_URL)); }
  static void saveBaseUrl(Context c, String v){ c.getSharedPreferences(PREFS,0).edit().putString(KEY_BASE_URL, normalize(v)).apply(); }
  static List<String> getBaseUrls(Context c){ ArrayList<String> u = new ArrayList<>(); add(u, getBaseUrl(c)); add(u, DEFAULT_BASE_URL); return u; }
  private static void add(ArrayList<String> u, String v){ if(v.length()>0 && !u.contains(v)) u.add(v); }
  private static String normalize(String v){ String u = v == null ? "" : v.trim(); if(u.length()==0) u = DEFAULT_BASE_URL; if(!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u; while(u.endsWith("/")) u = u.substring(0,u.length()-1); return u; }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseClient.java"), `${pkg}
import android.content.*; import org.json.*; import java.io.*; import java.net.*; import java.nio.charset.*; import java.security.*; import java.util.*;
final class LicenseClient {
  private final Context context; LicenseClient(Context c){ context = c.getApplicationContext(); }
  LicenseResult activate(String cardKey, String deviceId, String appVersion) throws Exception { JSONObject p = new JSONObject().put("cardKey",cardKey).put("deviceId",deviceId).put("appVersion",appVersion); return request("/api/activate", p); }
  LicenseResult heartbeat(String cardKey, String deviceId, String appVersion) throws Exception { JSONObject p = new JSONObject().put("cardKey",cardKey).put("deviceId",deviceId).put("appVersion",appVersion); return request("/api/heartbeat", p); }
  private LicenseResult request(String path, JSONObject payload) throws Exception { JSONObject env = makeEnvelope(payload); Exception last = null; for(String base: LicenseConfig.getBaseUrls(context)){ try { return once(base, path, env); } catch(Exception e){ last = e; } } throw last == null ? new IllegalStateException("网络验证失败") : last; }
  private LicenseResult once(String base, String path, JSONObject env) throws Exception { HttpURLConnection c=(HttpURLConnection)new URL(base+path).openConnection(); c.setRequestMethod("POST"); c.setConnectTimeout(20000); c.setReadTimeout(20000); c.setDoOutput(true); c.setRequestProperty("Content-Type","application/json; charset=utf-8"); OutputStream o=c.getOutputStream(); o.write(env.toString().getBytes(StandardCharsets.UTF_8)); o.close(); InputStream in=c.getResponseCode()>=400?c.getErrorStream():c.getInputStream(); JSONObject data = open(new JSONObject(readAll(in))); return new LicenseResult(data.optBoolean("ok",false), data.optInt("code",-1), data.optString("message",""), data.optLong("expiresAt",0), data.optLong("remainingSeconds",0), data.optLong("nextHeartbeatSeconds",180)); }
  private JSONObject makeEnvelope(JSONObject p) throws Exception { long ts=System.currentTimeMillis()/1000L; String nonce=UUID.randomUUID().toString().replace("-",""); p.put("ts",ts); String data=hex(rc4(p.toString().getBytes(StandardCharsets.UTF_8), LicenseConfig.RC4_KEY)); String sign=md5(LicenseConfig.APP_ID+ts+nonce+data+LicenseConfig.APP_SECRET); return new JSONObject().put("appId",LicenseConfig.APP_ID).put("ts",ts).put("nonce",nonce).put("data",data).put("sign",sign); }
  private JSONObject open(JSONObject e) throws Exception { String appId=e.optString("appId"), nonce=e.optString("nonce"), data=e.optString("data"), sign=e.optString("sign"); long ts=e.optLong("ts"); if(!LicenseConfig.APP_ID.equals(appId)) throw new IllegalStateException("App ID 不匹配"); if(Math.abs(System.currentTimeMillis()/1000L-ts)>300) throw new IllegalStateException("服务器时间戳无效"); if(!md5(appId+ts+nonce+data+LicenseConfig.APP_SECRET).equalsIgnoreCase(sign)) throw new IllegalStateException("响应签名错误"); JSONObject p=new JSONObject(new String(rc4(fromHex(data), LicenseConfig.RC4_KEY), StandardCharsets.UTF_8)); if(p.optLong("ts")!=ts) throw new IllegalStateException("响应时间戳不一致"); return p; }
  private static String readAll(InputStream in) throws Exception { BufferedReader r=new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)); StringBuilder b=new StringBuilder(); String l; while((l=r.readLine())!=null)b.append(l); r.close(); return b.toString(); }
  private static String md5(String s) throws Exception { MessageDigest md=MessageDigest.getInstance("MD5"); return hex(md.digest(s.getBytes(StandardCharsets.UTF_8))); }
  private static String hex(byte[] a){ StringBuilder b=new StringBuilder(a.length*2); for(byte x:a)b.append(String.format(Locale.US,"%02x",x&255)); return b.toString(); }
  private static byte[] fromHex(String h){ byte[] o=new byte[h.length()/2]; for(int i=0;i<o.length;i++)o[i]=(byte)Integer.parseInt(h.substring(i*2,i*2+2),16); return o; }
  private static byte[] rc4(byte[] input, String key){ int[] s=new int[256]; byte[] kb=key.getBytes(StandardCharsets.UTF_8); for(int i=0;i<256;i++)s[i]=i; int j=0; for(int i=0;i<256;i++){ j=(j+s[i]+(kb[i%kb.length]&255))&255; int t=s[i];s[i]=s[j];s[j]=t;} byte[] out=new byte[input.length]; int i=0; j=0; for(int n=0;n<input.length;n++){ i=(i+1)&255; j=(j+s[i])&255; int t=s[i];s[i]=s[j];s[j]=t; out[n]=(byte)(input[n]^s[(s[i]+s[j])&255]); } return out; }
}
`, "utf8");
  fs.writeFileSync(path.join(dir, "LicenseActivity.java"), `${pkg}
import android.app.*; import android.os.*; import android.content.*; import android.graphics.Color; import android.graphics.drawable.*; import android.provider.Settings; import android.view.*; import android.widget.*;
public class LicenseActivity extends Activity {
  EditText cardInput; TextView statusText; Button button;
  public void onCreate(Bundle b){ super.onCreate(b); requestWindowFeature(Window.FEATURE_NO_TITLE); buildUi(); cardInput.setText(getPreferences(0).getString("card","")); button.setOnClickListener(new View.OnClickListener(){ public void onClick(View v){ activate(); }}); if(cardInput.getText().toString().trim().length()>0) heartbeat(); }
  void buildUi(){ LinearLayout root=new LinearLayout(this); root.setGravity(Gravity.CENTER); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(28),0,dp(28),0); GradientDrawable bg=new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM,new int[]{Color.rgb(10,14,28),Color.rgb(2,10,18)}); root.setBackground(bg); LinearLayout box=new LinearLayout(this); box.setGravity(Gravity.CENTER); box.setOrientation(LinearLayout.VERTICAL); cardInput=input("请输入卡密",18); button=new Button(this); button.setText("验证"); button.setTextColor(Color.rgb(6,18,15)); button.setTextSize(16); button.setAllCaps(false); GradientDrawable bb=new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT,new int[]{Color.rgb(81,231,197),Color.rgb(255,238,97)}); bb.setCornerRadius(dp(10)); button.setBackground(bb); statusText=t("",14,Color.rgb(215,255,245)); statusText.setVisibility(View.GONE); add(box,cardInput,0,54); add(box,button,14,54); add(box,statusText,14,-2); root.addView(box,new LinearLayout.LayoutParams(-1,-2)); setContentView(root,new ViewGroup.LayoutParams(-1,-1)); }
  TextView t(String s,int sp,int c){ TextView v=new TextView(this); v.setText(s); v.setTextSize(sp); v.setTextColor(c); v.setGravity(Gravity.CENTER); return v; }
  EditText input(String h,int sp){ EditText e=new EditText(this); e.setHint(h); e.setSingleLine(true); e.setTextColor(Color.WHITE); e.setHintTextColor(Color.rgb(120,144,156)); e.setTextSize(sp); e.setGravity(Gravity.CENTER); e.setPadding(dp(14),0,dp(14),0); GradientDrawable d=new GradientDrawable(); d.setColor(Color.rgb(27,40,60)); d.setStroke(1,Color.rgb(48,72,99)); d.setCornerRadius(dp(10)); e.setBackground(d); return e; }
  void add(LinearLayout box, View v, int top, int height){ LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(-1, height < 0 ? -2 : dp(height)); lp.topMargin=dp(top); box.addView(v,lp); }
  int dp(int v){ return (int)(v*getResources().getDisplayMetrics().density+0.5f); }
  void activate(){ final String card=cardInput.getText().toString().trim(); if(card.length()==0){ setLoading(false,"请输入卡密"); return; } setLoading(true,"验证中..."); new Thread(new Runnable(){ public void run(){ try { LicenseResult r=new LicenseClient(LicenseActivity.this).activate(card, deviceId(), LicenseConfig.APP_VERSION); if(r.ok){ getPreferences(0).edit().putString("card",card.toUpperCase()).apply(); runOnUiThread(new Runnable(){ public void run(){ enterMain(); }}); } else { final String msg=r.message; runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"验证失败："+msg); }}); } } catch(final Exception e){ runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"验证失败："+(e.getMessage()==null?"网络验证失败":e.getMessage())); }}); } }}).start(); }
  void heartbeat(){ setLoading(true,"正在联网验证..."); new Thread(new Runnable(){ public void run(){ try { String card=cardInput.getText().toString().trim(); LicenseResult r=new LicenseClient(LicenseActivity.this).heartbeat(card, deviceId(), LicenseConfig.APP_VERSION); if(r.ok) { runOnUiThread(new Runnable(){ public void run(){ enterMain(); }}); } else { final String msg=r.message; runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"验证失败："+msg); }}); } } catch(final Exception e){ runOnUiThread(new Runnable(){ public void run(){ setLoading(false,"验证失败："+(e.getMessage()==null?"心跳验证失败":e.getMessage())); }}); } }}).start(); }
  String deviceId(){ String id=Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID); return id==null||id.trim().length()==0?"unknown-device":id; }
  void setLoading(boolean l,String m){ button.setEnabled(!l); cardInput.setEnabled(!l); statusText.setText(m == null ? "" : m); statusText.setVisibility(m == null || m.length()==0 ? View.GONE : View.VISIBLE); }
  void enterMain(){ try { startActivity(new Intent(this, Class.forName("${javaString(launcher)}"))); finish(); } catch(Exception e){ setLoading(false,"原启动页打开失败："+e.getMessage()); } }
}
`, "utf8");
}

async function addDex(apk, dexPath) {
  const entries = await zipList(apk);
  let n = 2;
  while (entries.includes(`classes${n}.dex`)) n++;
  const entryName = `classes${n}.dex`;
  const entryDir = path.join(path.dirname(apk), "dex-entry");
  fs.rmSync(entryDir, { recursive: true, force: true });
  fs.mkdirSync(entryDir, { recursive: true });
  fs.copyFileSync(dexPath, path.join(entryDir, entryName));
  try {
    await run(jarCommand(), ["uf", apk, "-C", entryDir, entryName], path.dirname(apk));
  } finally {
    fs.rmSync(entryDir, { recursive: true, force: true });
  }
}

async function zipList(apk) {
  const out = await runCapture(jarCommand(), ["tf", apk], path.dirname(apk));
  return out.split(/\r?\n/).filter(Boolean);
}

function jarCommand() {
  const javaHome = process.env.JAVA_HOME || (fs.existsSync("D:\\android\\jbr") ? "D:\\android\\jbr" : "");
  return firstExisting([path.join(javaHome, "bin", "jar.exe"), path.join(javaHome, "bin", "jar"), "jar"]) || "jar";
}

function findVmpPacker() {
  const local = path.join(ROOT, "tools", "vmp", "packer.bat");
  const shell = path.join(ROOT, "tools", "vmp", "packer.sh");
  return process.env.VMP_PACKER || (fs.existsSync(local) ? local : "") || (fs.existsSync(shell) ? shell : "");
}

function newestDir(parent) {
  if (!fs.existsSync(parent)) return "";
  const dirs = fs.readdirSync(parent).filter((d) => fs.statSync(path.join(parent, d)).isDirectory()).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
  return dirs[0] ? path.join(parent, dirs[0]) : "";
}

function firstExisting(candidates) {
  for (const c of candidates) if (c && (c === "java" || c === "javac" || fs.existsSync(c))) return c;
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
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "*",
    "access-control-allow-private-network": "true"
  };
}

function page() {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>APK 验证框一键工具</title><style>
body{margin:0;background:#f5f7fb;color:#172033;font-family:Arial,"Microsoft YaHei",sans-serif}.wrap{max-width:980px;margin:auto;padding:24px}.panel{background:white;border:1px solid #dde4ef;border-radius:8px;padding:18px;margin-top:14px}.drop{border:2px dashed #8aa4c4;border-radius:8px;padding:34px;text-align:center;background:#f8fbff}.drop.drag{background:#eaf4ff}input{width:100%;height:38px;border:1px solid #dde4ef;border-radius:6px;padding:8px;box-sizing:border-box}button{height:40px;border:0;border-radius:6px;background:#1769aa;color:white;font-weight:700;padding:0 14px}.muted{color:#667085}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.status{white-space:pre-wrap;background:#111827;color:#d7fff5;padding:14px;border-radius:8px;min-height:120px}@media(max-width:760px){.row{grid-template-columns:1fr}}</style></head><body><main class="wrap">
<h1>统一验证后台 · APK 保护</h1><p class="muted">把已经编译好的 APK 拖进来，本机自动加入卡密窗口、心跳、MD5 签名、RC4 加密和时间戳校验，再混淆验证模块并重新签名。</p><p><a href="${DEFAULT_SERVER}" target="_blank">打开卡密管理后台</a></p><p id="access" class="muted">正在读取手机访问地址...</p>
<section class="panel"><div id="drop" class="drop"><b>拖拽 APK 到这里</b><p class="muted">或点击选择 APK 文件</p><input id="file" type="file" accept=".apk" style="display:none"></div></section>
<section class="panel"><div class="row"><label>统一后台地址<input id="server" value="${DEFAULT_SERVER}"></label><label>App ID<input id="appId" value="demo_android_app"></label><label>App Secret<input id="secret" type="password" value="change_this_app_secret"></label><label>RC4 Key<input id="rc4" type="password" value="change_this_rc4_key"></label></div><p><label><input id="obfuscate" type="checkbox" checked> 使用 R8 混淆新加入的验证模块</label></p><p><label><input id="vmp" type="checkbox"> 处理完成后调用 VMP 壳</label></p><button id="start" disabled>一键加入验证并保护 APK</button></section>
<section class="panel"><h2>状态</h2><div id="status" class="status">等待 APK...</div><p id="download"></p></section>
<section class="panel"><h2>VMP 壳工具位置</h2><p class="muted">把你的 VMP 加固工具放到：<b>${ROOT.replace(/\\/g, "\\\\")}\\\\tools\\\\vmp\\\\packer.bat</b>。脚本需要支持两个参数：输入 APK、输出 APK。</p></section>
</main><script>
let selected=null; const drop=document.getElementById('drop'), file=document.getElementById('file'), start=document.getElementById('start'), statusBox=document.getElementById('status'), dl=document.getElementById('download');
drop.onclick=()=>file.click(); file.onchange=()=>setFile(file.files[0]); drop.ondragover=e=>{e.preventDefault();drop.classList.add('drag')}; drop.ondragleave=()=>drop.classList.remove('drag'); drop.ondrop=e=>{e.preventDefault();drop.classList.remove('drag');setFile(e.dataTransfer.files[0])};
function setFile(f){ if(!f||!f.name.toLowerCase().endsWith('.apk')) return log('请选择 APK 文件'); selected=f; start.disabled=false; log('已选择：'+f.name+'\\n点击开始处理'); }
function log(t){ statusBox.textContent=t; }
start.onclick=async()=>{ if(!selected)return; start.disabled=true; dl.innerHTML=''; log('正在本机处理 APK...\\n正在加入验证窗口和安全校验，请稍等。'); const qs=new URLSearchParams({fileName:selected.name,serverUrl:server.value,appId:appId.value,appSecret:secret.value,rc4Key:rc4.value,obfuscate:obfuscate.checked?'1':'0',vmp:vmp.checked?'1':'0'}); try{ const r=await fetch('/api/process?'+qs,{method:'POST',body:selected}); const b=await r.json(); if(!b.ok)throw new Error(b.message); log('处理完成\\n包名：'+b.packageName+'\\n原启动页：'+b.launcher+'\\n统一后台：'+b.serverUrl+'\\n安全传输：心跳 + MD5 + RC4 + 时间戳\\n'+b.obfuscationMessage+'\\n'+b.vmpMessage); dl.innerHTML='<a href="'+b.file+'">下载 '+b.fileName+'</a>'; }catch(e){ log('处理失败：\\n'+e.message); } finally{ start.disabled=false; } };
fetch('/api/status').then(r=>r.json()).then(b=>{ if(!b.ok)return; console.log(b.tools); const phone=(b.accessUrls||[]).filter(x=>!x.includes('127.0.0.1')); access.textContent=phone.length?'安卓手机与电脑连接同一 Wi-Fi 后打开：'+phone.join(' 或 '):'电脑访问：http://127.0.0.1:${PORT}'; });
</script></body></html>`;
}
