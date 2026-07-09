const TARGET_ORIGIN = "https://android-license-worker.mccarrickmalis331.workers.dev";

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", chunk => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

module.exports = async function handler(req, res) {
  try {
    const path = String(req.query.path || "");
    const query = { ...req.query };
    delete query.path;
    const search = new URLSearchParams(query).toString();
    const targetUrl = `${TARGET_ORIGIN}/${path}${search ? `?${search}` : ""}`;

    const headers = { ...req.headers };
    delete headers.host;
    delete headers["x-forwarded-host"];

    const response = await fetch(targetUrl, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : await readBody(req),
      redirect: "manual"
    });

    res.status(response.status);
    response.headers.forEach((value, key) => {
      if (!["content-encoding", "content-length", "transfer-encoding"].includes(key.toLowerCase())) {
        res.setHeader(key, value);
      }
    });
    res.send(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    res.status(502).json({ ok: false, message: error.message || "proxy error" });
  }
};
