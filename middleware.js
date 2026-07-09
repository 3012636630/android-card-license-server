const TARGET_ORIGIN = "https://android-license-worker.mccarrickmalis331.workers.dev";

export default async function middleware(request) {
  const sourceUrl = new URL(request.url);
  const targetUrl = new URL(sourceUrl.pathname + sourceUrl.search, TARGET_ORIGIN);
  const headers = new Headers(request.headers);
  headers.delete("host");

  return fetch(targetUrl, {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    redirect: "manual"
  });
}

export const config = {
  matcher: "/:path*"
};
