/**
 * Warns when `baseUrl` sends the api key over plain http to a host that is not loopback.
 * Silence it with a `process.on("warning")` listener that filters on the warning name, or with
 * `node --disable-warning=SANDFORT_INSECURE_BASE_URL`.
 */

export const INSECURE_BASE_URL_WARNING = "InsecureBaseUrlWarning";
export const INSECURE_BASE_URL_CODE = "SANDFORT_INSECURE_BASE_URL";

const LOOPBACK_NAME = "localhost";
const IPV4_LOOPBACK = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/**
 * The host of `baseUrl` when it is `http` and not loopback, else `null`. Loopback is
 * `localhost`, any 127.0.0.0/8 address and `::1`. A url that cannot be parsed gives `null`
 * (the transport reports it). Userinfo is never part of the result.
 */
export function insecureHost(baseUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(baseUrl.trim());
  } catch {
    return null;
  }
  if (url.protocol !== "http:") return null;
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (host === "") return null;
  if (host.replace(/\.+$/, "") === LOOPBACK_NAME) return null;
  if (IPV4_LOOPBACK.test(host) || host === "::1") return null;
  return host;
}

/** Emit `InsecureBaseUrlWarning` once for an `http://` base url to a remote host. */
export function warnIfInsecureBaseUrl(baseUrl: string): void {
  const host = insecureHost(baseUrl);
  if (host === null) return;
  // Browsers have no process, the warning is a Node feature.
  if (typeof process === "undefined") return;
  process.emitWarning(
    `baseUrl uses http:// for host '${host}', so the api key is sent in clear text. ` +
      "Use https://, or filter InsecureBaseUrlWarning if the network is private and trusted.",
    { type: INSECURE_BASE_URL_WARNING, code: INSECURE_BASE_URL_CODE },
  );
}
