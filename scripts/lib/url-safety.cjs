// Guards against SSRF: refuses URLs that point at this machine or private networks.
// Used by the model downloader and the web-search page fetcher.
const dns = require("dns").promises;
const net = require("net");

function isPrivateIpv4(ip) {
  const parts = String(ip || "").split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224;
}

function isPrivateIpv6(ip) {
  const value = String(ip || "").toLowerCase();
  if (value === "::" || value === "::1") return true;
  if (value.startsWith("::ffff:")) {
    const mapped = value.slice(7);
    return net.isIP(mapped) !== 4 || isPrivateIpv4(mapped);
  }
  const first = value.split(":")[0];
  return /^fe[89ab]/.test(first) || /^f[cd]/.test(first);
}

function isPrivateIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) return isPrivateIpv4(ip);
  if (family === 6) return isPrivateIpv6(ip);
  return true;
}

const LOCAL_HOSTNAME_RE = /(^|\.)(localhost|local|internal|intranet|lan|home|corp)$/i;

const PRIVATE_TARGET_MESSAGE = "That URL points at a local or private address, which the studio will not contact.";

// "" means the URL is fine to fetch. Anything else explains why it was refused.
function getUrlTargetIssue(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl || "").trim());
  } catch (_) {
    return "That is not a valid URL.";
  }
  if (!/^https?:$/.test(parsed.protocol)) return "Only http(s) URLs are allowed.";
  // new URL() normalizes decimal/hex IPv4 literals (e.g. http://2130706433 -> 127.0.0.1)
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return "That URL has no host.";
  if (LOCAL_HOSTNAME_RE.test(host)) return PRIVATE_TARGET_MESSAGE;
  if (net.isIP(host) && isPrivateIp(host)) return PRIVATE_TARGET_MESSAGE;
  return "";
}

// Resolves the URL, refuses when any answer is a private address, and returns
// the validated public address so callers can connect to THAT exact IP.
// Call this on every redirect hop, not just the first URL.
async function resolvePublicTarget(rawUrl) {
  const issue = getUrlTargetIssue(rawUrl);
  if (issue) return { issue };
  const parsed = new URL(String(rawUrl).trim());
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const port = parsed.port || "";
  if (net.isIP(host)) return { host, port }; // literal IP was already range-checked
  let records;
  try {
    records = await dns.lookup(host, { all: true, verbatim: false });
  } catch (_) {
    return { host, port }; // unresolvable hosts fail the request with the real error
  }
  const privateRecord = records.find((record) => isPrivateIp(record.address));
  if (privateRecord) {
    return { issue: `That URL resolves to a local or private address (${host} -> ${record.address}), which the studio will not contact.` };
  }
  const publicRecord = records.find((record) => !isPrivateIp(record.address));
  if (!publicRecord) return { host, port };
  return { host, port, address: publicRecord.address, family: publicRecord.family };
}

// Request options for http(s).get that connect to the validated IP while the
// original hostname drives TLS SNI/certificate checks and the Host header.
// This closes the resolve->connect gap a DNS rebind could otherwise exploit.
function pinnedRequestOptions(target, headers = {}) {
  const hostHeader = target.host.includes(":") ? `[${target.host}]` : target.host;
  const merged = { ...headers, Host: target.port ? `${hostHeader}:${target.port}` : hostHeader };
  if (!target.address) return { headers: merged };
  return {
    hostname: target.address,
    family: target.family,
    servername: target.host,
    headers: merged,
  };
}

module.exports = { isPrivateIp, getUrlTargetIssue, resolvePublicTarget, pinnedRequestOptions };
