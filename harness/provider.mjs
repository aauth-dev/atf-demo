// LOCAL HARNESS COPY of demo/provider/provider.mjs from the
// verifiable-agent-summit repository. Two changes from upstream:
//
//   1. `args()` recognizes `--no-atf` as a boolean flag.
//   2. `issue()` takes `noAtf`, which omits the ATF claim from the payload.
//      That is how the `no-atf` test case is produced: a well-formed AAuth
//      agent token from a trusted provider that carries no grade at all.
//
// Nothing else is modified. Upstream is Imran's; do not edit it from here.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const HERE = process.env.SUMMIT_PROVIDER_HOME
  ? path.resolve(process.env.SUMMIT_PROVIDER_HOME)
  : path.dirname(fileURLToPath(import.meta.url));
const PRIVATE = path.join(HERE, "private");
const OUT = path.join(HERE, "out");
const PUBLIC = path.join(HERE, "public");
const WELL_KNOWN = path.join(PUBLIC, ".well-known");
const ATF_CLAIM = "https://agentictrustframework.ai/atf";

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function jsonB64(value) {
  return b64url(Buffer.from(JSON.stringify(value)));
}

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function digest(value) {
  return `sha256:${crypto.createHash("sha256").update(canonical(value)).digest("hex")}`;
}

function publicJwk(key, kid) {
  return { ...key.export({ format: "jwk" }), alg: "Ed25519", use: "sig", kid };
}

function ensureProviderKey() {
  fs.mkdirSync(PRIVATE, { recursive: true });
  const privatePath = path.join(PRIVATE, "provider-key.pem");
  if (fs.existsSync(privatePath)) {
    return crypto.createPrivateKey(fs.readFileSync(privatePath));
  }
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(privatePath, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  return privateKey;
}

function validateIssuer(issuer) {
  const url = new URL(issuer);
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || issuer.endsWith("/")) {
    throw new Error("issuer must be an HTTPS origin with no path or trailing slash");
  }
  return issuer;
}

function providerKid(publicKey) {
  return `ap-${crypto.createHash("sha256").update(publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 16)}`;
}

export function initialize(issuer) {
  validateIssuer(issuer);
  const key = ensureProviderKey();
  const kid = providerKid(key.publicKey ?? crypto.createPublicKey(key));
  const jwk = publicJwk(crypto.createPublicKey(key), kid);
  fs.mkdirSync(WELL_KNOWN, { recursive: true });
  const discovery = `${JSON.stringify({
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    name: "Verifiable Agent Summit Provider",
    description: "Demo issuer binding a signed ATF appraisal to an AAuth agent token for the CSA Verifiable Agent Summit.",
    documentation_uri: "https://github.com/massivescale-ai/verifiable-agent-summit/tree/main/demo/provider",
  }, null, 2)}\n`;
  fs.writeFileSync(path.join(WELL_KNOWN, "aauth-agent.json"), discovery);
  // Keep the summit's originally agreed discovery spelling resolvable as an alias.
  fs.writeFileSync(path.join(WELL_KNOWN, "a-off-agent.json"), discovery);
  fs.writeFileSync(path.join(WELL_KNOWN, "jwks.json"), `${JSON.stringify({ keys: [jwk] }, null, 2)}\n`);
  return { key, kid, jwk };
}

function signJwt(header, payload, key) {
  const signingInput = `${jsonB64(header)}.${jsonB64(payload)}`;
  return `${signingInput}.${b64url(crypto.sign(null, Buffer.from(signingInput), key))}`;
}

export function issue({ issuer, appraisal, agentId, now = Math.floor(Date.now() / 1000), ttl = 3600, noAtf = false }) {
  const { key, kid } = initialize(issuer);
  if (noAtf && !appraisal) {
    // A plain AAuth agent token: no appraisal, no grade, nothing for a
    // resource with an ATF policy to read.
    const subject0 = agentId ?? `aauth:planner@${new URL(issuer).hostname}`;
    const { publicKey: ap0, privateKey: apk0 } = crypto.generateKeyPairSync("ed25519");
    const jwk0 = { ...ap0.export({ format: "jwk" }), alg: "Ed25519" };
    const payload0 = {
      iss: issuer, dwk: "aauth-agent.json", sub: subject0,
      jti: crypto.randomUUID(), cnf: { jwk: jwk0 }, iat: now, exp: now + ttl,
    };
    const header0 = { alg: "Ed25519", typ: "aa-agent+jwt", kid };
    return { token: signJwt(header0, payload0, key), header: header0, payload: payload0, agentPrivate: apk0, agentJwk: jwk0 };
  }
  if (!appraisal.signature) throw new Error("appraisal must be signed");
  if (appraisal.profile?.id !== "csa-atf" || appraisal.profile?.version !== "0.9.1") {
    throw new Error("appraisal must use csa-atf 0.9.1");
  }
  if (appraisal.result?.decision !== "qualifying") throw new Error("appraisal must be qualifying");
  const appraisalExpiry = Number(appraisal.exp);
  if (!Number.isSafeInteger(appraisalExpiry) || appraisalExpiry <= now) throw new Error("appraisal is expired");
  const subject = agentId ?? `aauth:planner@${new URL(issuer).hostname}`;
  if (!/^aauth:[^@]+@[^@]+$/.test(subject)) throw new Error("agent id must use aauth:local@domain syntax");

  const { publicKey: agentPublic, privateKey: agentPrivate } = crypto.generateKeyPairSync("ed25519");
  const agentJwk = { ...agentPublic.export({ format: "jwk" }), alg: "Ed25519" };
  const appraisalDigest = digest(appraisal);
  const payload = {
    iss: issuer,
    dwk: "aauth-agent.json",
    sub: subject,
    jti: crypto.randomUUID(),
    cnf: { jwk: agentJwk },
    iat: now,
    exp: Math.min(now + ttl, appraisalExpiry),
    [ATF_CLAIM]: {
      profile: `${appraisal.profile.id}:${appraisal.profile.version}`,
      level: appraisal.result.trust_level,
      appraisal_id: appraisal.appraisal_id,
      appraisal_issuer: appraisal.issuer,
      appraisal_hash: appraisalDigest,
      evidence_hash: appraisal.evidence.record_hash,
      appraisal_subject: appraisal.subject.agent_id,
      workload_id: appraisal.subject.workload_id,
      sequence: appraisal.sequence,
      exp: appraisal.exp,
      binding_status: "demo-proposal",
    },
  };
  if (noAtf) delete payload[ATF_CLAIM];
  const header = { alg: "Ed25519", typ: "aa-agent+jwt", kid };
  return { token: signJwt(header, payload, key), header, payload, agentPrivate, agentJwk };
}

function decodeSegment(segment, name) {
  try {
    return JSON.parse(Buffer.from(segment, "base64url"));
  } catch {
    throw new Error(`malformed JWT ${name}`);
  }
}

export function verify(token, jwk, { now = Math.floor(Date.now() / 1000) } = {}) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  // Check the signature over the raw segments before parsing anything out of
  // them. A tampered payload has to be reported as an invalid signature, not as
  // a JSON parse error escaping the verifier.
  if (!crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), crypto.createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(parts[2], "base64url"))) {
    throw new Error("invalid JWT signature");
  }
  const header = decodeSegment(parts[0], "header");
  const payload = decodeSegment(parts[1], "payload");
  if (header.typ !== "aa-agent+jwt" || header.alg !== "Ed25519" || header.kid !== jwk.kid) throw new Error("invalid JWT header");
  if (payload.dwk !== "aauth-agent.json") throw new Error("invalid JWT claims");
  if (payload.iat > now) throw new Error("token not yet valid");
  if (payload.exp <= now) throw new Error("token expired");
  validateIssuer(payload.iss);
  if (!/^aauth:[^@]+@[^@]+$/.test(payload.sub) || !payload.jti || payload.cnf?.jwk?.alg !== "Ed25519") {
    throw new Error("invalid agent identity claims");
  }
  const atf = payload[ATF_CLAIM];
  if (!atf || atf.profile !== "csa-atf:0.9.1" || !atf.appraisal_hash || !atf.evidence_hash || !atf.workload_id) {
    throw new Error("invalid ATF extension claim");
  }
  return { header, payload };
}

const BOOLEAN_FLAGS = new Set(["no-atf"]);

function args(argv) {
  const result = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    if (!argv[i].startsWith("--")) result._.push(argv[i]);
    else if (BOOLEAN_FLAGS.has(argv[i].slice(2))) result[argv[i].slice(2)] = true;
    else result[argv[i].slice(2)] = argv[++i];
  }
  return result;
}

function main() {
  const options = args(process.argv.slice(2));
  const command = options._[0];
  if (command === "verify") {
    if (!options.token || !options.jwks) throw new Error("verify requires --token FILE --jwks FILE");
    const token = fs.readFileSync(options.token, "utf8").trim();
    const keys = JSON.parse(fs.readFileSync(options.jwks, "utf8")).keys;
    const kid = decodeSegment(token.split(".")[0], "header").kid;
    const jwk = keys.find((candidate) => candidate.kid === kid);
    if (!jwk) throw new Error(`no discovery key matches ${kid}`);
    let result;
    try {
      result = verify(token, jwk, { now: options["at-time"] ? Number(options["at-time"]) : Math.floor(Date.now() / 1000) });
    } catch (error) {
      console.log(`FAIL token rejected     ${error.message}`);
      process.exitCode = 1;
      return;
    }
    const atf = result.payload[ATF_CLAIM];
    console.log(`PASS provider signature  ${result.header.kid}`);
    console.log(`PASS AAuth agent token   ${result.payload.sub}`);
    console.log(`PASS ATF claim           ${atf.level} under ${atf.profile}`);
    console.log(`PASS evidence binding    ${atf.evidence_hash}`);
    console.log(`NOTE identity binding    ${atf.binding_status}: ${result.payload.sub} -> ${atf.workload_id}`);
    return;
  }
  if (!command || !options.issuer) throw new Error("usage: provider.mjs <init|issue|verify> [options]");
  if (command === "init") {
    initialize(options.issuer);
    console.log(`wrote discovery documents under ${path.relative(process.cwd(), WELL_KNOWN)}`);
    return;
  }
  if (command !== "issue") throw new Error("usage: provider.mjs <init|issue|verify> [options]");
  if (!options.appraisal && !options["no-atf"]) throw new Error("issue requires --appraisal FILE");
  const appraisal = options.appraisal ? JSON.parse(fs.readFileSync(options.appraisal, "utf8")) : null;
  const result = issue({
    issuer: options.issuer,
    appraisal,
    agentId: options["agent-id"],
    now: options["at-time"] ? Number(options["at-time"]) : Math.floor(Date.now() / 1000),
    ttl: options.ttl ? Number(options.ttl) : 3600,
    noAtf: options["no-atf"] === true,
  });
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, "agent-token.jwt"), `${result.token}\n`);
  fs.writeFileSync(path.join(OUT, "agent-token-decoded.json"), `${JSON.stringify({ header: result.header, payload: result.payload }, null, 2)}\n`);
  fs.writeFileSync(path.join(OUT, "agent-public.jwk.json"), `${JSON.stringify(result.agentJwk, null, 2)}\n`);
  fs.writeFileSync(path.join(PRIVATE, "agent-key.pem"), result.agentPrivate.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  console.log(`issued ${result.payload.sub} at ${result.payload.iss}`);
  const atfOut = result.payload[ATF_CLAIM];
  console.log(`${atfOut ? `ATF ${atfOut.level}` : "no ATF claim"}; expires ${new Date(result.payload.exp * 1000).toISOString()}`);
  console.log(`wrote token artifacts under ${path.relative(process.cwd(), OUT)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
