/*
 * PQC Radar scanner engine.
 * Pattern-based, line-by-line rules for quantum-vulnerable crypto, classical crypto
 * mistakes and risky AI-agent configuration. Runs in the browser or in Node.
 * Nothing is sent anywhere.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PQCRadar = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var SEV_WEIGHT = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // Each rule: id, title, severity, kind (quantum | classical | agent | pqc),
  // re (RegExp tested per line) or test(line) returning a truthy value, and fix guidance.
  var RULES = [
    {
      id: "QR001", kind: "quantum", severity: "high", title: "RSA in use",
      re: /\bRSA\b|rsa\.generate|RSA_generate_key|generate_private_key\([^)]*rsa|getInstance\(\s*["']RSA|\b(RS|PS)(256|384|512)\b/,
      fix: "RSA is broken by Shor's algorithm. For key exchange move to ML-KEM (FIPS 203), ideally as a hybrid such as X25519MLKEM768. For signatures plan ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
      replace: "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
    },
    {
      id: "QR002", kind: "quantum", severity: "high", title: "Elliptic-curve crypto (ECDSA / ECDH)",
      re: /\bECDSA\b|\bECDHE?\b|\bsecp(256|384|521)[kr]1\b|\bprime256v1\b|\bP-(256|384|521)\b|ec\.generate_private_key|\bES(256|384|512)\b|EllipticCurve|\bECC\b/,
      fix: "Elliptic curves are broken by Shor's algorithm. Use hybrid key exchange (X25519MLKEM768) now and plan ML-DSA for signatures.",
      replace: "Hybrid X25519MLKEM768 / ML-DSA"
    },
    {
      id: "QR003", kind: "quantum", severity: "high", title: "Ed25519 / X25519 family",
      re: /\b(Ed25519|Ed448|X25519|X448)\b/,
      fix: "Modern and classically strong, but still quantum-vulnerable. Keep it inside a hybrid (X25519MLKEM768) and inventory where signatures need ML-DSA later.",
      replace: "Hybrid X25519MLKEM768 / ML-DSA"
    },
    {
      id: "QR004", kind: "quantum", severity: "high", title: "Diffie-Hellman key exchange",
      re: /Diffie-?Hellman|\bDHE-|\bffdhe\d+\b|dh\.generate_parameters|createDiffieHellman|\bdiffie_hellman\b/i,
      fix: "Finite-field DH is broken by Shor's algorithm. Replace with ML-KEM, deployed as a hybrid during migration.",
      replace: "ML-KEM (FIPS 203)"
    },
    {
      id: "QR005", kind: "quantum", severity: "high", title: "DSA signatures",
      re: /(?<!ML-)(?<!SLH-)\bDSA\b|ssh-dss/,
      fix: "DSA is deprecated and quantum-vulnerable. Move signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
      replace: "ML-DSA / SLH-DSA"
    },
    {
      id: "QR006", kind: "quantum", severity: "medium", title: "SSH RSA host or user key",
      re: /\bssh-rsa\b/,
      fix: "Rotate to ssh-ed25519 short term and track OpenSSH's post-quantum key exchange (mlkem768x25519-sha256).",
      replace: "mlkem768x25519-sha256 (OpenSSH)"
    },
    {
      id: "QC001", kind: "classical", severity: "medium", title: "MD5 or SHA-1 hash",
      re: /\bmd5\b|\bsha-?1\b(?![0-9])/i,
      fix: "MD5 and SHA-1 are broken for collision resistance. Use SHA-256 or SHA-3. SHA-2 stays acceptable in the post-quantum era.",
      replace: "SHA-256 / SHA-3"
    },
    {
      id: "QC002", kind: "classical", severity: "medium", title: "Weak or legacy cipher",
      re: /\b(3DES|TripleDES|RC4|RC2|ARCFOUR|Blowfish)\b|DES-EDE|\bDES\.new\b|getInstance\(\s*["']DES/,
      fix: "Replace with AES-256-GCM or ChaCha20-Poly1305.",
      replace: "AES-256-GCM"
    },
    {
      id: "QC003", kind: "classical", severity: "high", title: "Key size too small",
      re: /(key_?size|bits|modulus|key_?len(gth)?)\s*[=:]\s*(512|768|1024)\b|\bRSA[-_ ]?(512|768|1024)\b/i,
      fix: "Keys of 1024 bits or less are breakable today, no quantum computer needed. Rotate immediately.",
      replace: "Rotate now; plan PQC"
    },
    {
      id: "QC004", kind: "classical", severity: "medium", title: "Old SSL / TLS version",
      re: /SSLv2|SSLv3|TLSv1(\.0|\.1)?\b(?!\.[23])|TLS1_0|TLS1_1|PROTOCOL_TLSv1\b/,
      fix: "Require TLS 1.3 (or 1.2 minimum). TLS 1.3 is where hybrid post-quantum key exchange is deployed.",
      replace: "TLS 1.3 + hybrid PQ"
    },
    {
      id: "QC005", kind: "classical", severity: "critical", title: "Private key committed to source",
      re: /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
      fix: "Treat the key as leaked: revoke and rotate it, remove it from git history, and load keys from a secret manager.",
      replace: "Revoke + secret manager"
    },
    {
      id: "QC006", kind: "classical", severity: "medium", title: "ECB block-cipher mode",
      re: /MODE_ECB|\/ECB\/|\bECB\b/,
      fix: "ECB leaks patterns in the data. Use an authenticated mode such as GCM.",
      replace: "AES-GCM"
    },
    {
      id: "QC007", kind: "classical", severity: "low", title: "AES-128 (reduced margin vs Grover)",
      re: /AES[-_]?128/i,
      fix: "Grover's algorithm halves the effective key strength. AES-256 keeps a comfortable margin for long-lived data.",
      replace: "AES-256"
    },
    {
      id: "QA001", kind: "agent", severity: "high", title: "Agent tools auto-approved",
      re: /(autoApprove|alwaysAllow|auto_approve|autoApproveAll)["']?\s*[:=]\s*(true|\[\s*["'][^"']+)/i,
      fix: "Auto-approve lets the agent run tools with no human check. Keep it only for read-only tools; require approval for anything that writes, sends or spends.",
      replace: "Per-call approval for write tools"
    },
    {
      id: "QA002", kind: "agent", severity: "high", title: "Wildcard or bypassed agent permissions",
      re: /"(allow|permissions|tools|allowedTools)"\s*:\s*\[\s*"\*"|Bash\(\*\)|dangerously-skip-permissions|--yolo\b|"permissionMode"\s*:\s*"bypassPermissions"/i,
      fix: "Grant the agent an explicit allow-list of tools and commands. Wildcards turn one prompt injection into full access.",
      replace: "Explicit allow-list"
    },
    {
      id: "QA003", kind: "agent", severity: "medium", title: "MCP server not pinned to a version",
      test: function (line) {
        var m = line.match(/\b(?:npx|uvx|bunx|pnpx)\b(?:\s+-y|\s+--yes)?\s+(@?[\w.-]+(?:\/[\w.-]+)?(?:@[\w.^~-]+)?)/) ||
                line.match(/"(?:-y|--yes)"\s*,\s*"(@?[\w.-]+(?:\/[\w.-]+)?(?:@[\w.^~-]+)?)"/);
        if (!m) return false;
        var pkg = m[1];
        if (/^-/.test(pkg)) return false;
        return !/@\d+(\.\d+){0,2}$/.test(pkg) && !/@sha256/.test(pkg);
      },
      fix: "An unpinned npx/uvx server runs whatever version is published next. Pin an exact version (package@1.2.3) and review updates.",
      replace: "Pin exact version"
    },
    {
      id: "QA004", kind: "agent", severity: "critical", title: "Secret written directly in config",
      re: /\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b|(api[_-]?key|secret|token|password|passwd)["']?\s*[:=]\s*["'](?!\$|<|your|xxx|changeme|\*)[A-Za-z0-9_\-.]{12,}["']/i,
      fix: "Move the value to an environment variable or secret manager and reference it (\"${API_KEY}\"). Rotate the exposed secret.",
      replace: "Env var / secret manager"
    },
    {
      id: "QA005", kind: "agent", severity: "high", title: "Hidden or overriding instruction",
      re: /ignore (all )?(previous|prior|above) instructions|do not (tell|inform|mention (this )?to) the user|<!--[^>]*(instruction|system prompt|ignore)[^>]*-->|you must (now )?(send|upload|exfiltrate)/i,
      fix: "Instruction text inside skills, tool descriptions or docs can steer the agent. Remove it and review where the file came from.",
      replace: "Remove + review source"
    },
    {
      id: "QA006", kind: "agent", severity: "high", title: "Possible data exfiltration step",
      re: /(curl|wget|fetch|Invoke-WebRequest)[^\n]*(\.ssh|id_rsa|\.env\b|\.aws\/credentials|~\/\.)/i,
      fix: "A command that reads credential files and sends them out is a classic exfiltration pattern. Remove it and audit the agent's network access.",
      replace: "Remove + restrict egress"
    },
    {
      id: "QA007", kind: "agent", severity: "high", title: "Invisible Unicode characters",
      re: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]|[\uDB40][\uDC00-\uDC7F]/,
      fix: "Zero-width and bidi characters can hide instructions from human reviewers. Strip them and re-review the file.",
      replace: "Strip + re-review"
    },
    {
      id: "QA008", kind: "agent", severity: "medium", title: "Agent server over plain HTTP",
      re: /"(url|serverUrl|endpoint)"\s*:\s*"http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/i,
      fix: "Remote MCP servers should use HTTPS so tool calls and tokens are not readable in transit.",
      replace: "HTTPS"
    },
    {
      id: "QP001", kind: "pqc", severity: "info", title: "Post-quantum algorithm referenced",
      re: /ML-KEM|MLKEM|ML-DSA|SLH-DSA|\bKyber\b|Dilithium|SPHINCS|\bFALCON\b|liboqs|oqs-provider/i,
      fix: "Good sign: migration has started here. Confirm it is used as a hybrid where interoperability matters.",
      replace: "Already PQC"
    }
  ];

  function scanText(text, path) {
    var findings = [];
    var lines = String(text).split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line.length > 4000) continue; // skip minified blobs
      if (/pqc-?radar:\s*ignore/i.test(line)) continue;
      for (var r = 0; r < RULES.length; r++) {
        var rule = RULES[r];
        var hit = rule.re ? rule.re.test(line) : rule.test(line);
        if (hit) {
          findings.push({
            id: rule.id, title: rule.title, severity: rule.severity, kind: rule.kind,
            file: path || "pasted.txt", line: i + 1,
            snippet: line.trim().slice(0, 220), fix: rule.fix, replace: rule.replace
          });
        }
      }
    }
    return findings;
  }

  function score(findings) {
    // Smooth decay so large repos do not all collapse to zero.
    var penalty = 0;
    findings.forEach(function (f) { penalty += SEV_WEIGHT[f.severity] || 0; });
    return Math.round(100 * Math.exp(-penalty / 120));
  }

  function verdict(s) {
    if (s >= 90) return "Strong baseline";
    if (s >= 70) return "Plan migration";
    if (s >= 40) return "Action needed";
    return "High exposure";
  }

  function summarize(findings) {
    var bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    var byKind = { quantum: 0, classical: 0, agent: 0, pqc: 0 };
    findings.forEach(function (f) { bySev[f.severity]++; byKind[f.kind]++; });
    var s = score(findings);
    return { total: findings.length, bySeverity: bySev, byKind: byKind, score: s, verdict: verdict(s) };
  }

  function sort(findings) {
    return findings.slice().sort(function (a, b) {
      return (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || a.file.localeCompare(b.file) || a.line - b.line;
    });
  }

  function toSarif(findings) {
    var level = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
    return {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [{
        tool: { driver: { name: "PQC Radar", informationUri: "https://github.com/komarapujordanephraim-creator/pqc-radar",
          rules: RULES.map(function (r) { return { id: r.id, name: r.title, shortDescription: { text: r.title }, help: { text: r.fix } }; }) } },
        results: findings.map(function (f) {
          return { ruleId: f.id, level: level[f.severity], message: { text: f.title + ": " + f.fix },
            locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }] };
        })
      }]
    };
  }

  return { RULES: RULES, scanText: scanText, score: score, verdict: verdict, summarize: summarize, sort: sort, toSarif: toSarif };
});
