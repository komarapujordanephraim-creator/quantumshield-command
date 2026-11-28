/* QuantumShield Command Center: shared store + agent engine.
 * The client portal (app.html) and the admin panel (admin.html) both load this file.
 * Demo build: data lives in this browser (localStorage) so both screens stay in sync,
 * including live updates between open tabs. A production build swaps save/load for an API.
 */
(function (root) {
  "use strict";
  var KEY = "qs_command_v1";

  var COUNTRIES = {
    US: { name: "United States", frameworks: ["NIST FIPS 203/204/205", "CNSA 2.0 (national security suppliers)", "OMB quantum migration guidance"] },
    UK: { name: "United Kingdom", frameworks: ["NCSC PQC timeline: plan 2028, priority 2031, all 2035", "UK GDPR security duty"] },
    EU: { name: "European Union", frameworks: ["EU coordinated PQC roadmap", "DORA (financial entities)", "NIS2", "GDPR Art. 32"] },
    AU: { name: "Australia", frameworks: ["ASD Information Security Manual", "Essential Eight"] },
    CA: { name: "Canada", frameworks: ["Canadian Centre for Cyber Security PQC roadmap", "PIPEDA safeguards"] },
    SG: { name: "Singapore", frameworks: ["MAS Technology Risk Management guidelines", "PDPA protection obligation"] },
    GULF: { name: "Saudi Arabia / UAE", frameworks: ["SAMA cyber security framework", "UAE national information assurance standards"] },
    OTHER: { name: "Other country", frameworks: ["NIST post-quantum standards (global)", "ISO/IEC 27001 cryptography controls"] }
  };

  var PLANS = {
    starter: { name: "Starter", list: 200, repos: 1 },
    growth: { name: "Growth", list: 1000, repos: 5 },
    pro: { name: "Pro", list: 4000, repos: 25 }
  };

  var AGENTS = [
    { id: "discovery", name: "Discovery Agent", role: "Scans code, configs and dependency files for breakable crypto." },
    { id: "guard", name: "Agent Guard", role: "Checks AI-agent configs: auto-approve, wildcard permissions, secrets, unpinned MCP servers." },
    { id: "dollars", name: "Risk-to-Dollars Agent", role: "Prices every finding from your records, cost per record and retention." },
    { id: "compliance", name: "Compliance Agent", role: "Maps findings to the rules of your country and industry." },
    { id: "planner", name: "Fix-Plan Agent", role: "Builds the 90-day plan, ranked by dollars saved per hour of work." },
    { id: "reporter", name: "Report Agent", role: "Writes the board-ready summary and exports JSON / SARIF." }
  ];

  function defaults() {
    return {
      settings: {
        discountPct: 50, minMonths: 3,
        sevShare: { critical: 0.04, high: 0.015, medium: 0.005, low: 0.001, info: 0 },
        agentsEnabled: { discovery: true, guard: true, dollars: true, compliance: true, planner: true, reporter: true }
      },
      clients: [], log: []
    };
  }

  function load() {
    try { var raw = localStorage.getItem(KEY); if (raw) { var d = JSON.parse(raw); var base = defaults();
      d.settings = Object.assign(base.settings, d.settings || {}); d.settings.sevShare = Object.assign(base.settings.sevShare, d.settings.sevShare || {});
      d.settings.agentsEnabled = Object.assign(base.settings.agentsEnabled, d.settings.agentsEnabled || {});
      d.clients = d.clients || []; d.log = d.log || []; return d; } } catch (e) {}
    return defaults();
  }
  var mem = null;
  function save(d) { mem = d; try { localStorage.setItem(KEY, JSON.stringify(d)); } catch (e) {} emit(); }
  function get() { if (!mem) mem = load(); return mem; }
  var subs = [];
  function on(fn) { subs.push(fn); }
  function emit() { subs.forEach(function (f) { try { f(get()); } catch (e) {} }); }
  try { root.addEventListener("storage", function (e) { if (e.key === KEY) { mem = load(); emit(); } }); } catch (e) {}

  function uid() { return Math.random().toString(36).slice(2, 10); }
  function log(msg, clientId) { var d = get(); d.log.unshift({ t: Date.now(), msg: msg, client: clientId || null }); d.log = d.log.slice(0, 300); save(d); }

  function monthly(planId, settings) { var p = PLANS[planId] || PLANS.starter; return Math.round(p.list * (1 - (settings.discountPct || 0) / 100)); }

  /* Agents recommended from the client's own answers */
  function recommendAgents(c) {
    var rec = { discovery: true, dollars: true, planner: true, reporter: true, compliance: true, guard: !!c.usesAgents };
    var why = { guard: c.usesAgents ? "You run AI agents or chatbots." : "Off: you said you do not run AI agents yet.",
      compliance: "Maps to " + (COUNTRIES[c.country] || COUNTRIES.OTHER).name + " rules.",
      dollars: "Uses your " + Number(c.records).toLocaleString("en-US") + " records at $" + c.costPerRecord + " each." };
    return { rec: rec, why: why };
  }

  /* ---- agent engine ---- */
  function runDiscovery(files) {
    var all = [];
    files.forEach(function (f) { all = all.concat(root.PQCRadar.scanText(f.text, f.path)); });
    return root.PQCRadar.sort(all);
  }
  function priceFindings(findings, c, settings) {
    var base = Number(c.records) * Number(c.costPerRecord);
    var until = new Date().getUTCFullYear() + Number(c.retention || 0);
    var hndl = until >= 2030 ? 1 : 0.4;
    // diminishing returns: the nth finding of the same rule counts less
    var seen = {};
    var priced = findings.map(function (f) {
      var share = settings.sevShare[f.severity] || 0;
      if (f.kind === "quantum") share *= hndl;
      var n = (seen[f.id] = (seen[f.id] || 0) + 1);
      var v = base * share / n;
      return Object.assign({}, f, { usd: Math.round(v) });
    });
    var total = priced.reduce(function (a, f) { return a + f.usd; }, 0);
    total = Math.min(total, base); // never more than all records exposed
    return { findings: priced, total: total, base: base, hndl: hndl, until: until };
  }
  var EFFORT = { QR001: 8, QR002: 8, QR003: 6, QR004: 6, QR005: 6, QR006: 2, QC001: 3, QC002: 4, QC003: 3, QC004: 2, QC005: 1, QC006: 3, QC007: 2,
    QA001: 1, QA002: 1, QA003: 1, QA004: 1, QA005: 2, QA006: 2, QA007: 1, QA008: 1, QP001: 0 };
  function plan(priced) {
    var items = priced.filter(function (f) { return f.severity !== "info"; }).map(function (f) {
      var h = EFFORT[f.id] || 3; return Object.assign({}, f, { hours: h, perHour: Math.round(f.usd / Math.max(1, h)) });
    }).sort(function (a, b) { return b.perHour - a.perHour; });
    var phases = [
      { name: "Days 1-30", focus: "Lock down AI agents and leaked secrets", items: [] },
      { name: "Days 31-60", focus: "Crypto inventory, weak crypto, hybrid TLS", items: [] },
      { name: "Days 61-90", focus: "ML-KEM / ML-DSA rollout and CI guardrails", items: [] }
    ];
    items.forEach(function (f) {
      if (f.kind === "agent" || f.id === "QC005") phases[0].items.push(f);
      else if (f.kind === "classical") phases[1].items.push(f);
      else phases[2].items.push(f);
    });
    return { ranked: items, phases: phases };
  }
  function compliance(c, priced) {
    var co = COUNTRIES[c.country] || COUNTRIES.OTHER;
    var q = priced.filter(function (f) { return f.kind === "quantum"; }).length;
    var a = priced.filter(function (f) { return f.kind === "agent"; }).length;
    var cl = priced.filter(function (f) { return f.kind === "classical"; }).length;
    return co.frameworks.map(function (fw) {
      var gaps = /PQC|post-quantum|FIPS 203|CNSA|quantum/i.test(fw) ? q : (/GDPR|PDPA|PIPEDA|DORA|NIS2|SAMA|MAS|27001|Essential|ISM|information assurance/i.test(fw) ? cl + a : q + cl);
      return { framework: fw, gaps: gaps, status: gaps === 0 ? "On track" : gaps < 4 ? "Minor gaps" : "Action needed" };
    });
  }
  function daysToDeprecation() { return Math.max(0, Math.ceil((Date.UTC(2030, 0, 1) - Date.now()) / 864e5)); }

  function money(v) { return "$" + Math.round(v || 0).toLocaleString("en-US"); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (ch) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]; }); }

  root.QS = { KEY: KEY, COUNTRIES: COUNTRIES, PLANS: PLANS, AGENTS: AGENTS, get: get, save: save, on: on, log: log, uid: uid,
    monthly: monthly, recommendAgents: recommendAgents, runDiscovery: runDiscovery, priceFindings: priceFindings, plan: plan,
    compliance: compliance, daysToDeprecation: daysToDeprecation, money: money, esc: esc, defaults: defaults };
})(typeof window !== "undefined" ? window : this);
