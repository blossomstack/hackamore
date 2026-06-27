// hackamore policy studio — a dependency-light single-page app served from the admin
// listener. Three views (Compose / Server / Services) over one shared rule array. Talks to
// GET /admin/services, POST /policy/lint, POST /policy/test, POST /mint. Every edit
// re-renders the read-only JSON export and re-lints; the wire format is never the
// authoring surface.
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const el = (tag, attrs = {}, kids = []) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else n.setAttribute(k, v);
  }
  for (const kid of [].concat(kids)) if (kid != null) n.append(kid);
  return n;
};

// --- state -----------------------------------------------------------------
// Registered services from GET /admin/services: [{name, host, upstreamBase, address,
// auth, credential, model}], where `model` is the imported ApiModel or null.
let SERVICES = [];
let RULES = []; // [{effect, matches:{targets,verbs,resources,conditions}}]
let lintTimer = null;

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const verbLabel = (v) => (v.type === "Method" ? v.value.method : v.value.id);
const methodVerb = (m) => ({ type: "Method", value: { method: m } });
const policyDoc = () => ({ rules: RULES });

// --- shell: tabs + toast ---------------------------------------------------
function showView(name) {
  $$("#tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
}

let toastTimer = null;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

// --- compose: rules --------------------------------------------------------
function renderRules() {
  const root = $("#rules");
  root.replaceChildren();
  RULES.forEach((rule, i) => root.append(ruleCard(rule, i)));
}

// Conditionable field names offered for autocomplete: the union of field names from the
// imported models of this rule's target services (all configured services if no target).
// A service with no model (model: null) contributes nothing.
function fieldOptions(rule) {
  const targets = rule.matches.targets;
  const services = targets.length
    ? targets.map((t) => SERVICES.find((x) => x.name === t)).filter(Boolean)
    : SERVICES;
  const names = new Set();
  for (const s of services) {
    const ops = s.model && Array.isArray(s.model.operations) ? s.model.operations : [];
    for (const op of ops) for (const f of op.fields || []) names.add(f.name);
  }
  return [...names].sort();
}

function ruleCard(rule, i) {
  const card = el("div", { class: "rule" });

  const effect = el("select", { class: `effect-${rule.effect}` });
  for (const e of ["Allow", "Deny"]) {
    const o = el("option", { text: e });
    if (e === rule.effect) o.setAttribute("selected", "");
    effect.append(o);
  }
  effect.onchange = () => {
    rule.effect = effect.value;
    syncFromRules();
  };
  const del = el("button", { class: "del", title: "delete rule", text: "✕" });
  del.onclick = () => {
    RULES.splice(i, 1);
    syncFromRules();
  };
  card.append(el("div", { class: "row rule-top" }, [el("span", { class: "rule-no", text: `rule ${i}` }), effect, del]));

  card.append(listEditor(rule, "targets", "service name (blank = any)"));
  card.append(verbEditor(rule));
  card.append(listEditor(rule, "resources", "path glob, e.g. repos/*/*/pulls"));

  // a per-rule datalist drives condition-field autocomplete from the catalog
  const listId = `fields-r${i}`;
  const dl = el("datalist", { id: listId });
  for (const name of fieldOptions(rule)) dl.append(el("option", { value: name }));
  card.append(dl);
  card.append(conditionEditor(rule, listId));
  return card;
}

// A comma-tolerant editor for a string list (targets, resources).
function listEditor(rule, field, placeholder) {
  const arr = rule.matches[field];
  const input = el("input", { class: "grow", placeholder, value: arr.join(", ") });
  input.onchange = () => {
    rule.matches[field] = input.value.split(",").map((s) => s.trim()).filter(Boolean);
    syncFromRules();
  };
  return el("div", { class: "row" }, [el("label", { class: "field-label", text: field }), input]);
}

function verbEditor(rule) {
  const row = el("div", { class: "row" }, el("label", { class: "field-label", text: "verbs" }));
  for (const m of METHODS) {
    const on = rule.matches.verbs.some((v) => v.type === "Method" && v.value.method === m);
    const b = el("button", { class: `vtoggle v-${m} ${on ? "on" : "off"}`, text: on ? `✓ ${m}` : m });
    b.onclick = () => {
      const idx = rule.matches.verbs.findIndex((v) => v.type === "Method" && v.value.method === m);
      if (idx >= 0) rule.matches.verbs.splice(idx, 1);
      else rule.matches.verbs.push(methodVerb(m));
      syncFromRules();
    };
    row.append(b);
  }
  // preserve any named-action verbs (RPC, not editable here) as removable chips
  rule.matches.verbs
    .filter((v) => v.type === "Action")
    .forEach((v) => {
      const chip = el("button", { class: "vtoggle on", text: `✓ ${verbLabel(v)} ✕`, title: "named action — click to remove" });
      chip.onclick = () => {
        rule.matches.verbs = rule.matches.verbs.filter((x) => x !== v);
        syncFromRules();
      };
      row.append(chip);
    });
  row.append(el("span", { class: "hint", text: "none = any" }));
  return row;
}

// Conditions are a tagged union on the wire: {type, value:{field, ...}}. Equals carries
// {field, value}, OneOf {field, values}, Exists {field}. The editor keeps that nested
// shape so what mints is exactly what the composer shows.
function conditionEditor(rule, listId) {
  const wrap = el("div");
  rule.matches.conditions.forEach((c, ci) => {
    c.value = c.value || {};
    const field = el("input", { value: c.value.field || "", placeholder: "field", list: listId });
    field.onchange = () => {
      c.value.field = field.value;
      syncFromRules();
    };
    const type = el("select");
    for (const t of ["Equals", "OneOf", "Exists"]) {
      const o = el("option", { text: t });
      if (t === c.type) o.setAttribute("selected", "");
      type.append(o);
    }
    type.onchange = () => {
      c.type = type.value;
      const f = c.value.field || "";
      if (c.type === "Equals") c.value = { field: f, value: "" };
      else if (c.type === "OneOf") c.value = { field: f, values: [] };
      else c.value = { field: f };
      syncFromRules();
    };
    const row = el("div", { class: "cond" }, [el("label", { class: "field-label", text: "when" }), field, type]);
    if (c.type !== "Exists") {
      const val = el("input", {
        value: c.type === "OneOf" ? (c.value.values || []).join(", ") : jsonInline(c.value.value),
        placeholder: c.type === "OneOf" ? "v1, v2" : "value",
      });
      val.onchange = () => {
        if (c.type === "OneOf") c.value.values = val.value.split(",").map((s) => parseVal(s.trim()));
        else c.value.value = parseVal(val.value.trim());
        syncFromRules();
      };
      row.append(val);
    }
    const del = el("button", { class: "del", text: "✕" });
    del.onclick = () => {
      rule.matches.conditions.splice(ci, 1);
      syncFromRules();
    };
    row.append(del);
    wrap.append(row);
  });
  const add = el("button", { class: "ghost", text: "+ condition" });
  add.onclick = () => {
    rule.matches.conditions.push({ type: "Equals", value: { field: "", value: "" } });
    syncFromRules();
  };
  wrap.append(el("div", { class: "row" }, add));
  return wrap;
}

const jsonInline = (v) => (typeof v === "string" ? v : JSON.stringify(v));
const parseVal = (s) => {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
};

// --- sync / lint -----------------------------------------------------------
function syncFromRules() {
  renderRules();
  $("#policy-json").value = JSON.stringify(policyDoc(), null, 2);
  scheduleLint();
}

function scheduleLint() {
  clearTimeout(lintTimer);
  lintTimer = setTimeout(lint, 250);
}

async function lint() {
  const status = $("#lint-status");
  let findings;
  try {
    const r = await fetch("/policy/lint", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(policyDoc()),
    });
    findings = await r.json();
  } catch {
    status.textContent = "lint unreachable";
    status.className = "lint-pill err";
    return;
  }
  const box = $("#findings");
  box.replaceChildren();
  const errors = findings.filter((f) => f.severity === "Error").length;
  if (!findings.length) {
    status.textContent = "✓ clean";
    status.className = "lint-pill ok";
    box.append(el("div", { class: "clean", text: "no findings" }));
    return;
  }
  status.textContent = `${errors} error(s), ${findings.length - errors} warning(s)`;
  status.className = errors ? "lint-pill err" : "lint-pill warn";
  for (const f of findings) {
    const sev = f.severity.toLowerCase();
    box.append(el("div", { class: sev, text: `rule ${f.ruleIndex}: ${f.message}` }));
  }
}

// --- compose: dry-run + mint ----------------------------------------------
async function runTest() {
  const out = $("#test-result");
  let fields = {};
  const raw = $("#test-fields").value.trim();
  if (raw) {
    try {
      fields = JSON.parse(raw);
    } catch {
      out.replaceChildren(el("span", { class: "verdict-line deny", text: "fields must be a JSON object" }));
      return;
    }
  }
  const body = {
    policy: policyDoc(),
    target: $("#test-target").value,
    method: $("#test-method").value,
    path: $("#test-path").value || "/",
    query: "",
    fields,
  };
  const r = await fetch("/policy/test", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    out.replaceChildren(el("span", { class: "verdict-line deny", text: (await r.json()).error || `HTTP ${r.status}` }));
    return;
  }
  const res = await r.json();
  const allow = res.verdict.type === "Allow";
  const where = res.matched.type === "Rule" ? `matched rule ${res.matched.value.index}` : "no rule matched";
  const verb = verbLabel(res.action.verb);
  const path = res.action.resource.path;
  const headline = allow ? `✓ Allow · ${where}` : `✕ Deny (${res.verdict.value.reason}) · ${where}`;
  const fieldKeys = Object.keys(res.action.fields || {});
  const fieldStr = fieldKeys.length
    ? fieldKeys.map((k) => `${k}=${jsonInline(res.action.fields[k])}`).join(", ")
    : "—";

  const details = el("details");
  details.append(el("summary", { text: "▸ raw Action" }));
  details.append(el("pre", { text: JSON.stringify(res.action, null, 2) }));

  out.replaceChildren(
    el("div", { class: `verdict-line ${allow ? "allow" : "deny"}`, text: headline }),
    el("div", { class: "meta", text: `normalized to ${verb} ${path}` }),
    el("div", { class: "meta", text: `fields: ${fieldStr}` }),
    details,
  );
}

async function mint() {
  const out = $("#mint-result");
  const r = await fetch("/mint", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ policy: policyDoc(), ttlSeconds: Number($("#mint-ttl").value) }),
  });
  const body = await r.json();
  if (!r.ok) {
    const kids = [el("div", { class: "verdict-line deny", text: body.error || `HTTP ${r.status}` })];
    if (body.findings)
      for (const f of body.findings)
        kids.push(el("div", { class: "meta", text: `${f.severity} rule ${f.ruleIndex}: ${f.message}` }));
    out.replaceChildren(...kids);
    return;
  }
  out.replaceChildren(
    el("div", { class: "verdict-line allow", text: "✓ minted" }),
    el("div", { class: "token", text: body.token }),
    el("div", { class: "meta", text: `expires_at_ms: ${body.expiresAtMs}` }),
  );
}

function importJson() {
  const msg = $("#import-msg");
  try {
    RULES = JSON.parse($("#import-json").value).rules || [];
    syncFromRules();
    msg.textContent = `loaded ${RULES.length} rule(s)`;
    msg.className = "small ok-ink";
    $("#import-json").value = "";
  } catch {
    msg.textContent = "invalid JSON";
    msg.className = "small deny-ink";
  }
}

// --- server view -----------------------------------------------------------
function renderServices() {
  const body = $("#services-body");
  body.replaceChildren();
  if (!SERVICES.length) {
    body.append(el("div", { class: "raw-note", text: "No services configured on this server." }));
    return;
  }
  const th = (t) => el("th", { text: t });
  const table = el("table", { class: "svc-table" });
  table.append(el("tr", {}, [th("service"), th("host"), th("address"), th("outbound"), th("credential id")]));
  for (const s of SERVICES) {
    const authKind = s.auth.split(" ")[0];
    table.append(
      el("tr", {}, [
        el("td", {}, el("b", { text: s.name })),
        el("td", { class: "small" }, document.createTextNode(s.host || "—")),
        el("td", { class: "small" }, document.createTextNode(s.address || "—")),
        el("td", {}, el("span", { class: `auth auth-${authKind}`, text: s.auth })),
        el("td", { class: "small" }, s.credential
          ? el("span", { class: "cred", text: s.credential })
          : el("span", { class: "muted", text: "none" })),
      ]),
    );
  }
  body.append(table);
}

// --- services view (runtime-registered) ------------------------------------
// Rendered from GET /admin/services. Each carries an imported `model` (or null) whose
// operations we render. Add/remove POST/DELETE /admin/services and re-fetch.
function selectorText(sel) {
  if (sel.type === "Route") return `${sel.value.method} ${sel.value.pathTemplate}`;
  return sel.value.name; // Named
}

function svcOpRow(op) {
  // The op no longer carries a verb — derive the chip from its selector (Route → method,
  // Named → action name).
  const v = op.selector.type === "Route" ? op.selector.value.method : op.selector.value.name;
  const head = el("div", { class: "op-head" }, [
    el("span", { class: `vchip v-${v}`, text: v }),
    el("span", { class: "op-id", text: op.id }),
  ]);
  const row = el("div", { class: "op" }, [
    head,
    el("div", { class: "op-route", text: selectorText(op.selector) }),
  ]);
  if (op.summary) row.append(el("div", { class: "op-sum muted small", text: op.summary }));
  return row;
}

function svcCard(svc) {
  const card = el("div", { class: "svc-card" });

  const authKind = svc.auth.split(" ")[0];
  const meta = el("div", { class: "svc-meta" }, [
    el("span", { class: `auth auth-${authKind}`, text: svc.auth }),
  ]);
  if (svc.credential) meta.append(el("span", { class: "cred", text: svc.credential }));
  else meta.append(el("span", { class: "muted small", text: "no credential" }));

  const del = el("button", { class: "del", title: "remove service", text: "✕ remove" });
  del.onclick = () => removeService(svc.name);

  card.append(
    el("div", { class: "svc-card-head" }, [
      el("b", { class: "svc-name", text: svc.name }),
      el("span", { class: "svc-host small muted", text: svc.host }),
      meta,
      del,
    ]),
  );

  const model = svc.model;
  if (!model || !Array.isArray(model.operations)) {
    card.append(el("div", { class: "muted small svc-nomodel", text: "(no description)" }));
    return card;
  }
  const ops = model.operations;
  card.append(el("div", { class: "muted small svc-opcount", text: `(${ops.length} operation${ops.length === 1 ? "" : "s"})` }));
  const list = el("div", { class: "op-list" });
  for (const op of ops) list.append(svcOpRow(op));
  card.append(list);
  return card;
}

// Fetch the live registry into SERVICES, then refresh the views that read it (the
// Compose target select and the Server tab). Returns false when the fetch failed.
async function loadServices() {
  try {
    const r = await fetch("/admin/services");
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const services = await r.json();
    SERVICES = Array.isArray(services) ? services : [];
  } catch {
    return false;
  }
  refreshTargetSelect();
  renderServices();
  return true;
}

// (Re)populate the Compose dry-run target dropdown from SERVICES, preserving the
// current selection when still present.
function refreshTargetSelect() {
  const sel = $("#test-target");
  const prev = sel.value;
  sel.replaceChildren();
  for (const s of SERVICES) sel.append(el("option", { text: s.name }));
  if (SERVICES.some((s) => s.name === prev)) sel.value = prev;
}

async function renderServicesView() {
  const list = $("#svc-list");
  const ok = await loadServices();
  if (!ok) {
    list.replaceChildren(el("div", { class: "raw-note", text: "Could not reach /admin/services." }));
    return;
  }
  list.replaceChildren();
  if (!SERVICES.length) {
    list.append(el("div", { class: "raw-note", text: "No services registered at runtime yet. Add one above." }));
    return;
  }
  for (const svc of SERVICES) list.append(svcCard(svc));
}

async function removeService(name) {
  try {
    const r = await fetch(`/admin/services/${encodeURIComponent(name)}`, { method: "DELETE" });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
  } catch {
    toast(`failed to remove ${name}`);
    return;
  }
  toast(`removed ${name}`);
  renderServicesView();
}

// Build the outbound auth object. The injecting stances carry the real secret inline;
// hackamore vaults it (under the service name) and never echoes it back.
function svcOutbound() {
  const kind = $("#svc-outbound").value;
  const secret = $("#svc-secret").value;
  if (kind === "bearer") return { kind: "bearer", secret };
  if (kind === "header")
    return { kind: "header", name: $("#svc-header-name").value.trim() || "X-API-Key", secret };
  if (kind === "basic")
    return { kind: "basic", username: $("#svc-username").value.trim() || "x-access-token", secret };
  if (kind === "sigv4")
    return {
      kind: "sigv4",
      secret,
      access_key_id: $("#svc-akid").value.trim(),
      region: $("#svc-region").value.trim(),
      service: $("#svc-service").value.trim(),
    };
  return { kind: "passthrough" };
}

function syncSvcOutbound() {
  const kind = $("#svc-outbound").value;
  $("#svc-secret-row").hidden = kind === "passthrough";
  $("#svc-header-row").hidden = kind !== "header";
  $("#svc-basic-row").hidden = kind !== "basic";
  $("#svc-sigv4-row").hidden = kind !== "sigv4";
}

function syncSvcSource() {
  const useFile = $$('input[name="svc-src"]').find((r) => r.checked)?.value === "file";
  $("#svc-file").disabled = !useFile;
  $("#svc-url").disabled = useFile;
}

async function registerService() {
  const err = $("#svc-form-error");
  err.textContent = "";
  const useFile = $$('input[name="svc-src"]').find((r) => r.checked)?.value === "file";
  const body = {
    name: $("#svc-name").value.trim(),
    upstreamBase: $("#svc-upstream").value.trim(),
    idl: $("#svc-idl").value,
    outbound: svcOutbound(),
  };
  const host = $("#svc-host").value.trim();
  if (host) body.host = host; // optional — server defaults it to the upstream host
  if (useFile) body.sourceFile = $("#svc-file").value.trim();
  else body.sourceUrl = $("#svc-url").value.trim();
  const addr = $("#svc-address").value.trim();
  if (addr) body.address = addr;

  let r, payload;
  try {
    r = await fetch("/admin/services", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    payload = await r.json();
  } catch {
    err.textContent = "could not reach /admin/services";
    return;
  }
  if (!r.ok) {
    err.textContent = payload.error || `HTTP ${r.status}`;
    return;
  }
  toast(`registered ${payload.name}`);
  $("#svc-name").value = "";
  $("#svc-host").value = "";
  $("#svc-upstream").value = "";
  $("#svc-file").value = "";
  $("#svc-url").value = "";
  $("#svc-address").value = "";
  $("#svc-secret").value = "";
  $("#svc-username").value = "x-access-token";
  $("#svc-akid").value = "";
  $("#svc-region").value = "";
  $("#svc-service").value = "";
  renderServicesView();
}

// --- boot ------------------------------------------------------------------
async function boot() {
  // The configured + runtime-registered services drive the Compose target dropdown, the
  // condition-field autocomplete, and the Server/Services views.
  await loadServices();

  $$("#tabs .tab").forEach(
    (t) =>
      (t.onclick = () => {
        showView(t.dataset.view);
        if (t.dataset.view === "services") renderServicesView();
      }),
  );

  $("#add-rule").onclick = () => {
    RULES.push({ effect: "Allow", matches: { targets: [], verbs: [], resources: [], conditions: [] } });
    syncFromRules();
  };
  $("#copy-json").onclick = () => navigator.clipboard?.writeText($("#policy-json").value);
  $("#apply-json").onclick = importJson;
  $("#run-test").onclick = runTest;
  $("#mint").onclick = mint;

  // services view: source toggle, outbound reveal, register
  $$('input[name="svc-src"]').forEach((r) => (r.onchange = syncSvcSource));
  $("#svc-outbound").onchange = syncSvcOutbound;
  $("#svc-register").onclick = registerService;
  syncSvcSource();
  syncSvcOutbound();
  renderServicesView();

  // Seed with a starter rule so the composer isn't empty.
  RULES = [{ effect: "Allow", matches: { targets: [], verbs: [methodVerb("GET")], resources: [], conditions: [] } }];
  syncFromRules();
}

boot();
