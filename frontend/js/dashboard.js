/* ───────────────────────────────────────────────────────────────────
   Quantum-Safe KMS v2.0 — Dashboard JavaScript
   Complete rewrite for Capstone 2 lifecycle model.
   ─────────────────────────────────────────────────────────────────── */

const API  = "";          // same-origin; change to http://localhost:8001 for dev
const POLL = 30000;       // health poll interval (ms)

// ── Navigation ────────────────────────────────────────────────────────

document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", e => {
    e.preventDefault();
    const sec = item.dataset.section;
    navigate(sec);
  });
});

function navigate(section) {
  document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.section === section));
  document.querySelectorAll(".section").forEach(s => s.classList.toggle("active", s.id === `section-${section}`));
  document.getElementById("page-title").textContent = {
    dashboard:  "Dashboard",
    keys:       "Key Inventory",
    encrypt:    "Encrypt / Decrypt",
    rotation:   "Rotation",
    compliance: "Compliance",
    audit:      "Audit Logs",
    providers:  "KMS Providers",
  }[section] || section;

  if (section === "keys")       loadKeys();
  if (section === "audit")      loadAudit();
  if (section === "rotation")   loadRotationStatus();
  if (section === "compliance") loadCompliance();
  if (section === "providers")  loadProviders();
}

// ── Health + Provider Strip ────────────────────────────────────────────

async function loadHealth() {
  try {
    const h = await apiFetch("/healthz");
    updateProviderStrip(h);
    updateSysStatus(h);
  } catch {
    document.getElementById("status-text").textContent = "API unreachable";
    document.getElementById("status-dot").className    = "status-dot error";
  }
}

function updateProviderStrip(h) {
  const setChip = (chipId, dotId, modeId, mode) => {
    const chip = document.getElementById(chipId);
    const dot  = document.getElementById(dotId);
    const mEl  = document.getElementById(modeId);
    if (!chip) return;
    const cls = mode === "LIVE" ? "live" : mode === "SIM" ? "sim" : "doc";
    chip.className = `provider-chip ${cls}`;
    if (dot)  { dot.className = `chip-dot ${cls}`; }
    if (mEl)  { mEl.textContent = mode; }
  };

  setChip("chip-aws",   "dot-aws",   "mode-aws",   h.aws_kms_mode);
  setChip("chip-azure", "dot-azure", "mode-azure",  h.azure_kv_mode);
  setChip("chip-pqc",   "dot-pqc",   "mode-pqc",   h.pqc_mode === "AVAILABLE" ? "LIVE" : "SIM");
  const rEl = document.getElementById("chip-region");
  if (rEl) rEl.textContent = h.region || "local";
}

function updateSysStatus(h) {
  const dot  = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  const live = h.aws_kms_mode === "LIVE" || h.azure_kv_mode === "LIVE";
  dot.className  = `status-dot ${live ? "live" : "sim"}`;
  text.textContent = live ? "Cloud LIVE" : "Simulation";
}

// ── Dashboard overview ────────────────────────────────────────────────

async function loadDashboard() {
  await loadHealth();
  await loadComplianceEvidence(true);  // stats only
  await loadRecentAudit();
  await loadFrameworks();
}

async function loadComplianceEvidence(statsOnly = false) {
  try {
    const ev = await apiFetch("/api/v1/lifecycle/compliance");
    document.getElementById("sv-total").textContent     = ev.inventory;
    document.getElementById("sv-versions").textContent  = ev.total_versions;
    document.getElementById("sv-pqc").textContent       = ev.pqc_ready_versions;
    document.getElementById("sv-violations").textContent = ev.violations;
    document.getElementById("sv-score").textContent     = `${ev.pqc_ready_pct}%`;
    // rotation due: query keys
    try {
      const keys = await apiFetch("/api/v1/lifecycle/keys");
      const now  = Date.now();
      const due  = keys.filter(k => k.rotation_due_at && new Date(k.rotation_due_at) < now).length;
      document.getElementById("sv-rotation").textContent = due;
    } catch { document.getElementById("sv-rotation").textContent = "–"; }
  } catch (e) {
    console.warn("Evidence load failed:", e);
  }
}

async function loadFrameworks() {
  try {
    const ev = await apiFetch("/api/v1/lifecycle/compliance");
    const row = document.getElementById("framework-row");
    if (!row || !ev.frameworks) return;
    row.innerHTML = ev.frameworks.map(f => `
      <div class="fw-card ${f.status.toLowerCase()}">
        <div class="fw-name">${f.framework}</div>
        <div class="fw-status ${f.status.toLowerCase()}">${f.status}</div>
        <div class="fw-ctrl">${f.control}</div>
      </div>
    `).join("");
  } catch {}
}

async function loadRecentAudit() {
  try {
    const logs = await apiFetch("/api/v1/keys/audit?limit=8").catch(() => []);
    const tb   = document.getElementById("tbody-recent");
    if (!tb) return;
    if (!logs.length) { tb.innerHTML = `<tr><td colspan="5" class="empty-state-cell">No activity yet.</td></tr>`; return; }
    tb.innerHTML = logs.map(l => `
      <tr>
        <td class="mono-sm">${fmt(l.timestamp)}</td>
        <td><span class="badge badge-active">${l.action}</span></td>
        <td class="mono">${l.key_id ? l.key_id.slice(0,8) + "…" : "–"}</td>
        <td class="mono">${l.version_id ? "v?" : "–"}</td>
        <td>${l.success ? "✓" : "✗"}</td>
      </tr>`).join("");
  } catch {}
}

// ── Key Inventory ─────────────────────────────────────────────────────

async function loadKeys() {
  try {
    const keys = await apiFetch("/api/v1/lifecycle/keys");
    const tb   = document.getElementById("tbody-keys");
    const emp  = document.getElementById("keys-empty");
    if (!keys.length) {
      tb.innerHTML = "";
      if (emp) emp.style.display = "flex";
      return;
    }
    if (emp) emp.style.display = "none";
    tb.innerHTML = keys.map(k => {
      const risk = riskBadge(k.is_quantum_safe, k.is_hybrid);
      return `
        <tr>
          <td><b>${k.name}</b></td>
          <td class="mono-sm">${k.algorithm || "–"}</td>
          <td>${providerBadge(k.kms_provider)}</td>
          <td><span class="badge badge-active">v${k.active_version_number || 1}</span></td>
          <td>${k.total_versions || 1}</td>
          <td>${risk}</td>
          <td>${statusBadge(k.status)}</td>
          <td>
            <div class="action-btns">
              <button class="btn btn-ghost btn-sm" onclick="showVersions('${k.id}','${k.name}')">History</button>
              <button class="btn btn-ghost btn-sm" onclick="rotateKey('${k.id}')">↺ Rotate</button>
            </div>
          </td>
        </tr>`;
    }).join("");
  } catch (e) {
    console.error("loadKeys:", e);
    toast("Failed to load keys", "error");
  }
}

async function showVersions(keyId, alias) {
  const panel = document.getElementById("version-panel");
  const title = document.getElementById("version-panel-title");
  const tb    = document.getElementById("tbody-versions");
  panel.style.display = "block";
  title.textContent   = `Version History — ${alias}`;
  tb.innerHTML = `<tr><td colspan="8" style="color:var(--txt-muted);padding:20px;text-align:center">Loading…</td></tr>`;

  try {
    const vs = await apiFetch(`/api/v1/lifecycle/keys/${keyId}/versions`);
    if (!vs.length) {
      tb.innerHTML = `<tr><td colspan="8" style="color:var(--txt-muted);padding:20px;text-align:center">No versions found.</td></tr>`;
      return;
    }
    tb.innerHTML = vs.map(v => `
      <tr>
        <td><b class="mono">v${v.version_number}</b></td>
        <td>${stateBadge(v.state)}</td>
        <td class="mono-sm">${v.pqc_algorithm} + ${v.classical_algorithm}</td>
        <td>${quantumBadge(v.quantum_risk_tag)}</td>
        <td class="mono-sm">${v.transit_posture}</td>
        <td class="mono-sm">${fmtShort(v.created_at)}</td>
        <td class="mono-sm">${v.rotation_due_at ? fmtShort(v.rotation_due_at) : "–"}</td>
        <td>
          <div class="action-btns">
            ${v.state === "ACTIVE" || v.state === "RETIRED" ?
              `<button class="btn btn-ghost btn-sm" onclick="encryptWithKey('${keyId}')">🔐 Encrypt</button>` : ""}
          </div>
        </td>
      </tr>`).join("");
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="8" style="color:var(--c-red)">Error: ${e.message}</td></tr>`;
  }
  panel.scrollIntoView({ behavior: "smooth" });
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────

function encryptWithKey(keyId) {
  navigate("encrypt");
  // auto-fill won't have alias here easily, but navigate and let user go
}

document.getElementById("btn-encrypt").addEventListener("click", async () => {
  const alias    = document.getElementById("enc-alias").value.trim();
  const tenant   = document.getElementById("enc-tenant").value.trim();
  const plain    = document.getElementById("enc-plaintext").value.trim();
  const resultEl = document.getElementById("enc-result");
  const envEl    = document.getElementById("envelope-viewer");
  const envGrid  = document.getElementById("envelope-grid");

  if (!alias || !plain) { toast("Key alias and plaintext required", "error"); return; }

  resultEl.style.display = "none";
  envEl.style.display    = "none";

  try {
    // Look up key by alias
    const key = await apiFetch(`/api/v1/lifecycle/keys/by-name/${alias}`);
    // Encrypt
    const res = await apiFetch(`/api/v1/lifecycle/keys/${key.id}/encrypt`, {
      method: "POST",
      body: JSON.stringify({ plaintext: plain, tenant_context: tenant }),
    });

    resultEl.className   = "result-box success";
    resultEl.textContent = JSON.stringify({
      envelope_id:    res.envelope_id,
      key_alias:      res.key_alias,
      version:        `v${res.version_number}`,
      aws_mode:       res.aws_mode,
      pqc_available:  res.pqc_available,
    }, null, 2);
    resultEl.style.display = "block";

    // Show envelope structure
    const env = res.envelope || {};
    const fields = [
      ["version", env.version, "algo"],
      ["combiner", env.combiner, "algo"],
      ["pqc_algo", env.pqc_algo, "algo"],
      ["sign_algo", env.sign_algo, "algo"],
      ["classical_algo", env.classical_algo, "algo"],
      ["aws_mode", env.aws_mode, "mode"],
      ["pqc_available", String(env.pqc_available), "mode"],
      ["tenant", env.tenant, ""],
      ["ciphertext", env.ciphertext ? env.ciphertext.slice(0,30)+"…" : "–", ""],
      ["mlkem_ct", env.mlkem_ct ? env.mlkem_ct.slice(0,30)+"…" : "–", ""],
      ["mldsa_sig", env.mldsa_sig ? env.mldsa_sig.slice(0,30)+"…" : "–", ""],
      ["aws_wrapped_dk", env.aws_wrapped_dk ? env.aws_wrapped_dk.slice(0,30)+"…" : "–", ""],
    ];
    envGrid.innerHTML = fields.map(([k, v, cls]) => `
      <div class="env-field">
        <div class="env-key">${k}</div>
        <div class="env-val ${cls}">${v || "–"}</div>
      </div>`).join("");
    envEl.style.display = "block";

    // Auto-fill decrypt field
    document.getElementById("dec-envelope-id").value = res.envelope_id;

    toast(`Encrypted with v${res.version_number} (${res.aws_mode})`, "success");
  } catch (e) {
    resultEl.className   = "result-box error";
    resultEl.textContent = `Error: ${e.message}`;
    resultEl.style.display = "block";
    toast("Encryption failed", "error");
  }
});

document.getElementById("btn-decrypt").addEventListener("click", async () => {
  const envId  = document.getElementById("dec-envelope-id").value.trim();
  const resEl  = document.getElementById("dec-result");
  if (!envId) { toast("Envelope ID required", "error"); return; }

  resEl.style.display = "none";
  try {
    const res = await apiFetch("/api/v1/lifecycle/decrypt", {
      method: "POST",
      body: JSON.stringify({ envelope_id: envId }),
    });
    resEl.className   = "result-box success";
    resEl.textContent = JSON.stringify({
      plaintext:      res.plaintext,
      key_alias:      res.key_alias,
      version:        `v${res.version_number}`,
      tenant_context: res.tenant_context,
    }, null, 2);
    resEl.style.display = "block";
    toast("Decryption successful", "success");
  } catch (e) {
    resEl.className   = "result-box error";
    resEl.textContent = `Error: ${e.message}`;
    resEl.style.display = "block";
    toast("Decryption failed", "error");
  }
});

// ── Rotation ──────────────────────────────────────────────────────────

async function loadRotationStatus() {
  try {
    const r  = await apiFetch("/api/v1/lifecycle/rotation-status");
    const el = document.getElementById("rotation-status-body");
    el.innerHTML = `
      <div class="saga-info">
        <div class="saga-stat"><span>Scheduler</span><b style="color:${r.running ? "var(--c-emerald)" : "var(--c-red)"}">${r.running ? "Running" : "Stopped"}</b></div>
        <div class="saga-stat"><span>Interval</span><b>${r.interval_seconds}s</b></div>
        <div class="saga-stat"><span>Next Fire</span><b>${r.next_fire_time ? fmtShort(r.next_fire_time) : "–"}</b></div>
        <div class="saga-stat"><span>Keys Due</span><b style="color:${r.keys_due_rotation > 0 ? "var(--c-amber)" : "var(--c-emerald)"}">${r.keys_due_rotation}</b></div>
        <div class="saga-stat"><span>Total Keys</span><b>${r.total_keys}</b></div>
      </div>`;
  } catch {}
}

document.getElementById("btn-rotate-now").addEventListener("click", async () => {
  const resEl = document.getElementById("rotation-result");
  resEl.style.display = "none";
  try {
    const r = await apiFetch("/api/v1/lifecycle/rotate-now", { method: "POST" });
    resEl.className   = "result-box success";
    resEl.textContent = JSON.stringify(r, null, 2);
    resEl.style.display = "block";
    toast(`Rotated ${r.rotated?.length || 0} key(s)`, "success");
    await loadRotationStatus();
    await loadKeys();
  } catch (e) {
    resEl.className   = "result-box error";
    resEl.textContent = `Error: ${e.message}`;
    resEl.style.display = "block";
    toast("Rotation failed", "error");
  }
});

async function rotateKey(keyId) {
  try {
    await apiFetch(`/api/v1/lifecycle/keys/${keyId}/rotate`, {
      method: "POST",
      body: JSON.stringify({ reason: "Manual rotation from dashboard" }),
    });
    toast("Key rotated successfully", "success");
    await loadKeys();
  } catch (e) {
    toast(`Rotation failed: ${e.message}`, "error");
  }
}

// ── Compliance ────────────────────────────────────────────────────────

async function loadCompliance() {
  try {
    const ev = await apiFetch("/api/v1/lifecycle/compliance");

    // Summary strip
    const sumEl = document.getElementById("compliance-summary");
    sumEl.className = "compliance-summary";
    sumEl.innerHTML = `
      <div class="cs-item"><div class="cs-lbl">Inventory</div><div class="cs-val teal">${ev.inventory}</div></div>
      <div class="cs-item"><div class="cs-lbl">Versions</div><div class="cs-val teal">${ev.total_versions}</div></div>
      <div class="cs-item"><div class="cs-lbl">PQC-Ready</div><div class="cs-val green">${ev.pqc_ready_versions}</div></div>
      <div class="cs-item"><div class="cs-lbl">PQC Coverage</div><div class="cs-val green">${ev.pqc_ready_pct}%</div></div>
      <div class="cs-item"><div class="cs-lbl">Violations</div><div class="cs-val ${ev.violations > 0 ? "red" : "green"}">${ev.violations}</div></div>
      <div class="cs-item"><div class="cs-lbl">AWS Mode</div><div class="cs-val ${ev.provider_panel.aws_kms?.mode === "LIVE" ? "green" : "amber"}">${ev.provider_panel.aws_kms?.mode || "–"}</div></div>
      <div class="cs-item"><div class="cs-lbl">Azure Mode</div><div class="cs-val ${ev.provider_panel.azure_kv?.mode === "LIVE" ? "green" : "amber"}">${ev.provider_panel.azure_kv?.mode || "–"}</div></div>
    `;

    // Frameworks table
    const tb = document.getElementById("tbody-frameworks");
    tb.innerHTML = (ev.frameworks || []).map(f => `
      <tr>
        <td><b>${f.framework}</b></td>
        <td class="mono-sm">${f.control}</td>
        <td><span class="badge ${f.status === "COMPLIANT" ? "badge-active" : f.status === "PARTIAL" ? "badge-sim" : "badge-noncomp"}">${f.status}</span></td>
      </tr>`).join("");

    // Capability matrix
    loadCapabilityMatrix(ev);
  } catch (e) {
    console.error("loadCompliance:", e);
    toast("Failed to load compliance", "error");
  }
}

async function loadCapabilityMatrix(ev) {
  try {
    const cap = await apiFetch("/api/v1/providers/capability-matrix");
    const tb  = document.getElementById("tbody-providers-cap");
    if (!tb) return;
    tb.innerHTML = cap.providers.map(p => `
      <tr>
        <td><b>${p.provider}</b></td>
        <td>${providerBadge(p.provider)}</td>
        <td><span class="badge ${p.pq_import_support ? "badge-pq-yes" : "badge-pq-no"}">${p.pq_import_support ? "✓ YES" : "✗ NO"}</span></td>
        <td class="mono-sm">${p.transit_posture}</td>
        <td class="mono-sm">${(p.import_methods || []).join(", ")}</td>
        <td style="font-size:0.72rem;color:var(--txt-muted);max-width:260px">${p.notes}</td>
      </tr>`).join("");
  } catch {}
}

// ── Audit Logs ────────────────────────────────────────────────────────

async function loadAudit() {
  try {
    const logs = await apiFetch("/api/v1/compliance/audit?limit=50").catch(
      () => apiFetch("/api/v1/keys/audit?limit=50").catch(() => [])
    );
    const tb = document.getElementById("tbody-audit");
    if (!logs.length) {
      tb.innerHTML = `<tr><td colspan="6" style="color:var(--txt-muted);padding:20px;text-align:center">No audit records.</td></tr>`;
      return;
    }
    tb.innerHTML = logs.map(l => `
      <tr>
        <td class="mono-sm">${fmt(l.timestamp)}</td>
        <td><span class="badge badge-active">${l.action}</span></td>
        <td class="mono">${l.key_id ? l.key_id.slice(0,8)+"…" : "–"}</td>
        <td class="mono">${l.version_id ? l.version_id.slice(0,8)+"…" : "–"}</td>
        <td class="mono-sm">${JSON.stringify(l.details || {}).slice(0,80)}</td>
        <td style="color:${l.success ? "var(--c-emerald)" : "var(--c-red)"}">${l.success ? "✓" : "✗"}</td>
      </tr>`).join("");
  } catch {}
}

// ── Providers ─────────────────────────────────────────────────────────

async function loadProviders() {
  try {
    const h   = await apiFetch("/healthz");
    const cap = await apiFetch("/api/v1/providers/capability-matrix");
    const grid = document.getElementById("providers-grid");

    const PROVIDERS = [
      { name: "aws_kms",  label: "AWS KMS",         icon: "☁", mode: h.aws_kms_mode,  region: h.region, arn: h.key_arn },
      { name: "azure_kv", label: "Azure Key Vault",  icon: "☁", mode: h.azure_kv_mode, region: "–", arn: "–" },
      { name: "gcp_kms",  label: "GCP Cloud KMS",    icon: "☁", mode: "DOC",           region: "global", arn: "–" },
    ];

    grid.innerHTML = PROVIDERS.map(p => {
      const capInfo = cap.providers?.find(c => c.provider === p.name) || {};
      return `
        <div class="provider-card ${p.mode.toLowerCase()}">
          <div class="prov-header">
            <div class="prov-icon" style="background:${p.mode === "LIVE" ? "var(--c-emerald-glow)" : p.mode === "SIM" ? "var(--c-amber-glow)" : "var(--c-purple-glow)"}">${p.icon}</div>
            <div>
              <div class="prov-name">${p.label}</div>
              <span class="badge ${p.mode === "LIVE" ? "badge-live" : p.mode === "SIM" ? "badge-sim" : "badge-doc"}">${p.mode}</span>
            </div>
          </div>
          <div class="prov-row"><span class="prov-lbl">Region</span><span class="prov-val">${p.region}</span></div>
          <div class="prov-row"><span class="prov-lbl">PQ Import</span><span class="badge ${capInfo.pq_import_support ? "badge-pq-yes" : "badge-pq-no"}">${capInfo.pq_import_support ? "✓ YES" : "✗ NO"}</span></div>
          <div class="prov-row"><span class="prov-lbl">Transit Posture</span><span class="prov-val">${capInfo.transit_posture || "–"}</span></div>
          ${p.arn && p.arn !== "–" ? `<div class="prov-row"><span class="prov-lbl">Key ARN</span><span class="mono-sm" style="max-width:180px;overflow:hidden;text-overflow:ellipsis">${p.arn}</span></div>` : ""}
        </div>`;
    }).join("");
  } catch {}
}

// ── Create Key Modal ──────────────────────────────────────────────────

["btn-create-key", "btn-create-key2"].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener("click", () => document.getElementById("modal-create").style.display = "flex");
});
["modal-close", "btn-cancel-modal"].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener("click", () => document.getElementById("modal-create").style.display = "none");
});

document.getElementById("form-create").addEventListener("submit", async e => {
  e.preventDefault();
  const payload = {
    name:          document.getElementById("inp-name").value.trim(),
    algorithm:     document.getElementById("inp-algo").value,
    kms_provider:  document.getElementById("inp-provider").value,
    owner:         document.getElementById("inp-owner").value.trim() || undefined,
    environment:   document.getElementById("inp-env").value,
    purpose:       document.getElementById("inp-purpose").value.trim() || undefined,
    rotation_days: parseInt(document.getElementById("inp-rotation").value) || 365,
  };
  try {
    await apiFetch("/api/v1/lifecycle/keys", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    document.getElementById("modal-create").style.display = "none";
    toast(`Key '${payload.name}' created`, "success");
    await loadKeys();
    navigate("keys");
  } catch (e) {
    toast(`Create failed: ${e.message}`, "error");
  }
});

// ── Compliance download ────────────────────────────────────────────────

document.getElementById("btn-download-evidence").addEventListener("click", async () => {
  try {
    const ev   = await apiFetch("/api/v1/lifecycle/compliance");
    const blob = new Blob([JSON.stringify(ev, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = "compliance_evidence.json";
    a.click();
    URL.revokeObjectURL(url);
    toast("Evidence downloaded", "success");
  } catch { toast("Download failed", "error"); }
});

document.getElementById("btn-gen-report").addEventListener("click", async () => {
  try {
    const r = await apiFetch("/api/v1/lifecycle/compliance/generate-report", { method: "POST" });
    toast(`Report generated — ${r.pqc_ready_versions} PQC-ready, ${r.violations} violations`, "success");
    await loadCompliance();
  } catch (e) { toast(`Report failed: ${e.message}`, "error"); }
});

// ── Refresh ────────────────────────────────────────────────────────────

document.getElementById("btn-refresh").addEventListener("click", () => loadDashboard());

// ── Demo Mode ─────────────────────────────────────────────────────────

let DEMO_MODE = false;

// Pre-baked demo key IDs (stable across the session)
const _DK = [
  "7ba88dd7-0001-4a2b-9c3d-e5f621a87b4c",
  "7ba88dd7-0002-4a2b-9c3d-e5f621a87b4c",
  "7ba88dd7-0003-4a2b-9c3d-e5f621a87b4c",
  "7ba88dd7-0004-4a2b-9c3d-e5f621a87b4c",
  "7ba88dd7-0005-4a2b-9c3d-e5f621a87b4c",
  "7ba88dd7-0006-4a2b-9c3d-e5f621a87b4c",
  "7ba88dd7-0007-4a2b-9c3d-e5f621a87b4c",
  "7ba88dd7-0008-4a2b-9c3d-e5f621a87b4c",
];

const _DEMO_KEYS = [
  { id:_DK[0], name:"prod-hybrid-payment-gateway",   algorithm:"HYBRID-ML-KEM-768-AES-256-GCM", kms_provider:"aws_kms",   status:"active",   risk_level:"low",    owner:"payments-team",   environment:"production",  purpose:"Payment data encryption",     is_quantum_safe:true,  is_hybrid:true,  active_version_number:3, total_versions:3, rotation_due_at: new Date(Date.now()+78*86400000).toISOString(), rotation_count:2 },
  { id:_DK[1], name:"prod-kyber-api-gateway",        algorithm:"HYBRID-ML-KEM-768-AES-256-GCM", kms_provider:"aws_kms",   status:"active",   risk_level:"low",    owner:"platform-team",   environment:"production",  purpose:"API authentication",           is_quantum_safe:true,  is_hybrid:false, active_version_number:1, total_versions:1, rotation_due_at: new Date(Date.now()+80*86400000).toISOString(), rotation_count:0 },
  { id:_DK[2], name:"prod-dilithium-code-signing",   algorithm:"HYBRID-ML-KEM-768-AES-256-GCM", kms_provider:"azure_kv",  status:"active",   risk_level:"low",    owner:"devops-team",     environment:"production",  purpose:"CI/CD pipeline signing",       is_quantum_safe:true,  is_hybrid:true,  active_version_number:2, total_versions:2, rotation_due_at: new Date(Date.now()+55*86400000).toISOString(), rotation_count:1 },
  { id:_DK[3], name:"prod-hybrid-health-records",    algorithm:"HYBRID-ML-KEM-768-AES-256-GCM", kms_provider:"azure_kv",  status:"active",   risk_level:"low",    owner:"hipaa-team",      environment:"production",  purpose:"PHI data encryption",          is_quantum_safe:true,  is_hybrid:true,  active_version_number:1, total_versions:1, rotation_due_at: new Date(Date.now()+70*86400000).toISOString(), rotation_count:0 },
  { id:_DK[4], name:"customer-data",                 algorithm:"HYBRID-ML-KEM-768-AES-256-GCM", kms_provider:"aws_kms",   status:"active",   risk_level:"low",    owner:"system",          environment:"production",  purpose:"Demo key for Capstone 2",      is_quantum_safe:true,  is_hybrid:true,  active_version_number:1, total_versions:1, rotation_due_at: new Date(Date.now()+365*86400000).toISOString(), rotation_count:0 },
  { id:_DK[5], name:"prod-aes-s3-backup",            algorithm:"AES-256-GCM",                   kms_provider:"aws_kms",   status:"active",   risk_level:"medium", owner:"infra-team",      environment:"production",  purpose:"S3 backup encryption",         is_quantum_safe:false, is_hybrid:false, active_version_number:4, total_versions:4, rotation_due_at: new Date(Date.now()-1*86400000).toISOString(),  rotation_count:3 },
  { id:_DK[6], name:"prod-rsa-legacy-tls",           algorithm:"RSA-4096",                      kms_provider:"aws_kms",   status:"active",   risk_level:"high",   owner:"networking-team", environment:"production",  purpose:"Legacy TLS termination",       is_quantum_safe:false, is_hybrid:false, active_version_number:7, total_versions:7, rotation_due_at: new Date(Date.now()-210*86400000).toISOString(), rotation_count:6 },
  { id:_DK[7], name:"dev-rsa-jwt-legacy",            algorithm:"RSA-4096",                      kms_provider:"azure_kv",  status:"revoked",  risk_level:"critical",owner:"backend-team",    environment:"development", purpose:"Legacy JWT signing (deprecated)",is_quantum_safe:false, is_hybrid:false, active_version_number:10,total_versions:10,rotation_due_at: new Date(Date.now()-410*86400000).toISOString(), rotation_count:9 },
];

function _demoVersions(keyId) {
  const k = _DEMO_KEYS.find(x => x.id === keyId);
  if (!k) return [];
  const total = k.total_versions;
  const now   = new Date();
  return Array.from({length: total}, (_, i) => {
    const vn   = i + 1;
    const isActive = vn === k.active_version_number;
    const isHybrid = k.is_hybrid && k.is_quantum_safe;
    return {
      id:                 `${keyId}-v${vn}`,
      key_id:             keyId,
      version_number:     vn,
      state:              isActive ? "ACTIVE" : vn === total - 1 ? "RETIRED" : "RETIRED",
      quantum_risk_tag:   isHybrid ? "HYBRID_READY" : k.is_quantum_safe ? "PQC_READY" : "QUANTUM_VULNERABLE",
      transit_posture:    k.kms_provider === "gcp_kms" ? "pq_native" : "classical_only",
      pqc_algorithm:      k.is_quantum_safe ? "ML-KEM-768" : "None",
      classical_algorithm:k.algorithm.includes("AES") ? "AES-256-GCM" : k.algorithm,
      sign_algorithm:     k.is_quantum_safe ? "ML-DSA-65" : "RSA-4096",
      created_at:         new Date(now - (total - vn) * 30 * 86400000).toISOString(),
      rotation_due_at:    isActive ? k.rotation_due_at : null,
    };
  }).reverse();
}

const _DEMO_COMPLIANCE = {
  inventory:          _DEMO_KEYS.length,
  total_versions:     _DEMO_KEYS.reduce((s, k) => s + k.total_versions, 0),
  pqc_ready_versions: _DEMO_KEYS.filter(k => k.is_quantum_safe).reduce((s, k) => s + k.total_versions, 0),
  pqc_ready_pct:      Math.round(_DEMO_KEYS.filter(k => k.is_quantum_safe).length / _DEMO_KEYS.length * 100),
  violations:         2,
  provider_panel:     { aws_kms: { mode: "SIM" }, azure_kv: { mode: "SIM" }, gcp_kms: { mode: "DOC" } },
  frameworks: [
    { framework:"RBI CYBER SECURITY FRAMEWORK", control:"Annual key rotation + quantum-safe wrapping", status:"COMPLIANT" },
    { framework:"PCI-DSS V4.0 §3.7.1",          control:"365-day max key-usage period (configured: 90d)", status:"COMPLIANT" },
    { framework:"DORA ART. 9",                   control:"ICT cryptographic risk management", status:"COMPLIANT" },
    { framework:"NIST SP 800-57 / FIPS 203",     control:"ML-KEM-768 hybrid key lifecycle", status:"COMPLIANT" },
    { framework:"FIPS 140-3",                     control:"Approved PQC algorithms (ML-KEM-768, ML-DSA-65)", status:"COMPLIANT" },
  ],
};

const _DEMO_AUDIT = (() => {
  const actions = ["key_created","encrypt","decrypt","key_rotated","key_rotated","encrypt","decrypt","encrypt","decrypt","key_created","encrypt","decrypt","key_rotated","encrypt","decrypt"];
  const now = Date.now();
  return actions.map((action, i) => ({
    id:         `audit-demo-${i}`,
    key_id:     _DK[i % _DK.length],
    version_id: `${_DK[i % _DK.length]}-v1`,
    action,
    actor:      ["alice@org.com","ci-pipeline","rotation-scheduler","bob@org.com","compliance-scanner"][i % 5],
    timestamp:  new Date(now - i * 3600000 * 2.3).toISOString(),
    success:    true,
    details:    { message: action.replace("_"," ") + " completed successfully" },
  }));
})();

let _demoEnvelopeStore = {};   // envelope_id → { plaintext, key_alias, version_number }

async function _demoFetch(path, opts) {
  const method = (opts.method || "GET").toUpperCase();
  await new Promise(r => setTimeout(r, 120 + Math.random() * 80));  // fake latency

  // /healthz
  if (path === "/healthz") return {
    status:"ok", pqc_available:true, pqc_mode:"AVAILABLE",
    aws_kms_mode:"SIM", azure_kv_mode:"SIM", gcp_kms_mode:"DOC",
    region:"eu-north-1", key_arn:"arn:aws:kms:eu-north-1:123456789012:key/demo", timestamp:new Date().toISOString(),
    providers:["aws_kms","azure_kv"],
  };

  // /api/v1/lifecycle/keys  (GET list or POST create)
  if (path === "/api/v1/lifecycle/keys") {
    if (method === "POST") {
      const body = JSON.parse(opts.body || "{}");
      const newKey = { id:`demo-new-${Date.now()}`, name:body.name, algorithm:body.algorithm||"HYBRID-ML-KEM-768-AES-256-GCM",
        kms_provider:body.kms_provider||"aws_kms", status:"active", risk_level:"low",
        owner:body.owner||"user", environment:body.environment||"production", purpose:body.purpose||"",
        is_quantum_safe:true, is_hybrid:true, active_version_number:1, total_versions:1,
        rotation_due_at:new Date(Date.now()+(body.rotation_days||365)*86400000).toISOString(), rotation_count:0 };
      _DEMO_KEYS.push(newKey);
      return newKey;
    }
    return _DEMO_KEYS;
  }

  // /api/v1/lifecycle/keys/by-name/:name
  const byName = path.match(/^\/api\/v1\/lifecycle\/keys\/by-name\/(.+)$/);
  if (byName) {
    const alias = decodeURIComponent(byName[1]);
    const found = _DEMO_KEYS.find(k => k.name === alias);
    if (!found) throw new Error(`Key '${alias}' not found. In Demo Mode, use 'customer-data'.`);
    return found;
  }

  // /api/v1/lifecycle/keys/:id/versions
  const versions = path.match(/^\/api\/v1\/lifecycle\/keys\/([^/]+)\/versions$/);
  if (versions) return _demoVersions(versions[1]);

  // /api/v1/lifecycle/keys/:id/rotate  (POST)
  const rotateKey = path.match(/^\/api\/v1\/lifecycle\/keys\/([^/]+)\/rotate$/);
  if (rotateKey && method === "POST") {
    const k = _DEMO_KEYS.find(x => x.id === rotateKey[1]);
    if (k) { k.active_version_number++; k.total_versions++; k.rotation_count++; k.rotation_due_at = new Date(Date.now()+365*86400000).toISOString(); }
    return { success:true, key_id:rotateKey[1], new_version: k?.active_version_number };
  }

  // /api/v1/lifecycle/keys/:id/encrypt
  const encryptPath = path.match(/^\/api\/v1\/lifecycle\/keys\/([^/]+)\/encrypt$/);
  if (encryptPath && method === "POST") {
    const body = JSON.parse(opts.body || "{}");
    const k    = _DEMO_KEYS.find(x => x.id === encryptPath[1]);
    const envId = `env-demo-${Date.now().toString(36)}`;
    _demoEnvelopeStore[envId] = { plaintext: body.plaintext, key_alias: k?.name || "unknown", version_number: k?.active_version_number || 1, tenant_context: body.tenant_context };
    const ct = btoa(body.plaintext || "").slice(0, 32);
    return {
      envelope_id:   envId,
      key_alias:     k?.name,
      version_number:k?.active_version_number || 1,
      aws_mode:      "SIM",
      pqc_available: true,
      envelope: {
        version:         "v2-hybrid",
        combiner:        "XOR-then-AES-GCM",
        pqc_algo:        "ML-KEM-768",
        sign_algo:       "ML-DSA-65",
        classical_algo:  "AES-256-GCM",
        aws_mode:        "SIM",
        pqc_available:   true,
        tenant:          body.tenant_context || "demo-tenant-1",
        ciphertext:      ct + "aGVsbG8gd29ybGQgdGhpcyBpcyBkZW1v",
        mlkem_ct:        "mlkem768ct" + Math.random().toString(36).slice(2,18),
        mldsa_sig:       "mldsa65sig"  + Math.random().toString(36).slice(2,18),
        aws_wrapped_dk:  "awswrapped"  + Math.random().toString(36).slice(2,18),
      },
    };
  }

  // /api/v1/lifecycle/decrypt
  if (path === "/api/v1/lifecycle/decrypt" && method === "POST") {
    const body = JSON.parse(opts.body || "{}");
    const stored = _demoEnvelopeStore[body.envelope_id];
    if (!stored) throw new Error("Envelope not found. Encrypt something first in Demo Mode.");
    return { plaintext:stored.plaintext, key_alias:stored.key_alias, version_number:stored.version_number, tenant_context:stored.tenant_context };
  }

  // /api/v1/lifecycle/compliance
  if (path.startsWith("/api/v1/lifecycle/compliance")) return _DEMO_COMPLIANCE;

  // /api/v1/lifecycle/compliance/generate-report
  if (path === "/api/v1/lifecycle/compliance/generate-report" && method === "POST") {
    return { ..._DEMO_COMPLIANCE, generated_at: new Date().toISOString() };
  }

  // /api/v1/lifecycle/rotation-status
  if (path === "/api/v1/lifecycle/rotation-status") {
    const due = _DEMO_KEYS.filter(k => k.rotation_due_at && new Date(k.rotation_due_at) < Date.now()).length;
    return { running:true, interval_seconds:3600, next_fire_time:new Date(Date.now()+3600000).toISOString(), keys_due_rotation:due, total_keys:_DEMO_KEYS.length };
  }

  // /api/v1/lifecycle/rotate-now
  if (path === "/api/v1/lifecycle/rotate-now" && method === "POST") {
    const due = _DEMO_KEYS.filter(k => k.rotation_due_at && new Date(k.rotation_due_at) < Date.now());
    due.forEach(k => { k.active_version_number++; k.total_versions++; k.rotation_count++; k.rotation_due_at = new Date(Date.now()+365*86400000).toISOString(); });
    return { rotated: due.map(k => ({ key_id:k.id, key_alias:k.name, new_version:k.active_version_number })), skipped:[], errors:[] };
  }

  // /api/v1/keys/audit  (legacy audit endpoint)
  if (path.startsWith("/api/v1/keys/audit") || path.startsWith("/api/v1/compliance/audit")) {
    return _DEMO_AUDIT;
  }

  // /api/v1/providers/capability-matrix
  if (path === "/api/v1/providers/capability-matrix") return {
    assessed_at: new Date().toISOString(),
    providers: [
      { provider:"aws_kms",  mode:"SIM", pq_import_support:false, import_methods:["RSAES_OAEP_SHA_256","RSA_AES_KEY_WRAP_SHA_256"], transit_posture:"classical_only", notes:"RSA symmetric key import only; wrapping method not operator-selectable (§10.5.1)" },
      { provider:"azure_kv", mode:"SIM", pq_import_support:false, import_methods:["RSA-OAEP"], transit_posture:"classical_only", notes:"BYOK via RSA-OAEP only; no PQ import option (§10.5)" },
      { provider:"gcp_kms",  mode:"DOC", pq_import_support:true,  import_methods:["HPKE X-Wing","ML-KEM-768","ML-KEM-1024"], transit_posture:"pq_native", notes:"Preview; software protection level only; not exercised against live service (§10.5, §11.1)" },
    ],
  };

  throw new Error(`Demo: unhandled path ${path}`);
}

function toggleDemoMode() {
  DEMO_MODE = !DEMO_MODE;
  const btn    = document.getElementById("btn-demo-mode");
  const banner = document.getElementById("demo-banner");
  btn.classList.toggle("active", DEMO_MODE);
  banner.style.display = DEMO_MODE ? "flex" : "none";
  document.body.classList.toggle("demo-active", DEMO_MODE);
  if (DEMO_MODE) {
    toast("🎯 Demo Mode ON — all data is simulated", "success");
    loadDashboard();
  } else {
    toast("Demo Mode OFF — reconnecting to backend…", "info");
    loadDashboard();
  }
}

document.getElementById("btn-demo-mode").addEventListener("click", toggleDemoMode);

// ── Utility ───────────────────────────────────────────────────────────

async function apiFetch(path, opts = {}) {
  if (DEMO_MODE) return _demoFetch(path, opts);
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function fmt(ts) {
  if (!ts) return "–";
  return new Date(ts).toLocaleString("en-GB", { dateStyle:"short", timeStyle:"medium" });
}

function fmtShort(ts) {
  if (!ts) return "–";
  return new Date(ts).toLocaleString("en-GB", { dateStyle:"short", timeStyle:"short" });
}

function riskBadge(isQSafe, isHybrid) {
  if (isHybrid && isQSafe) return `<span class="badge badge-hybrid">HYBRID_READY / PQC_READY</span>`;
  if (isQSafe)             return `<span class="badge badge-pqc">PQC_READY</span>`;
  return `<span class="badge badge-vuln">QUANTUM_VULNERABLE</span>`;
}

function quantumBadge(tag) {
  const MAP = {
    HYBRID_READY:       `<span class="badge badge-hybrid">HYBRID_READY / PQC_READY</span>`,
    PQC_READY:          `<span class="badge badge-pqc">PQC_READY</span>`,
    QUANTUM_VULNERABLE: `<span class="badge badge-vuln">QUANTUM_VULNERABLE</span>`,
    NON_COMPLIANT:      `<span class="badge badge-noncomp">NON_COMPLIANT</span>`,
  };
  return MAP[tag] || `<span class="badge">${tag}</span>`;
}

function stateBadge(state) {
  const MAP = {
    ACTIVE:    "badge-active",
    RETIRED:   "badge-retired",
    REVOKED:   "badge-revoked",
    DESTROYED: "badge-destroyed",
  };
  return `<span class="badge ${MAP[state] || ""}">${state}</span>`;
}

function statusBadge(status) {
  return `<span class="badge ${status === "active" ? "badge-active" : "badge-revoked"}">${status}</span>`;
}

function providerBadge(prov) {
  const MAP = { aws_kms: "badge-live", azure_kv: "badge-live", gcp_kms: "badge-doc" };
  const labels = { aws_kms: "AWS KMS", azure_kv: "Azure KV", gcp_kms: "GCP KMS" };
  return `<span class="badge ${MAP[prov] || "badge-sim"}">${labels[prov] || prov}</span>`;
}

function toast(msg, type = "info") {
  const c   = document.getElementById("toast-container");
  const t   = document.createElement("div");
  const ico = type === "success" ? "✓" : type === "error" ? "✗" : "ℹ";
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${ico}</span> ${msg}`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Init ──────────────────────────────────────────────────────────────

loadDashboard();
setInterval(loadHealth, POLL);

