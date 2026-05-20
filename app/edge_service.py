from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib import error, request
from uuid import uuid4

from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import serialization
from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from app import audit, config, crypto_utils, integrity, storage
from app.models import (
    AuditEvent,
    AuditLogResponse,
    EncryptAndBackupResponse,
    HealthResponse,
    IdentityResponse,
    LocalStorageView,
    RecoverFromCloudResponse,
    RegisterNodeRequest,
    RegisterNodeResponse,
    RetrieveBackupRequest,
    RetrieveBackupResponse,
    StoreBackupRequest,
    StoreBackupResponse,
)

app = FastAPI(title="Secure Edge-Cloud Edge Service")


@app.get("/", response_class=RedirectResponse, include_in_schema=False)
def root() -> RedirectResponse:
    """Redirect the base edge URL to the browser demo page."""
    return RedirectResponse(url="/demo-page")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return a minimal health response for this edge node."""
    return HealthResponse(service="edge_service", node_id=EDGE_NODE_ID)


@app.get("/identity", response_model=IdentityResponse)
def identity() -> IdentityResponse:
    """Return the edge node identity and raw Ed25519 public key bytes in base64."""
    public_key = _load_public_key()
    public_key_b64 = _public_key_to_b64(public_key)
    return IdentityResponse(node_id=EDGE_NODE_ID, public_key_b64=public_key_b64)


@app.get("/demo-page", response_class=HTMLResponse)
def demo_page() -> HTMLResponse:
    """Render a small browser-based demo page for exercising the edge-cloud flow."""
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Edge Demo Page</title>
  <style>
    :root {{
      --bg: #f4f7fb;
      --panel: #ffffff;
      --panel-soft: #f8fafc;
      --border: #d9e2ec;
      --text: #17202a;
      --muted: #5f6f82;
      --accent: #1f6feb;
      --accent-dark: #164f9f;
      --success: #117a48;
      --danger: #b42318;
      --warning-bg: #fff4e5;
      --code-bg: #101828;
    }}

    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.45;
    }}

    header {{
      background: #ffffff;
      border-bottom: 1px solid var(--border);
      padding: 24px clamp(18px, 4vw, 42px);
    }}

    main {{
      padding: 24px clamp(18px, 4vw, 42px) 42px;
      max-width: 1280px;
      margin: 0 auto;
    }}

    h1 {{
      margin: 0 0 6px;
      font-size: 28px;
      font-weight: 700;
      letter-spacing: 0;
    }}

    h2 {{
      margin: 0 0 14px;
      font-size: 18px;
      font-weight: 700;
      letter-spacing: 0;
    }}

    h3 {{
      margin: 0;
      font-size: 14px;
      color: var(--muted);
      font-weight: 700;
      text-transform: uppercase;
    }}

    .subtitle {{
      margin: 0;
      color: var(--muted);
      font-size: 15px;
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }}

    .wide-grid {{
      display: grid;
      grid-template-columns: minmax(320px, 0.9fr) minmax(360px, 1.1fr);
      gap: 16px;
      align-items: start;
    }}

    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    }}

    .summary-card {{
      min-height: 112px;
    }}

    .summary-value {{
      margin-top: 10px;
      font-size: 28px;
      font-weight: 700;
    }}

    .summary-note {{
      margin-top: 4px;
      color: var(--muted);
      font-size: 14px;
    }}

    .section {{
      margin-top: 18px;
    }}

    .field-grid {{
      display: grid;
      gap: 10px;
    }}

    .field-row {{
      display: flex;
      justify-content: space-between;
      gap: 18px;
      padding: 10px 0;
      border-bottom: 1px solid #edf1f5;
    }}

    .field-row:last-child {{
      border-bottom: 0;
    }}

    .label {{
      color: var(--muted);
      font-size: 14px;
    }}

    .value {{
      font-weight: 700;
      text-align: right;
      overflow-wrap: anywhere;
    }}

    .pill {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 13px;
      font-weight: 700;
      background: #eef6ff;
      color: var(--accent-dark);
    }}

    .pill.success {{
      background: #eaf7ef;
      color: var(--success);
    }}

    .pill.failure {{
      background: #fdecec;
      color: var(--danger);
    }}

    textarea {{
      width: 100%;
      min-height: 150px;
      padding: 12px;
      border: 1px solid #b6c2cf;
      border-radius: 6px;
      resize: vertical;
      box-sizing: border-box;
      font: 15px/1.45 Arial, Helvetica, sans-serif;
      color: var(--text);
      background: #ffffff;
    }}

    .help-text {{
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 13px;
    }}

    button {{
      margin-right: 8px;
      margin-top: 10px;
      padding: 10px 14px;
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #ffffff;
      cursor: pointer;
      font: 700 14px Arial, Helvetica, sans-serif;
    }}

    button:hover {{
      background: var(--accent-dark);
      border-color: var(--accent-dark);
    }}

    button.secondary {{
      background: #ffffff;
      color: var(--accent);
    }}

    button.secondary:hover {{
      background: #eef6ff;
      color: var(--accent-dark);
    }}

    button.small {{
      margin: 8px 0 0;
      padding: 7px 10px;
      font-size: 13px;
    }}

    pre {{
      margin: 10px 0 0;
      white-space: pre-wrap;
      word-break: break-word;
      background: var(--code-bg);
      color: #e5e7eb;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font: 13px/1.45 Consolas, "Courier New", monospace;
    }}

    details {{
      margin-top: 12px;
      border-top: 1px solid #edf1f5;
      padding-top: 10px;
    }}

    summary {{
      cursor: pointer;
      color: var(--accent);
      font-weight: 700;
      font-size: 14px;
    }}

    .status {{
      margin: 18px 0;
      padding: 12px 14px;
      border-radius: 6px;
      background: #eaf7ef;
      color: #0f5132;
      border: 1px solid #badbcc;
      font-weight: 700;
    }}

    .status.error {{
      background: #fdecec;
      color: var(--danger);
      border-color: #f5c2c7;
    }}

    .event-list {{
      display: grid;
      gap: 8px;
    }}

    .event {{
      display: grid;
      grid-template-columns: 150px 90px 1fr 170px;
      gap: 10px;
      align-items: center;
      padding: 10px;
      border: 1px solid #edf1f5;
      border-radius: 6px;
      background: var(--panel-soft);
      font-size: 14px;
    }}

    .event-action {{
      font-weight: 700;
      overflow-wrap: anywhere;
    }}

    .event-detail, .event-time {{
      color: var(--muted);
      overflow-wrap: anywhere;
    }}

    .content-panel {{
      background: var(--panel-soft);
      border: 1px solid #edf1f5;
      border-radius: 6px;
      padding: 14px;
      min-height: 60px;
      overflow-wrap: anywhere;
    }}

    .structured-view {{
      display: grid;
      gap: 8px;
    }}

    .structured-row {{
      display: grid;
      grid-template-columns: 140px 1fr;
      gap: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid #e5ebf1;
    }}

    .structured-row:last-child {{
      border-bottom: 0;
      padding-bottom: 0;
    }}

    .empty {{
      color: var(--muted);
      font-style: italic;
    }}

    @media (max-width: 900px) {{
      .wide-grid {{
        grid-template-columns: 1fr;
      }}

      .event {{
        grid-template-columns: 1fr;
      }}

      .value {{
        text-align: left;
      }}

      .field-row {{
        flex-direction: column;
        gap: 4px;
      }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Secure Edge-Cloud Storage Demo</h1>
    <p class="subtitle">Edge node <strong>{EDGE_NODE_ID}</strong> connected to cloud service <strong>{_cloud_base_url()}</strong></p>
  </header>

  <main>
    <div id="status" class="status">Loading demo state...</div>

    <div class="grid">
      <div class="card summary-card">
        <h3>Edge Status</h3>
        <div id="edgeStatusSummary" class="summary-value">Loading</div>
        <div id="edgeStatusNote" class="summary-note"></div>
      </div>
      <div class="card summary-card">
        <h3>Cloud Status</h3>
        <div id="cloudStatusSummary" class="summary-value">Loading</div>
        <div id="cloudStatusNote" class="summary-note"></div>
      </div>
      <div class="card summary-card">
        <h3>Vault Version</h3>
        <div id="vaultSummary" class="summary-value">-</div>
        <div id="keySummary" class="summary-note">Local key: unknown</div>
      </div>
      <div class="card summary-card">
        <h3>Last Action</h3>
        <div id="lastActionSummary" class="summary-value">Ready</div>
        <div id="lastActionNote" class="summary-note">No action run yet.</div>
      </div>
    </div>

    <div class="wide-grid section">
      <div class="card">
        <h2>Plaintext Input</h2>
        <textarea id="payloadInput">hello from browser demo</textarea>
        <p class="help-text">Enter plain text naturally. If the input is a valid JSON object, it will be sent as that object; otherwise it will be sent as {{ "message": "your text" }}.</p>
        <div>
          <button id="encryptButton">Encrypt and Backup</button>
          <button id="recoverButton" class="secondary">Recover from Cloud</button>
          <button id="refreshButton" class="secondary">Refresh Status</button>
        </div>
      </div>

      <div class="card">
        <h2>Recovered Content</h2>
        <div id="recoveredView" class="content-panel empty">No recovery run yet.</div>
        <details>
          <summary>Show raw JSON</summary>
          <pre id="recoveredRaw">null</pre>
        </details>
      </div>
    </div>

    <div class="grid section">
      <div class="card">
        <h2>Edge Identity</h2>
        <div id="identityView" class="field-grid"></div>
        <details>
          <summary>Show raw JSON</summary>
          <pre id="edgeIdentityRaw"></pre>
        </details>
      </div>

      <div class="card">
        <h2>Local Storage State</h2>
        <div id="localStorageView" class="field-grid"></div>
        <details>
          <summary>Show raw JSON</summary>
          <pre id="localStorageRaw"></pre>
        </details>
      </div>

      <div class="card">
        <h2>Service Health</h2>
        <div id="healthView" class="field-grid"></div>
        <details>
          <summary>Show raw JSON</summary>
          <pre id="healthRaw"></pre>
        </details>
      </div>
    </div>

    <div class="grid section">
      <div class="card">
        <h2>Edge Audit Log</h2>
        <div id="edgeAuditLogView" class="event-list"></div>
        <details>
          <summary>Show raw JSON</summary>
          <pre id="edgeAuditLogRaw"></pre>
        </details>
      </div>

      <div class="card">
        <h2>Cloud Access Log</h2>
        <div id="cloudAccessLogView" class="event-list"></div>
        <details>
          <summary>Show raw JSON</summary>
          <pre id="cloudAccessLogRaw"></pre>
        </details>
      </div>
    </div>
  </main>

  <script>
    const cloudBaseUrl = "{_cloud_base_url()}";
    let lastRecoveredPlaintext = null;

    function formatJson(value) {{
      return JSON.stringify(value, null, 2);
    }}

    function setBlock(id, value) {{
      document.getElementById(id).textContent = typeof value === "string" ? value : formatJson(value);
    }}

    function setStatus(message, isError = false) {{
      const status = document.getElementById("status");
      status.textContent = message;
      status.classList.toggle("error", isError);
    }}

    function text(value, fallback = "-") {{
      if (value === null || value === undefined || value === "") {{
        return fallback;
      }}
      return String(value);
    }}

    function shorten(value, head = 12, tail = 8) {{
      const raw = text(value, "");
      if (!raw) {{
        return "-";
      }}
      if (raw.length <= head + tail + 3) {{
        return raw;
      }}
      return raw.slice(0, head) + "..." + raw.slice(-tail);
    }}

    function formatTime(value) {{
      if (!value) {{
        return "-";
      }}
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) {{
        return text(value);
      }}
      return date.toLocaleString();
    }}

    function fieldRow(label, value) {{
      return '<div class="field-row"><span class="label">' + escapeHtml(label) + '</span><span class="value">' + escapeHtml(text(value)) + '</span></div>';
    }}

    function escapeHtml(value) {{
      return text(value, "").replace(/[&<>"']/g, (char) => ({{
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      }}[char]));
    }}

    function setFields(id, rows) {{
      document.getElementById(id).innerHTML = rows.map(([label, value]) => fieldRow(label, value)).join("");
    }}

    async function fetchJson(url, options) {{
      const response = await fetch(url, options);
      let data;
      try {{
        data = await response.json();
      }} catch (err) {{
        data = {{ detail: "Non-JSON response" }};
      }}
      if (!response.ok) {{
        const message = data && data.detail ? data.detail : response.statusText;
        throw new Error(url + " -> " + response.status + " " + message);
      }}
      return data;
    }}

    function buildPayload() {{
      const raw = document.getElementById("payloadInput").value.trim();
      if (!raw) {{
        return {{ message: "" }};
      }}

      try {{
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {{
          return parsed;
        }}
        return {{ message: raw }};
      }} catch (err) {{
        return {{ message: raw }};
      }}
    }}

    function renderStatusCards(edgeHealth, cloudHealth, localStorage) {{
      document.getElementById("edgeStatusSummary").innerHTML = '<span class="pill success">' + escapeHtml((edgeHealth.status || "unknown").toUpperCase()) + '</span>';
      document.getElementById("edgeStatusNote").textContent = "Edge node: " + text(edgeHealth.node_id);
      document.getElementById("cloudStatusSummary").innerHTML = '<span class="pill success">' + escapeHtml((cloudHealth.status || "unknown").toUpperCase()) + '</span>';
      document.getElementById("cloudStatusNote").textContent = "Cloud node: " + text(cloudHealth.node_id);
      document.getElementById("vaultSummary").textContent = text(localStorage.vault_version, "No vault");
      document.getElementById("keySummary").textContent = "Local key: " + (localStorage.has_local_key ? "Present" : "Missing");
    }}

    function renderIdentity(identity) {{
      setFields("identityView", [
        ["Node ID", identity.node_id],
        ["Public key", shorten(identity.public_key_b64)],
      ]);
      setBlock("edgeIdentityRaw", identity);
    }}

    function renderLocalStorage(localStorage) {{
      setFields("localStorageView", [
        ["Vault version", localStorage.vault_version ?? "No local vault"],
        ["Has local key", localStorage.has_local_key ? "yes" : "no"],
        ["Integrity hash", shorten(localStorage.integrity_hash, 16, 10)],
        ["Ciphertext", localStorage.ciphertext_b64 ? shorten(localStorage.ciphertext_b64, 16, 10) : "not stored"],
      ]);
      setBlock("localStorageRaw", localStorage);
    }}

    function renderHealth(edgeHealth, cloudHealth) {{
      setFields("healthView", [
        ["Edge status", edgeHealth.status || "unknown"],
        ["Edge service", edgeHealth.service],
        ["Edge node", edgeHealth.node_id],
        ["Cloud status", cloudHealth.status || "unknown"],
        ["Cloud service", cloudHealth.service],
        ["Cloud node", cloudHealth.node_id],
      ]);
      setBlock("healthRaw", {{ edge: edgeHealth, cloud: cloudHealth }});
    }}

    function detailSummary(details) {{
      if (!details || typeof details !== "object") {{
        return "";
      }}
      if (details.vault_version !== undefined) {{
        return "vault v" + details.vault_version;
      }}
      if (details.request_reason !== undefined) {{
        return text(details.request_reason);
      }}
      if (details.reason !== undefined) {{
        return text(details.reason);
      }}
      if (details.result !== undefined) {{
        return text(details.result);
      }}
      if (details.message !== undefined) {{
        return text(details.message);
      }}
      return "";
    }}

    function renderEvents(targetId, log) {{
      const entries = Array.isArray(log.entries) ? log.entries.slice(-8).reverse() : [];
      const target = document.getElementById(targetId);
      if (entries.length === 0) {{
        target.innerHTML = '<div class="empty">No events recorded.</div>';
        return;
      }}
      target.innerHTML = entries.map((entry) => {{
        const statusClass = entry.status === "success" ? "success" : "failure";
        return '<div class="event">'
          + '<div class="event-action">' + escapeHtml(entry.action) + '</div>'
          + '<div><span class="pill ' + statusClass + '">' + escapeHtml(entry.status) + '</span></div>'
          + '<div class="event-detail">' + escapeHtml(detailSummary(entry.details)) + '</div>'
          + '<div class="event-time">' + escapeHtml(formatTime(entry.timestamp)) + '</div>'
          + '</div>';
      }}).join("");
    }}

    function renderRecovered(value) {{
      lastRecoveredPlaintext = value;
      const target = document.getElementById("recoveredView");
      if (!value || typeof value !== "object") {{
        target.className = "content-panel empty";
        target.textContent = "No recovery run yet.";
        setBlock("recoveredRaw", value);
        return;
      }}

      const keys = Object.keys(value);
      const messageKey = keys.find((key) => ["message", "text", "content"].includes(key));
      target.className = "content-panel";
      if (keys.length === 1 && messageKey) {{
        target.textContent = text(value[messageKey]);
      }} else {{
        target.innerHTML = '<div class="structured-view">' + keys.map((key) => {{
          const displayValue = typeof value[key] === "object" ? formatJson(value[key]) : text(value[key]);
          return '<div class="structured-row"><strong>' + escapeHtml(key) + '</strong><span>' + escapeHtml(displayValue) + '</span></div>';
        }}).join("") + '</div>';
      }}
      setBlock("recoveredRaw", value);
    }}

    async function refreshSections() {{
      const [edgeHealth, cloudHealth, edgeIdentity, localStorage, edgeAuditLog, cloudAccessLog] = await Promise.all([
        fetchJson("/health"),
        fetchJson(cloudBaseUrl + "/health"),
        fetchJson("/identity"),
        fetchJson("/local-storage"),
        fetchJson("/audit-log"),
        fetchJson(cloudBaseUrl + "/access-log"),
      ]);

      renderStatusCards(edgeHealth, cloudHealth, localStorage);
      renderIdentity(edgeIdentity);
      renderLocalStorage(localStorage);
      renderHealth(edgeHealth, cloudHealth);
      renderEvents("edgeAuditLogView", edgeAuditLog);
      renderEvents("cloudAccessLogView", cloudAccessLog);
      setBlock("edgeAuditLogRaw", edgeAuditLog);
      setBlock("cloudAccessLogRaw", cloudAccessLog);
      if (lastRecoveredPlaintext !== null) {{
        renderRecovered(lastRecoveredPlaintext);
      }}
    }}

    async function encryptAndBackup() {{
      setStatus("Encrypting locally and backing up to cloud...");
      const payload = buildPayload();
      const result = await fetchJson("/encrypt-and-backup", {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify(payload),
      }});
      await refreshSections();
      setStatus("Encrypt and backup completed.");
      document.getElementById("lastActionSummary").textContent = "Backup completed";
      document.getElementById("lastActionNote").textContent = "Vault version " + text(result.vault_version);
      return result;
    }}

    async function recoverFromCloud() {{
      setStatus("Recovering backup from cloud...");
      const result = await fetchJson("/recover-from-cloud", {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({{ request_reason: "recovery" }}),
      }});
      renderRecovered(result.recovered_plaintext ?? null);
      await refreshSections();
      setStatus("Recovery completed.");
      document.getElementById("lastActionSummary").textContent = "Recovery completed";
      document.getElementById("lastActionNote").textContent = "Vault version " + text(result.vault_version);
      return result;
    }}

    async function runAction(action) {{
      try {{
        await action();
      }} catch (err) {{
        setStatus(err.message || "Request failed", true);
      }}
    }}

    document.getElementById("encryptButton").addEventListener("click", () => runAction(encryptAndBackup));
    document.getElementById("recoverButton").addEventListener("click", () => runAction(recoverFromCloud));
    document.getElementById("refreshButton").addEventListener("click", () => runAction(refreshSections));

    runAction(async () => {{
      await refreshSections();
      renderRecovered(null);
      setStatus("Demo page ready.");
    }});
  </script>
</body>
</html>"""
    )


@app.post("/encrypt-and-backup", response_model=EncryptAndBackupResponse)
def encrypt_and_backup(plaintext: dict[str, Any] = Body(...)) -> EncryptAndBackupResponse:
    """Encrypt a JSON payload locally, store it, and upload only ciphertext to the cloud."""
    if not plaintext:
        raise HTTPException(status_code=400, detail="Plaintext JSON object is required")

    plaintext_bytes = _serialize_plaintext(plaintext)
    ciphertext = crypto_utils.encrypt_data(_load_fernet_key(), plaintext_bytes)
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    vault_version = _next_vault_version()
    integrity_hash = integrity.compute_sha256_bytes(ciphertext)

    storage.save_local_vault_ciphertext(EDGE_NODE_ID, ciphertext)
    _update_local_metadata(
        {
            "node_id": EDGE_NODE_ID,
            "vault_version": vault_version,
            "ciphertext_b64": ciphertext_b64,
            "integrity_hash": integrity_hash,
            "updated_at": _utc_now().isoformat(),
        }
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=EDGE_NODE_ID,
        action="encrypt_local",
        status="success",
        details={"vault_version": vault_version},
    )

    cloud_response = _store_backup_in_cloud(
        vault_version=vault_version,
        ciphertext_b64=ciphertext_b64,
        integrity_hash=integrity_hash,
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=config.CLOUD,
        action="store_backup",
        status="success",
        details={"vault_version": cloud_response.vault_version},
    )
    return EncryptAndBackupResponse(
        success=True,
        node_id=EDGE_NODE_ID,
        vault_version=cloud_response.vault_version,
        message="Local encryption complete and cloud backup stored",
    )


@app.post("/recover-from-cloud", response_model=RecoverFromCloudResponse)
def recover_from_cloud(request_body: dict[str, Any] | None = Body(None)) -> RecoverFromCloudResponse:
    """Retrieve ciphertext from the cloud, verify integrity, and decrypt locally."""
    safe_request_body = request_body or {}
    request_reason = safe_request_body.get("request_reason", "recovery")
    if not isinstance(request_reason, str):
        raise HTTPException(status_code=400, detail="request_reason must be a string")

    backup = _retrieve_backup_from_cloud(request_reason=request_reason)
    if not backup.found or backup.ciphertext_b64 is None or backup.integrity_hash is None:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="retrieve_backup",
            status="failure",
            details={"reason": "backup not found", "request_reason": request_reason},
        )
        raise HTTPException(status_code=404, detail="Backup not found in cloud")

    try:
        ciphertext = base64.b64decode(backup.ciphertext_b64, validate=True)
    except ValueError as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="integrity_mismatch",
            status="failure",
            details={"reason": "cloud returned invalid base64 ciphertext"},
        )
        raise HTTPException(status_code=502, detail="Cloud returned invalid ciphertext") from exc

    actual_hash = integrity.compute_sha256_bytes(ciphertext)
    if not integrity.hashes_match(backup.integrity_hash, actual_hash):
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="integrity_mismatch",
            status="failure",
            details={
                "expected_hash": backup.integrity_hash,
                "actual_hash": actual_hash,
                "vault_version": backup.vault_version,
            },
        )
        raise HTTPException(status_code=409, detail="Integrity verification failed")

    try:
        plaintext_bytes = crypto_utils.decrypt_data(_load_fernet_key(), ciphertext)
    except InvalidToken as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=EDGE_NODE_ID,
            action="request_denied",
            status="failure",
            details={
                "reason": "local decryption failed",
                "vault_version": backup.vault_version,
            },
        )
        raise HTTPException(status_code=422, detail="Unable to decrypt recovered backup") from exc

    try:
        plaintext = json.loads(plaintext_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=EDGE_NODE_ID,
            action="request_denied",
            status="failure",
            details={
                "reason": "recovered plaintext is not valid JSON",
                "vault_version": backup.vault_version,
            },
        )
        raise HTTPException(status_code=422, detail="Recovered plaintext is not valid JSON") from exc

    storage.save_local_vault_ciphertext(EDGE_NODE_ID, ciphertext)
    _update_local_metadata(
        {
            "node_id": EDGE_NODE_ID,
            "vault_version": backup.vault_version,
            "ciphertext_b64": backup.ciphertext_b64,
            "integrity_hash": backup.integrity_hash,
            "updated_at": _utc_now().isoformat(),
        }
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=config.CLOUD,
        action="retrieve_backup",
        status="success",
        details={"vault_version": backup.vault_version, "request_reason": request_reason},
    )
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=EDGE_NODE_ID,
        action="decrypt_local",
        status="success",
        details={"vault_version": backup.vault_version},
    )
    return RecoverFromCloudResponse(
        success=True,
        node_id=EDGE_NODE_ID,
        vault_version=backup.vault_version,
        recovered_plaintext=plaintext,
        message="Backup recovered and decrypted locally",
    )


@app.get("/local-storage", response_model=LocalStorageView)
def local_storage() -> LocalStorageView:
    """Return the locally cached ciphertext metadata for this edge node."""
    ciphertext = storage.load_local_vault_ciphertext(EDGE_NODE_ID)
    metadata = storage.load_local_vault_metadata(EDGE_NODE_ID) or {}

    ciphertext_b64 = metadata.get("ciphertext_b64")
    if ciphertext_b64 is None and ciphertext is not None:
        ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")

    return LocalStorageView(
        node_id=EDGE_NODE_ID,
        vault_version=metadata.get("vault_version"),
        ciphertext_b64=ciphertext_b64,
        integrity_hash=metadata.get("integrity_hash"),
        has_local_key=config.get_fernet_key_path(EDGE_NODE_ID).exists(),
    )


@app.get("/audit-log", response_model=AuditLogResponse)
def audit_log() -> AuditLogResponse:
    """Return the edge-node audit log entries."""
    return audit.read_audit_log(EDGE_NODE_ID)


def _get_edge_node_id() -> str:
    """Resolve the edge node identity from environment or default to edgeA."""
    candidate = os.getenv("EDGE_NODE_ID")
    if candidate:
        try:
            validated = config.validate_node_id(candidate)
        except ValueError as exc:
            raise RuntimeError(f"Invalid EDGE_NODE_ID: {candidate}") from exc
        if validated not in config.EDGE_NODE_IDS:
            raise RuntimeError("EDGE_NODE_ID must refer to an edge node")
        return validated

    port_text = os.getenv("PORT") or os.getenv("UVICORN_PORT")
    if port_text and port_text.isdigit():
        port = int(port_text)
        for node_id in config.EDGE_NODE_IDS:
            if config.get_node_port(node_id) == port:
                return node_id

    return config.EDGE_A


def _utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


def _cloud_base_url() -> str:
    """Build the local cloud service base URL from shared configuration."""
    return f"http://127.0.0.1:{config.get_node_port(config.CLOUD)}"


def _serialize_plaintext(payload: dict[str, Any]) -> bytes:
    """Serialize plaintext JSON deterministically before local encryption."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _serialize_signed_payload(payload: dict[str, object]) -> bytes:
    """Serialize signed request fields in the same canonical format as the cloud service."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_private_key():
    """Load the edge node's Ed25519 private key from disk."""
    try:
        return crypto_utils.load_private_key_from_file(config.get_private_key_path(EDGE_NODE_ID))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Edge private key not found") from exc


def _load_public_key():
    """Load the edge node's Ed25519 public key from disk."""
    try:
        return crypto_utils.load_public_key_from_file(config.get_public_key_path(EDGE_NODE_ID))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Edge public key not found") from exc


def _load_fernet_key() -> bytes:
    """Load the edge node's local Fernet key used for vault encryption."""
    try:
        return crypto_utils.load_fernet_key_from_file(config.get_fernet_key_path(EDGE_NODE_ID))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail="Local encryption key not found") from exc


def _public_key_to_b64(public_key: Any) -> str:
    """Convert the PEM-loaded Ed25519 public key into raw base64 bytes for API use."""
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_key_bytes).decode("ascii")


def _next_vault_version() -> int:
    """Return the next local vault version based on stored metadata."""
    metadata = _load_local_metadata()
    current_version = metadata.get("vault_version")
    if isinstance(current_version, int) and current_version >= 1:
        return current_version + 1
    return 1


def _nonce_candidates() -> list[dict]:
    """Load and prune cached nonces for this edge node."""
    entries = storage.load_nonce_cache(EDGE_NODE_ID)
    pruned_entries = _prune_nonce_entries(entries)
    if pruned_entries != entries:
        storage.save_nonce_cache(EDGE_NODE_ID, pruned_entries)
    return pruned_entries


def _generate_nonce() -> str:
    """Generate a nonce that is not already present in the shared nonce cache."""
    existing_nonces = {entry.get("nonce") for entry in _nonce_candidates()}
    for _ in range(10):
        nonce = uuid4().hex
        if nonce not in existing_nonces:
            return nonce
    raise HTTPException(status_code=500, detail="Unable to generate a unique nonce")


def _prune_nonce_entries(entries: list[dict]) -> list[dict]:
    """Remove expired nonce entries using the shared replay window."""
    cutoff = _utc_now() - timedelta(seconds=config.NONCE_TTL_SECONDS)
    valid_entries: list[dict] = []

    for entry in entries:
        timestamp_text = entry.get("timestamp")
        if not isinstance(timestamp_text, str):
            continue
        try:
            entry_timestamp = datetime.fromisoformat(timestamp_text)
        except ValueError:
            continue
        if entry_timestamp >= cutoff:
            valid_entries.append(entry)

    return valid_entries[-config.MAX_NONCE_CACHE_ENTRIES :]


def _sign_payload(message: bytes) -> str:
    """Sign a canonical payload and verify it against the local public key before use."""
    private_key = _load_private_key()
    signature = crypto_utils.sign_message(private_key, message)
    if not crypto_utils.verify_signature(_load_public_key(), message, signature):
        raise HTTPException(status_code=500, detail="Local signature verification failed")
    return base64.b64encode(signature).decode("ascii")


def _ensure_cloud_registration(force: bool = False) -> RegisterNodeResponse:
    """Register this edge node with the cloud when local state says it is needed."""
    if not force and _is_cloud_registration_known():
        return RegisterNodeResponse(
            registered=True,
            node_id=EDGE_NODE_ID,
            message="Node already registered locally",
        )

    timestamp = _utc_now()
    public_key_b64 = identity().public_key_b64
    nonce = _generate_nonce()
    payload = {
        "action": "register-node",
        "node_id": EDGE_NODE_ID,
        "public_key_b64": public_key_b64,
        "timestamp": timestamp.isoformat(),
        "nonce": nonce,
    }
    signed_request = RegisterNodeRequest(
        node_id=EDGE_NODE_ID,
        public_key_b64=public_key_b64,
        signature_b64=_sign_payload(_serialize_signed_payload(payload)),
        timestamp=timestamp,
        nonce=nonce,
    )
    response = _post_to_cloud("/register-node", signed_request.model_dump(mode="json"))
    registration = RegisterNodeResponse.model_validate(response)
    _mark_cloud_registration_state(True)
    _append_audit_event(
        actor=EDGE_NODE_ID,
        target=config.CLOUD,
        action="register_node",
        status="success",
        details={"message": registration.message},
    )
    return registration


def _store_backup_in_cloud(
    vault_version: int,
    ciphertext_b64: str,
    integrity_hash: str,
) -> StoreBackupResponse:
    """Send locally encrypted ciphertext to the cloud using the shared signed format."""
    _ensure_cloud_registration()
    timestamp = _utc_now()
    nonce = _generate_nonce()
    payload = {
        "action": "store-backup",
        "node_id": EDGE_NODE_ID,
        "vault_version": vault_version,
        "ciphertext_b64": ciphertext_b64,
        "integrity_hash": integrity_hash,
        "timestamp": timestamp.isoformat(),
        "nonce": nonce,
    }
    signed_request = StoreBackupRequest(
        node_id=EDGE_NODE_ID,
        vault_version=vault_version,
        ciphertext_b64=ciphertext_b64,
        integrity_hash=integrity_hash,
        signature_b64=_sign_payload(_serialize_signed_payload(payload)),
        timestamp=timestamp,
        nonce=nonce,
    )
    try:
        response = _post_to_cloud("/store-backup", signed_request.model_dump(mode="json"))
    except HTTPException as exc:
        if _is_invalid_signature_error(exc):
            _mark_cloud_registration_state(False)
            _raise_cloud_key_mismatch()
        if not _is_not_registered_error(exc):
            raise
        _mark_cloud_registration_state(False)
        _ensure_cloud_registration(force=True)
        response = _post_to_cloud("/store-backup", signed_request.model_dump(mode="json"))
    return StoreBackupResponse.model_validate(response)


def _retrieve_backup_from_cloud(request_reason: str) -> RetrieveBackupResponse:
    """Request the stored ciphertext from the cloud using the shared signed format."""
    _ensure_cloud_registration()
    timestamp = _utc_now()
    nonce = _generate_nonce()
    payload = {
        "action": "retrieve-backup",
        "node_id": EDGE_NODE_ID,
        "request_reason": request_reason,
        "timestamp": timestamp.isoformat(),
        "nonce": nonce,
    }
    signed_request = RetrieveBackupRequest(
        node_id=EDGE_NODE_ID,
        request_reason=request_reason,
        signature_b64=_sign_payload(_serialize_signed_payload(payload)),
        timestamp=timestamp,
        nonce=nonce,
    )
    try:
        response = _post_to_cloud("/retrieve-backup", signed_request.model_dump(mode="json"))
    except HTTPException as exc:
        if _is_invalid_signature_error(exc):
            _mark_cloud_registration_state(False)
            _raise_cloud_key_mismatch()
        if not _is_not_registered_error(exc):
            raise
        _mark_cloud_registration_state(False)
        _ensure_cloud_registration(force=True)
        response = _post_to_cloud("/retrieve-backup", signed_request.model_dump(mode="json"))
    return RetrieveBackupResponse.model_validate(response)


def _post_to_cloud(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST a JSON payload to the cloud service and return the decoded JSON response."""
    body = json.dumps(payload).encode("utf-8")
    http_request = request.Request(
        url=f"{_cloud_base_url()}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=10) as response:
            response_body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        detail = _extract_error_detail(exc)
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"path": path, "status_code": exc.code, "detail": detail},
        )
        raise HTTPException(status_code=exc.code, detail=detail) from exc
    except error.URLError as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"path": path, "reason": "cloud unavailable"},
        )
        raise HTTPException(status_code=503, detail="Cloud service unavailable") from exc

    try:
        return json.loads(response_body)
    except json.JSONDecodeError as exc:
        _append_audit_event(
            actor=EDGE_NODE_ID,
            target=config.CLOUD,
            action="request_denied",
            status="failure",
            details={"path": path, "reason": "cloud returned invalid JSON"},
        )
        raise HTTPException(status_code=502, detail="Cloud returned invalid JSON") from exc


def _extract_error_detail(exc: error.HTTPError) -> str:
    """Extract a FastAPI-style error detail from an upstream HTTP error response."""
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "Cloud request failed"

    detail = payload.get("detail")
    if isinstance(detail, str):
        return detail
    return "Cloud request failed"


def _load_local_metadata() -> dict[str, Any]:
    """Load this edge node's local metadata as a mutable dictionary."""
    return storage.load_local_vault_metadata(EDGE_NODE_ID) or {}


def _update_local_metadata(updates: dict[str, Any]) -> None:
    """Merge new values into the existing local metadata record."""
    vault_path = config.get_local_vault_path(EDGE_NODE_ID)
    metadata_path = vault_path.with_name(f"{vault_path.stem}_metadata.json")
    with storage.file_lock(metadata_path):
        metadata = _load_local_metadata()
        metadata.update(updates)
        storage.save_local_vault_metadata(EDGE_NODE_ID, metadata)


def _is_cloud_registration_known() -> bool:
    """Return whether local state says this edge is already registered in the cloud."""
    return _load_local_metadata().get("cloud_registered") is True


def _mark_cloud_registration_state(registered: bool) -> None:
    """Persist the local cloud-registration state for this edge node."""
    updates: dict[str, Any] = {"cloud_registered": registered}
    if registered:
        updates["cloud_registered_at"] = _utc_now().isoformat()
    _update_local_metadata(updates)


def _is_not_registered_error(exc: HTTPException) -> bool:
    """Return whether the cloud rejected the request because the node is not registered."""
    return exc.status_code == 403 and exc.detail == "Node is not registered"


def _is_invalid_signature_error(exc: HTTPException) -> bool:
    """Return whether the cloud rejected the request because keys no longer match."""
    return exc.status_code == 401 and exc.detail == "Invalid signature"


def _raise_cloud_key_mismatch() -> None:
    """Raise a clear error for stale local registration after a cloud signature failure."""
    raise HTTPException(
        status_code=409,
        detail="Cloud registration key mismatch; local cloud_registered state was cleared",
    )


def _append_audit_event(
    actor: str,
    target: str,
    action: str,
    status: str,
    details: dict[str, object],
) -> None:
    """Append an audit event to this edge node's log."""
    audit.append_audit_event(
        EDGE_NODE_ID,
        AuditEvent(
            event_id=str(uuid4()),
            actor=actor,
            target=target,
            action=action,
            status=status,
            timestamp=_utc_now(),
            details=details,
        ),
    )


EDGE_NODE_ID = _get_edge_node_id()
