const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const state = { selectedJob: null };

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
  return body;
}

let toastTimer;
function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("show"), 3500);
}

function metric(value, label) {
  const node = element("div", "metric");
  node.append(element("b", "", String(value)), element("span", "", label));
  return node;
}

async function loadDashboard(payload) {
  const data = payload || await api("/api/dashboard");
  const container = $("#metrics");
  container.replaceChildren(
    metric(data.devices || 0, "Geräte"),
    metric(data.events || 0, "Ereignisse"),
    metric(data.open_observations || 0, "Offene Beobachtungen"),
    metric(data.running_jobs || 0, "Aktive Jobs"),
    metric(data.monitors || 0, "Monitore"),
    metric(data.generated_tools || 0, "Analyzer-Versionen"),
    metric(data.filters || 0, "Filter-Versionen"),
    metric(data.recipes || 0, "Recipes"),
    metric(data.firewall_proposals || 0, "Firewall-Vorschläge"),
    metric(data.incidents || 0, "Incidents"),
    metric(data.sensor_records || 0, "Sensor-Records"),
    metric(data.knowledge_documents || 0, "Wissensdokumente")
  );
  $("#network-state").textContent = data.open_observations ? "Prüfung empfohlen" : "Ruhig und bereit";
}

async function loadJobs() {
  const rows = await api("/api/jobs?limit=30");
  const list = $("#jobs"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Noch keine Jobs."));
  rows.forEach(row => {
    const item = element("div", "item");
    const head = element("div", "item-head");
    head.append(element("b", "", row.kind), element("span", `pill ${row.status}`, row.status));
    item.append(head, element("small", "", `${row.id} · ${row.elapsed_ms ?? "…"} ms`));
    item.addEventListener("click", () => showJob(row.id));
    list.append(item);
  });
}

async function showJob(id) {
  state.selectedJob = id;
  const row = await api(`/api/jobs/${encodeURIComponent(id)}`);
  $("#job-output").textContent = JSON.stringify(row, null, 2);
}

async function submitJob(path, body) {
  const job = await api(path, { method: "POST", body: JSON.stringify(body) });
  state.selectedJob = job.id;
  toast(`Job ${job.id} wurde eingereiht.`);
  await loadJobs();
  let attempts = 0;
  const poll = async () => {
    const current = await api(`/api/jobs/${encodeURIComponent(job.id)}`);
    $("#job-output").textContent = JSON.stringify(current, null, 2);
    if (["queued", "running"].includes(current.status) && attempts++ < 120) setTimeout(poll, 1000);
    else { loadAll(); if (current.status === "failed") toast(current.error || "Job fehlgeschlagen"); }
  };
  poll();
}

async function loadInterfaces() {
  const rows = await api("/api/capture/interfaces");
  const select = $("#capture-interface"); select.replaceChildren();
  rows.forEach(row => { const option = element("option", "", `${row.id} · ${row.label}`); option.value = row.id; select.append(option); });
  const wlan = rows.find(row => /\(WLAN\)$/.test(row.label)); if (wlan) select.value = wlan.id;
}

async function loadCaptures() {
  const rows = await api("/api/captures"); const list = $("#captures"); list.replaceChildren();
  rows.forEach(row => {
    const item = element("div", "item"); const actions = element("div", "item-head");
    item.append(element("b", "", row.name), element("small", "", `${(row.bytes / 1024).toFixed(1)} KiB · ${row.retention_state || "nicht indexiert"} · ${row.path}`));
    if (row.id && row.retention_state !== "incident_locked") {
      const locked = row.retention_state === "manually_locked";
      const button = element("button", "ghost", locked ? "Rolling erlauben" : "Manuell schützen");
      button.addEventListener("click", async event => { event.stopPropagation(); try { await api(`/api/captures/${row.id}/retention`, {method:"PATCH", body:JSON.stringify({state:locked ? "rolling" : "manually_locked", reason:locked ? null : "Manuell in der UI geschützt"})}); loadCaptures(); } catch(err) { toast(err.message); } });
      actions.append(button); item.append(actions);
    }
    item.addEventListener("click", () => { $("#pcap-path").value = row.path; }); list.append(item);
  });
}

async function loadSensors() {
  const [sources, records] = await Promise.all([api("/api/sensors/sources"), api("/api/sensors/records?limit=25")]);
  const sourceList = $("#sensor-sources"), recordList = $("#sensor-records"); sourceList.replaceChildren(); recordList.replaceChildren();
  if (!sources.length) sourceList.append(element("p", "muted", "Noch keine Sensorquelle registriert."));
  sources.forEach(row => {
    const item = element("div", "item"), head = element("div", "item-head"), actions = element("div", "item-head");
    head.append(element("b", "", row.name), element("span", `pill ${row.enabled ? "completed" : ""}`, row.enabled ? "aktiv" : "pausiert"));
    const ingest = element("button", "ghost", "Jetzt einlesen"), toggle = element("button", "ghost", row.enabled ? "Pausieren" : "Aktivieren"), monitor = element("button", "ghost", "60s-Monitor");
    ingest.disabled = !row.enabled;
    ingest.addEventListener("click", event => { event.stopPropagation(); submitJob(`/api/sensors/sources/${row.id}/ingest`, {max_records:10000,reset_checkpoint:false}).catch(err => toast(err.message)); });
    toggle.addEventListener("click", async event => { event.stopPropagation(); try { await api(`/api/sensors/sources/${row.id}`, {method:"PATCH",body:JSON.stringify({enabled:!row.enabled})}); loadSensors(); } catch(err) { toast(err.message); } });
    monitor.addEventListener("click", async event => { event.stopPropagation(); try { await api("/api/monitors", {method:"POST",body:JSON.stringify({name:`${row.name} einlesen`,kind:"sensor_ingest",interval_seconds:60,config:{source_id:row.id,max_records:10000}})}); toast("Sensor-Monitor angelegt."); loadMonitors(); } catch(err) { toast(err.message); } });
    actions.append(ingest, toggle, monitor); item.append(head, element("small", "", `${row.kind} · ${row.records} Records / ${row.alerts} Alerts · Checkpoint ${row.checkpoint_bytes}/${row.last_size} Bytes`), element("small", "", row.path), actions); sourceList.append(item);
  });
  if (!records.length) recordList.append(element("p", "muted", "Noch keine Records importiert."));
  records.forEach(row => { const item = element("div", "item"), head = element("div", "item-head"); head.append(element("b", "", row.signature || row.sensor_event_type), element("span", `pill ${row.severity}`, row.severity)); item.append(head, element("small", "", `${row.ts} · ${row.src_ip || "–"}:${row.src_port || "–"} → ${row.dst_ip || "–"}:${row.dst_port || "–"}`), element("small", "", `${row.category || row.app_proto || row.proto || "Metadaten"} · ${row.id}`)); item.addEventListener("click", () => { $("#job-output").textContent = JSON.stringify(row, null, 2); $("[data-panel='observe']").click(); }); recordList.append(item); });
}

async function loadObservations() {
  const rows = await api("/api/observations?limit=50"); const list = $("#observations"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Keine Beobachtungen."));
  rows.forEach(row => { const item = element("div", "item"); const head = element("div", "item-head"); head.append(element("b", "", row.title), element("span", `pill ${row.state}`, row.state)); item.append(head, element("small", "", row.detail), element("small", "", `${row.device_key || "system"} · ${row.evidence_json}`)); list.append(item); });
}

async function loadIncidents() {
  const rows = await api("/api/incidents?limit=100"); const list = $("#incidents"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Keine korrelierten Incidents."));
  rows.forEach(row => { const item = element("div", "item"); const head = element("div", "item-head"), actions = element("div", "item-head"); head.append(element("b", "", row.title), element("span", `pill ${row.severity}`, `${row.severity} · ${Math.round(row.confidence * 100)}%`)); item.append(head, element("small", "", row.summary), element("small", "", `${row.rule_id} · ${row.target || "kein Blockziel"} · ${row.status}`)); const addAction = (label, status) => { const button = element("button", "ghost", label); button.addEventListener("click", async event => { event.stopPropagation(); const note = window.prompt(`Notiz für Status „${status}“ (optional):`, "") ?? null; if (note === null) return; try { await api(`/api/incidents/${row.id}`, {method:"PATCH", body:JSON.stringify({status,note})}); loadIncidents(); loadCaptures(); } catch(err) { toast(err.message); } }); actions.append(button); }; if (row.status === "open") addAction("Bestätigen", "acknowledged"); if (["open", "acknowledged"].includes(row.status)) { addAction("Schließen", "closed"); addAction("False positive", "false_positive"); } if (["closed", "false_positive"].includes(row.status)) addAction("Wieder öffnen", "open"); if (actions.children.length) item.append(actions); item.addEventListener("click", () => { $("#job-output").textContent = JSON.stringify(row, null, 2); $("[data-panel='observe']").click(); }); list.append(item); });
}

async function loadDetectionRules() {
  const rows = await api("/api/detections/rules"); const list = $("#detection-rules"); list.replaceChildren();
  rows.forEach(row => { const item = element("div", "item"), head = element("div", "item-head"); const toggle = element("button", "ghost", row.enabled ? "Deaktivieren" : "Aktivieren"); head.append(element("b", "", row.name), element("span", `pill ${row.enabled ? "completed" : ""}`, row.enabled ? "aktiv" : "aus")); item.append(head, element("small", "", `${row.category} · floor ${Math.round(row.confidence_floor * 100)}% · ${JSON.stringify(row.spec)}`), toggle); toggle.addEventListener("click", async event => { event.stopPropagation(); try { await api(`/api/detections/rules/${row.id}`, {method:"PATCH", body:JSON.stringify({enabled:!row.enabled})}); loadDetectionRules(); } catch(err) { toast(err.message); } }); item.addEventListener("click", () => { $("#job-output").textContent = JSON.stringify(row, null, 2); $("[data-panel='observe']").click(); }); list.append(item); });
}

async function searchKnowledge(query = null) {
  const value = query || $("#knowledge-query").value; const data = await api("/api/knowledge/search", {method:"POST", body:JSON.stringify({query:value, limit:10})}); const list = $("#knowledge-results"); list.replaceChildren();
  list.append(element("small", "muted", `${data.stats.documents} Dokumente · ${data.stats.engine}`));
  if (!data.results.length) list.append(element("p", "muted", "Keine lokalen Treffer."));
  data.results.forEach(row => { const item = element("div", "item"); const link = element("a", "", row.title); link.href = row.source_url; if (/^https:\/\//.test(row.source_url)) { link.target = "_blank"; link.rel = "noopener noreferrer"; } item.append(link, element("small", "", `${row.source_type} · Revision ${row.revision} · Relevanz ${row.relevance}`), element("small", "", row.excerpt)); list.append(item); });
}

async function loadDevices() {
  const rows = await api("/api/devices?limit=200"); const wrap = $("#devices"); wrap.replaceChildren();
  const table = element("table"), head = element("thead"), body = element("tbody");
  const trh = element("tr"); ["Gerät", "Status", "Erstmals", "Zuletzt"].forEach(v => trh.append(element("th", "", v))); head.append(trh);
  rows.forEach(row => { const tr = element("tr"); [row.display_name || row.device_key, row.state, row.first_seen, row.last_seen].forEach(v => tr.append(element("td", "", v || "–"))); body.append(tr); });
  table.append(head, body); wrap.append(table);
}

async function loadMonitors() {
  const rows = await api("/api/monitors"); const list = $("#monitor-list"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Noch keine Monitore."));
  rows.forEach(row => { const item = element("div", "item"); const head = element("div", "item-head"); head.append(element("b", "", row.name), element("span", `pill ${row.enabled ? "completed" : ""}`, row.enabled ? "aktiv" : "gestoppt")); item.append(head, element("small", "", `${row.kind} · alle ${row.interval_seconds}s · nächster Lauf ${row.next_run_at || "–"}`)); item.addEventListener("click", async () => { await api(`/api/monitors/${row.id}/${row.enabled ? "stop" : "start"}`, {method:"POST"}); loadMonitors(); }); list.append(item); });
}

async function loadGeneratedTools() {
  const rows = await api("/api/tool-lab"); const list = $("#generated-tools"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Noch keine Vorschläge."));
  rows.forEach(row => { const item = element("div", "item"); const head = element("div", "item-head"); const actions = element("div", "item-head"); const run = element("button", "ghost", "Ausführen"); const evolve = element("button", "ghost", "Verbessern + vergleichen"); head.append(element("b", "", `${row.name} · v${row.version}`), element("span", `pill ${row.status}`, row.status)); actions.append(run, evolve); item.append(head, element("small", "", `${row.id} · Score ${(JSON.parse(row.score_json || "{}").score ?? "–")}`), actions); item.addEventListener("click", () => { $("#job-output").textContent = JSON.stringify({spec:JSON.parse(row.spec_json), validation:JSON.parse(row.validation_json), score:JSON.parse(row.score_json || "{}")}, null, 2); $("[data-panel='observe']").click(); }); run.addEventListener("click", async event => { event.stopPropagation(); try { const result = await api(`/api/tool-lab/${row.id}/run`, {method:"POST"}); $("#job-output").textContent = JSON.stringify(result, null, 2); $("[data-panel='observe']").click(); loadAll(); } catch(err) { toast(err.message); } }); evolve.addEventListener("click", event => { event.stopPropagation(); submitJob(`/api/tool-lab/${row.id}/evolve`, {use_llm:true}).catch(err => toast(err.message)); }); list.append(item); });
}

async function loadFilters() {
  const rows = await api("/api/filters"); const list = $("#filter-list"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Noch keine Filter."));
  rows.forEach(row => { const item = element("div", "item"); const head = element("div", "item-head"); const test = element("button", "ghost", "Gegen PCAP testen"); head.append(element("b", "", `${row.name} · v${row.version}`), element("span", `pill ${row.status}`, row.status)); item.append(head, element("small", "", `${row.kind} · ${row.expression_template}`), test); item.addEventListener("click", () => { $("#job-output").textContent = JSON.stringify(row, null, 2); $("[data-panel='observe']").click(); }); test.addEventListener("click", async event => { event.stopPropagation(); try { const result = await api(`/api/filters/${row.id}/test`, {method:"POST",body:JSON.stringify({values:{}})}); $("#job-output").textContent = JSON.stringify(result, null, 2); $("[data-panel='observe']").click(); loadFilters(); } catch(err) { toast(err.message); } }); list.append(item); });
}

async function loadRecipes() {
  const rows = await api("/api/recipes"); const list = $("#recipe-list"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Noch keine Recipes."));
  rows.forEach(row => { const item = element("div", "item"); const head = element("div", "item-head"); const run = element("button", "ghost", "Recipe ausführen"); head.append(element("b", "", `${row.name} · v${row.version}`), element("span", `pill ${row.status}`, row.status)); item.append(head, element("small", "", row.description || "Ohne Beschreibung"), run); item.addEventListener("click", () => { $("#recipe-spec").value = JSON.stringify(row.spec, null, 2); }); run.addEventListener("click", event => { event.stopPropagation(); submitJob(`/api/recipes/${row.id}/run`, {}).catch(err => toast(err.message)); }); list.append(item); });
}

async function loadFirewalls() {
  const [bindings, proposals, policies] = await Promise.all([api("/api/firewalls/bindings"), api("/api/firewalls/proposals"), api("/api/firewalls/policies")]);
  const list = $("#firewall-bindings"), select = $("#firewall-binding"), proposalList = $("#firewall-proposals"); list.replaceChildren(); select.replaceChildren(); proposalList.replaceChildren();
  policies.forEach(row => { const item = element("div", "item"); item.append(element("b", "", row.name), element("small", "", `${row.mode} · ab ${Math.round(row.min_confidence * 100)}% · max. ${row.max_actions_per_hour}/h · TTL ${row.ttl_seconds}s`)); list.append(item); });
  bindings.forEach(row => { const item = element("div", "item"); const probe = element("button", "ghost", "Status prüfen"); item.append(element("b", "", row.name), element("small", "", `${row.adapter} · ${row.status}`), probe); probe.addEventListener("click", async () => { try { const result = await api(`/api/firewalls/bindings/${row.id}/probe`, {method:"POST"}); $("#job-output").textContent = JSON.stringify(result, null, 2); $("[data-panel='observe']").click(); loadFirewalls(); } catch(err) { toast(err.message); } }); list.append(item); const option = element("option", "", row.name); option.value = row.id; select.append(option); });
  if (!proposals.length) proposalList.append(element("p", "muted", "Keine Vorschläge."));
  proposals.forEach(row => { const item = element("div", "item"); const actions = element("div", "item-head"); item.append(element("b", "", `${row.action}: ${row.target}`), element("small", "", `${row.status} · ${row.reason}`), element("small", "", `Bestätigung ${row.confirmation_hash}`)); if (row.status === "pending_review") { const apply = element("button", "ghost", "Geprüft anwenden"); apply.addEventListener("click", async event => { event.stopPropagation(); if (!window.confirm(`Exakte Regel für ${row.target} anwenden?\nHash: ${row.confirmation_hash}`)) return; try { const result = await api(`/api/firewalls/proposals/${row.id}/apply`, {method:"POST", body:JSON.stringify({confirmation_hash:row.confirmation_hash})}); $("#job-output").textContent = JSON.stringify(result, null, 2); loadFirewalls(); } catch(err) { toast(err.message); } }); actions.append(apply); item.append(actions); } if (["applied", "rollback_required"].includes(row.status)) { const rollback = element("button", "ghost", "Rollback"); rollback.addEventListener("click", async event => { event.stopPropagation(); if (!window.confirm(`Regel für ${row.target} jetzt zurückrollen?`)) return; try { const result = await api(`/api/firewalls/proposals/${row.id}/rollback`, {method:"POST", body:JSON.stringify({confirmation_hash:row.confirmation_hash})}); $("#job-output").textContent = JSON.stringify(result, null, 2); loadFirewalls(); } catch(err) { toast(err.message); } }); actions.append(rollback); item.append(actions); } item.addEventListener("click", () => { $("#job-output").textContent = JSON.stringify(row, null, 2); $("[data-panel='observe']").click(); }); proposalList.append(item); });
}

async function loadEnergy() {
  const [settings, live] = await Promise.all([api("/api/energy/settings"), api("/api/energy/live")]);
  $("#energy-price").value = settings.electricity_eur_per_kwh; $("#energy-cpu-max").value = settings.cpu_max_watts; $("#energy-cpu-idle").value = settings.cpu_idle_watts;
  const list = $("#energy-live"); list.replaceChildren();
  list.append(element("small", "muted", `${settings.electricity_eur_per_kwh} €/kWh · CPU ${settings.cpu_idle_watts}–${settings.cpu_max_watts} W · GPU ${settings.gpu_meter}`));
  if (!live.active.length) list.append(element("p", "muted", "Gerade kein gemessener Job."));
  live.active.forEach(row => { const item = element("div", "item"); item.append(element("b", "", `${row.job_id} · ${row.wall_seconds.toFixed(1)}s`), element("small", "", `System-CPU ${row.system_cpu_percent.toFixed(1)}% · RAM ${(row.rss_bytes / 1024 ** 2).toFixed(1)} MiB · GPU ${row.gpu_power_watts ?? "–"} W`)); list.append(item); });
}

async function loadBenchmarks() {
  const rows = await api("/api/benchmarks?limit=10"); const list = $("#benchmarks"); list.replaceChildren();
  if (!rows.length) list.append(element("p", "muted", "Noch kein Benchmark."));
  rows.forEach(row => { const item = element("div", "item"); const result = row.result; item.append(element("b", "", `${result.tshark_decode.frames_per_second} Frames/s · ${result.tshark_decode.p50_ms} ms p50`), element("small", "", `RAG ${result.knowledge_bm25.p50_ms} ms · Detection ${result.detection_engine.p50_ms} ms · ${row.started_at}`)); item.addEventListener("click", () => { $("#job-output").textContent = JSON.stringify(row, null, 2); $("[data-panel='observe']").click(); }); list.append(item); });
}

async function loadCatalog() {
  const data = await api("/api/catalog"); const wrap = $("#catalog"); wrap.replaceChildren();
  [...data.datasets, ...data.integrations].forEach(row => { const card = element("div", "catalog-card"); const link = element("a", "", row.name); link.href = row.source_url; link.target = "_blank"; link.rel = "noopener noreferrer"; card.append(link, element("span", `pill ${row.local_status === "ready" ? "completed" : ""}`, row.local_status || row.status), element("small", "", row.purpose || row.role), element("small", "", row.recommendation || row.fit), element("small", "", row.risk || row.constraints)); wrap.append(card); });
  (data.artifacts || []).forEach(row => { const card = element("div", "catalog-card"); card.append(element("b", "", `Verifiziertes Artefakt · ${row.dataset_id}`), element("span", "pill completed", "ready"), element("small", "", `${row.bytes} Bytes · SHA-256 ${row.sha256}`), element("small", "", row.path)); wrap.append(card); });
}

async function loadSystem(refresh = false) {
  const [data, diagnosis] = await Promise.all([api(`/api/system${refresh ? "?refresh=true" : ""}`), api("/api/doctor")]); const wrap = $("#system-info"); wrap.replaceChildren();
  const grid = element("div", "cap-grid");
  Object.entries(data.capabilities || {}).forEach(([name, value]) => { const cap = element("div", "cap"); cap.append(element("b", "", name), element("span", value.available ? "yes" : "no", value.available ? "bereit" : "nicht installiert"), element("small", "muted", value.version || value.path || value.integration || "")); grid.append(cap); });
  const ollama = element("div", "cap"); ollama.append(element("b", "", "Ollama"), element("span", data.ollama?.available ? "yes" : "no", data.ollama?.available ? "bereit" : "nicht erreichbar"), element("small", "muted", (data.ollama?.models || []).join(", "))); grid.append(ollama); const profile = element("div", "cap"); profile.append(element("b", "", `Profil: ${data.profile?.id || "–"}`), element("span", "yes", data.profile?.capture || ""), element("small", "muted", data.profile?.description || "")); grid.append(profile); wrap.append(grid);
  const doctor = $("#doctor-info"); doctor.replaceChildren(); diagnosis.checks.forEach(check => { const item = element("div", "item"); const head = element("div", "item-head"); head.append(element("b", "", check.name), element("span", `pill ${check.status === "healthy" ? "completed" : check.status}`, check.status)); item.append(head, element("small", "", JSON.stringify(check.detail)), ...(check.action ? [element("small", "", check.action)] : [])); doctor.append(item); });
}

async function loadAudit() {
  const rows = await api("/api/audit?limit=50"); const list = $("#audit"); list.replaceChildren();
  rows.forEach(row => { const item = element("div", "item"); item.append(element("b", "", `${row.action} · ${row.outcome}`), element("small", "", `${row.ts} · ${row.target || "system"}`)); list.append(item); });
}

async function loadAll() { await Promise.allSettled([loadDashboard(), loadJobs(), loadCaptures(), loadSensors(), loadObservations(), loadIncidents(), loadDetectionRules(), loadDevices(), loadMonitors(), loadGeneratedTools(), loadFilters(), loadRecipes(), loadFirewalls(), loadCatalog(), loadEnergy(), loadBenchmarks(), loadAudit()]); }

$$('.tab').forEach(tab => tab.addEventListener('click', () => { $$('.tab,.panel').forEach(node => node.classList.remove('active')); tab.classList.add('active'); $(`#${tab.dataset.panel}`).classList.add('active'); }));
$("#tool-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/tools/run", {tool:$("#tool-name").value,target:$("#tool-target").value || null,profile:$("#tool-profile").value}).catch(err => toast(err.message)); });
$("#capture-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/capture/start", {interface:Number($("#capture-interface").value),duration_seconds:Number($("#capture-duration").value),max_packets:Number($("#capture-packets").value)}).catch(err => toast(err.message)); });
$("#pcap-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/pcap/analyze", {path:$("#pcap-path").value}).catch(err => toast(err.message)); });
$("#sensor-form").addEventListener("submit", async event => { event.preventDefault(); try { const source = await api("/api/sensors/sources", {method:"POST",body:JSON.stringify({name:$("#sensor-name").value,kind:"suricata_eve",path:$("#sensor-path").value,enabled:true})}); toast(`Quelle ${source.name} registriert.`); loadSensors(); } catch(err) { toast(err.message); } });
$("#query-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/query", {question:$("#query-text").value,use_llm:$("#query-llm").checked}).catch(err => toast(err.message)); });
$("#detection-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/detections/run", {window_minutes:Number($("#detection-window").value)}).catch(err => toast(err.message)); });
$("#knowledge-form").addEventListener("submit", event => { event.preventDefault(); searchKnowledge().catch(err => toast(err.message)); });
$("#monitor-form").addEventListener("submit", async event => { event.preventDefault(); try { await api("/api/monitors", {method:"POST",body:JSON.stringify({name:$("#monitor-name").value,kind:$("#monitor-kind").value,interval_seconds:Number($("#monitor-interval").value),config:{}})}); toast("Monitor wurde angelegt."); loadMonitors(); } catch(err) { toast(err.message); } });
$("#lab-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/tool-lab/generate", {prompt:$("#lab-prompt").value,use_llm:$("#lab-llm").checked}).catch(err => toast(err.message)); });
$("#filter-generate-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/filters/generate", {prompt:$("#filter-prompt").value,use_llm:$("#filter-llm").checked}).catch(err => toast(err.message)); });
$("#recipe-form").addEventListener("submit", async event => { event.preventDefault(); try { const spec = JSON.parse($("#recipe-spec").value); await api("/api/recipes", {method:"POST",body:JSON.stringify({name:$("#recipe-name").value,description:$("#recipe-description").value,spec,activate:true})}); toast("Recipe-Version gespeichert."); loadRecipes(); } catch(err) { toast(err.message); } });
$("#firewall-proposal-form").addEventListener("submit", async event => { event.preventDefault(); try { const result = await api("/api/firewalls/proposals", {method:"POST",body:JSON.stringify({binding_id:$("#firewall-binding").value,target:$("#firewall-target").value,reason:$("#firewall-reason").value,ttl_seconds:Number($("#firewall-ttl").value),evidence:[]})}); $("#job-output").textContent = JSON.stringify(result, null, 2); toast("Firewall-Vorschlag gespeichert; nichts wurde angewendet."); loadFirewalls(); } catch(err) { toast(err.message); } });
$("#energy-form").addEventListener("submit", async event => { event.preventDefault(); try { await api("/api/energy/settings", {method:"PUT", body:JSON.stringify({electricity_eur_per_kwh:Number($("#energy-price").value), cpu_max_watts:Number($("#energy-cpu-max").value), cpu_idle_watts:Number($("#energy-cpu-idle").value)})}); toast("Messprofil gespeichert."); loadEnergy(); } catch(err) { toast(err.message); } });
$("#benchmark-form").addEventListener("submit", event => { event.preventDefault(); submitJob("/api/benchmarks/run", {repeats:Number($("#benchmark-repeats").value)}).catch(err => toast(err.message)); });
$("#refresh-jobs").addEventListener("click", loadJobs); $("#refresh-system").addEventListener("click", () => loadSystem(true).catch(err => toast(err.message)));

api("/api/health").then(() => { $("#health-dot").classList.add("ok"); $("#health-text").textContent="Lokal bereit"; }).catch(() => $("#health-text").textContent="Nicht erreichbar");
loadInterfaces().catch(err => toast(err.message)); loadSystem().catch(err => toast(err.message)); loadAll();
const stream = new EventSource("/api/stream"); stream.addEventListener("status", event => loadDashboard(JSON.parse(event.data)));
setInterval(() => loadEnergy().catch(() => {}), 1500);
