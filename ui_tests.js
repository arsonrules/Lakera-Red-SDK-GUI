// Browser feature test for static/index.html, driven against the offline demo rig.
// Needs `python demo_servers.py` (echo target on :8801, mock Red relay on :8803).
// Run: open the app, paste this file into the devtools console, then `await uiTests()`.
// Then reload the page and run `await uiTestsAfterReload()` to check what the browser remembered.

async function uiTests() {
  const $ = id => document.getElementById(id);
  const results = [];
  const check = (name, ok, info = "") => results.push({ ok: !!ok, name, info: ok ? "" : String(info) });
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const until = async (fn, ms = 20000) => {
    for (const end = Date.now() + ms; Date.now() < end; await sleep(100)) { const v = fn(); if (v) return v; }
    return null;
  };
  const fire = (id, type) => $(id).dispatchEvent(new Event(type, { bubbles: true }));  // as real typing does
  const set = (id, v) => { $(id).value = v; fire(id, "input"); fire(id, "change"); };
  const pick = (id, v) => { $(id).value = v; fire(id, "change"); };
  const msg = id => document.querySelector(`.field-msg[data-for=${id}]`)?.textContent || "";
  const invalid = id => $(id).getAttribute("aria-invalid") === "true";
  const visible = el => !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
  const width = el => el.getBoundingClientRect().width;
  const DEMO = "http://127.0.0.1:8801", RELAY = "http://127.0.0.1:8803";
  const OBJS = ["security.system-prompt-extraction.1", "safety.dangerous-instructions.1"];
  const probe = async () => {
    $("probe").click();
    await until(() => !/Testing/.test($("probe-out").textContent) && !$("probe-out").hidden);
    return $("probe-out");
  };

  await until(() => document.body.dataset.ready);

  // ---- layout
  if (innerWidth > 900) {
    check("wide: form and run panel side by side", visible($("form")) && width($("run")) > 300, width($("run")));
    check("wide: view tabs hidden", !visible($("tabs")));
  } else {
    check("narrow: view tabs shown", visible($("tabs")));
    $("tab-config").click();
    check("narrow: Configure shows the form only", visible($("form")) && !visible($("run")));
    $("tab-run").click();
    check("narrow: Run shows the run panel at full width",
      !visible($("form")) && width($("run")) >= innerWidth - 20, width($("run")));
    check("narrow: selected tab is marked", $("tab-run").getAttribute("aria-selected") === "true");
    $("tab-config").click();
    check("narrow: no horizontal page scroll", document.documentElement.scrollWidth <= innerWidth,
      document.documentElement.scrollWidth);
  }

  // ---- accessibility basics
  const orphan = [...document.querySelectorAll("#form label:not(.inline)")]
    .filter(l => !l.querySelector("input") && l.id !== "objectives-label" && !$(l.htmlFor));
  check("every form label is linked to its control", !orphan.length, orphan.map(l => l.textContent.trim()).join(" | "));
  check("status and probe output are announced", $("status").getAttribute("aria-live") === "polite"
    && $("probe-out").getAttribute("aria-live") === "polite" && $("tls-out").getAttribute("aria-live") === "polite");
  const secrets = document.querySelectorAll("input[type=password]");
  check("every secret field has a show/hide toggle",
    [...secrets].every(i => i.parentElement.classList.contains("secret")), secrets.length);
  const tog = $("api_key").nextElementSibling;
  tog.click();
  const shown = $("api_key").type === "text" && tog.getAttribute("aria-pressed") === "true";
  tog.click();
  check("show/hide toggles the key's visibility", shown && $("api_key").type === "password");
  check("CA bundle hint says it adds to the default roots", /Adds this CA to the default trust store/.test($("form").textContent));

  // ---- header, shortcuts, themes
  check("header: shows the Red key status", /^Red key: /.test($("hs-key").textContent) && !!$("hs-key").dataset.s,
    $("hs-key").textContent);
  check("header: shows the installed SDK version", /^SDK v0\.11\.\d+$/.test($("sdkver").textContent), $("sdkver").textContent);
  check("reply timeout is bounded to Red's 1–480 s", $("response_timeout_seconds").min === "1"
    && $("response_timeout_seconds").max === "480");
  document.activeElement?.blur();
  document.body.dispatchEvent(new KeyboardEvent("keydown", {key: "/", bubbles: true}));
  check("shortcut: '/' jumps to the objective filter", document.activeElement === $("obj_search") && $("sec-scan").open);
  $("response_path").focus();
  $("response_path").dispatchEvent(new KeyboardEvent("keydown", {key: "/", bubbles: true}));
  check("shortcut: '/' typed in a field stays in that field", document.activeElement === $("response_path"));
  const urlBefore = $("url").value;
  set("url", "ftp://bad");
  document.body.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", ctrlKey: true, bubbles: true}));
  check("shortcut: Ctrl+Enter submits the scan form", /Fix the highlighted field/.test($("form-err").textContent),
    $("form-err").textContent);
  set("url", urlBefore || `${DEMO}/chat`);

  const tok = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const lum = hex => {
    const n = hex.replace("#", ""), full = n.length === 3 ? [...n].map(c => c + c).join("") : n;
    const [r, g, b] = [0, 2, 4].map(i => parseInt(full.slice(i, i + 2), 16) / 255)
      .map(c => c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const ratio = (a, b) => { const [x, y] = [lum(tok(a)), lum(tok(b))].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const PAIRS = [["--fg", "--bg"], ["--fg", "--panel"], ["--dim", "--bg"], ["--dim", "--panel"], ["--dim", "--panel2"],
    ["--accent", "--panel"], ["--warn", "--panel"], ["--ok", "--panel"], ["--link", "--panel"],
    ["--fail-fg", "--fail-bg"], ["--pass-fg", "--pass-bg"], ["--warn-fg", "--warn-bg"], ["--on-accent", "--btn"]];
  const themeBefore = document.documentElement.dataset.theme || "system";
  for (const theme of ["light", "dark"]) {
    applyTheme(theme);
    const bodyBg = getComputedStyle(document.body).backgroundColor;
    const want = tok("--bg").replace("#", "").match(/../g).map(x => parseInt(x, 16)).join(", ");
    check(`theme ${theme}: page uses that theme's background`, bodyBg === `rgb(${want})`, `${bodyBg} vs ${want}`);
    const weak = PAIRS.map(([a, b]) => [a, b, ratio(a, b)]).filter(([, , r]) => r < 4.5);
    check(`theme ${theme}: text pairs meet 4.5:1 contrast`, !weak.length,
      weak.map(([a, b, r]) => `${a} on ${b} ${r.toFixed(2)}`).join(", "));
  }
  applyTheme("system");
  $("theme").click();
  const cycle = [document.documentElement.dataset.theme];
  $("theme").click(); cycle.push(document.documentElement.dataset.theme);
  $("theme").click(); cycle.push(document.documentElement.dataset.theme || "system");
  check("theme button cycles light → dark → system", cycle.join() === "light,dark,system", cycle.join());
  check("theme choice is remembered", localStorage.getItem("redrunner.theme") === null && $("theme").textContent === "Theme: system");
  applyTheme(themeBefore);

  // ---- toggles
  pick("auth_type", "bearer");
  check("bearer auth shows the token field", visible($("token_bearer")) && !visible($("username")));
  pick("auth_type", "none");
  pick("strategy", "crescendo");
  check("crescendo shows its options", visible($("max_turns")) && !visible($("number_of_probes")));
  pick("strategy", "static");
  set("url", "ws://127.0.0.1:8801/ws");
  check("a ws URL hides the HTTP method", !visible($("method")));

  // ---- field checks
  set("url", "ftp://example.com/x");
  check("url: unsupported scheme flagged", invalid("url") && /http, https, ws or wss/.test(msg("url")), msg("url"));
  set("url", "http://127.0.0.1:8801/chat");
  check("url: fixing it clears the error", !invalid("url") && !msg("url"), msg("url"));
  set("response_path", "https://apiai.staging-eid.gov.hk/api/v1/llm/stream/{StreamToken}");
  check("response path: a URL is flagged and points to SSE stream URL",
    invalid("response_path") && /SSE stream URL/.test(msg("response_path")), msg("response_path"));
  set("response_path", "choices.0.message.content");
  check("response path: a dot path is accepted", !invalid("response_path"));
  set("body_template", '{"chatbot_id": "{{chkp-test}}", "data": {"text": "{{prompt}}"}}');
  check("body: unknown placeholder flagged by name", invalid("body_template") && msg("body_template").includes("{{chkp-test}}"),
    msg("body_template"));
  set("body_template", '{"chatbot_id": "chkp-test", "data": {"text": "{{prompt}}"}, "h": {{messages}}}');
  check("body: {{prompt}} and {{messages}} accepted", !invalid("body_template"), msg("body_template"));
  set("body_template", "");
  set("headers", "{bad");
  check("headers: invalid JSON flagged", invalid("headers") && /Not valid JSON/.test(msg("headers")));
  set("headers", '{"X-N": 1}');
  check("headers: non-string value flagged", invalid("headers"));
  set("headers", '{"X-Env": "staging"}');
  check("headers: an object of strings accepted", !invalid("headers"));
  set("headers", "");
  set("custom_objectives", "{}");
  check("custom objectives: non-array flagged", invalid("custom_objectives"));
  set("custom_objectives", "");
  set("stream_url", "wss://host/sse");
  check("stream URL: non-http scheme flagged", invalid("stream_url"));
  set("stream_url", "[https://apiai.staging-eid.gov.hk/api/v1/llm/stream/](https://apiai.staging-eid.gov.hk/api/v1/llm/stream/${encodeURIComponent(streamToken))");
  check("stream URL: pasted link + JS token expression become {StreamToken}",
    $("stream_url").value === "https://apiai.staging-eid.gov.hk/api/v1/llm/stream/{StreamToken}" && !invalid("stream_url"),
    $("stream_url").value);
  check("stream URL: the conversion is explained", /Converted/.test(msg("stream_url")), msg("stream_url"));
  set("stream_url", "https://x.example/stream/${encodeURIComponent(streamToken)}");
  check("stream URL: a well-formed JS template converts too", $("stream_url").value === "https://x.example/stream/{StreamToken}",
    $("stream_url").value);
  set("stream_url", "");
  set("url", "wss://apiai.staging-eid.gov.hk/ws");
  check("ws target without a stream URL gets a note, not an error",
    !invalid("stream_url") && /ws\/wss/.test(msg("stream_url")), msg("stream_url"));

  // ---- Test connection
  set("url", `${DEMO}/chat`);
  set("response_path", "https://wrong.example/x");
  let out = await probe();
  check("probe: blocked by an invalid field, which gets focus",
    out.classList.contains("fail") && /Fix the highlighted field/.test(out.textContent)
    && document.activeElement === $("response_path"), out.textContent);
  set("response_path", "choices.0.message.content");
  check("probe: the 'fix first' message clears once the field is edited", $("probe-out").hidden);
  out = await probe();
  check("probe: http target connects, shows steps and the reply",
    out.classList.contains("ok") && out.querySelectorAll(".steps li").length >= 1 && /echo/.test(out.querySelector("pre")?.textContent),
    out.textContent);
  check("header: shows the last connection test", $("hs-probe").dataset.s === "ok" && /connected/.test($("hs-probe").textContent),
    $("hs-probe").textContent);
  set("url", `${DEMO}/sse-chat`); set("response_path", "");
  out = await probe();
  check("probe: SSE target reports its chunks and hand-off steps",
    out.classList.contains("ok") && /SSE chunk/.test(out.querySelector("h5").textContent)
    && out.querySelectorAll(".steps li").length >= 3, out.textContent);
  set("url", `${DEMO.replace("http", "ws")}/ws`); set("response_path", "reply"); set("body_template", "{{prompt}}");
  out = await probe();
  check("probe: ws target connects", out.classList.contains("ok"), out.textContent);
  set("url", "http://127.0.0.1:1/nothing"); set("response_path", ""); set("body_template", "");
  out = await probe();
  check("probe: unreachable target fails with the error shown",
    out.classList.contains("fail") && /Connection failed/.test(out.textContent) && out.querySelector("pre")?.textContent,
    out.textContent);
  check("probe: error text is rendered as text, not HTML", !out.querySelector("pre *"));
  check("header: a failed test shows as failed", $("hs-probe").dataset.s === "fail");
  set("response_path", "x");
  check("header: editing the target marks the test as stale", /changed since/.test($("hs-probe").textContent));
  set("response_path", "");

  // ---- Diagnose TLS: its own box, leaves the probe result alone
  const probeText = $("probe-out").textContent;
  $("tlsdoc").click();
  await until(() => !$("tls-out").hidden && !/Inspecting/.test($("tls-out").textContent));
  check("TLS diagnosis renders in its own box", /TLS/.test($("tls-out").querySelector("h5")?.textContent), $("tls-out").textContent);
  check("TLS diagnosis does not overwrite the probe result", $("probe-out").textContent === probeText);

  // ---- CA store listing
  pick("ca_mode", "upload");
  await until(() => $("ca_saved").options.length);
  check("CA upload mode lists stored bundles", visible($("ca_upload_box")) && $("ca_saved").options.length >= 1);
  pick("ca_mode", "none");

  // ---- sections and sticky actions
  check("form is grouped into collapsible sections", document.querySelectorAll("details.sec").length === 7);
  set("url", "wss://apiai.example.test/ws"); pick("auth_type", "bearer");
  check("a section summary reflects its fields",
    $("sec-conn").querySelector(".sum").textContent === "wss · apiai.example.test · bearer token",
    $("sec-conn").querySelector(".sum").textContent);
  pick("auth_type", "none");
  set("url", `${DEMO}/chat`);
  $("sec-resp").open = false;
  set("response_path", "https://x.example/y");
  $("probe").click();
  check("an invalid field in a collapsed section is opened and focused",
    $("sec-resp").open && document.activeElement === $("response_path"));
  set("response_path", "");
  $("form").scrollTop = 0; scrollTo(0, 0);
  const goBox = $("go").getBoundingClientRect();
  check("Run scan stays on screen while the form is scrolled to the top",
    goBox.top >= 0 && goBox.bottom <= innerHeight, `${goBox.top}..${goBox.bottom} of ${innerHeight}`);

  // ---- remembered form and saved configs
  set("token_bearer", "SECRET-TOKEN-123"); set("api_key", "SECRET-KEY-456"); set("target_name", "remembered-target");
  check("the form is remembered in this browser", (localStorage.getItem("redrunner.form.v1") || "").includes("remembered-target"));
  check("secrets are never written to browser storage", !/SECRET-/.test(JSON.stringify(localStorage)));
  const realPrompt = window.prompt, realConfirm = window.confirm;
  window.prompt = () => "ui-test-config"; window.confirm = () => true;
  try {
    $("cfg_save").click();
    check("Save as stores a named config and selects it", $("saved_cfg").value === "ui-test-config");
    check("a saved config holds no secrets", !/SECRET-/.test(localStorage.getItem("redrunner.configs.v1")));
    set("target_name", "changed");
    pick("saved_cfg", "ui-test-config");
    check("loading a saved config restores its fields",
      await until(() => $("target_name").value === "remembered-target", 3000), $("target_name").value);
    const exported = configJSON();
    check("export holds the fields without secrets", exported.includes("remembered-target") && !/SECRET-/.test(exported));
    await importConfig(JSON.stringify({config: {target_name: "imported-target", api_key: "SECRET-IMPORT",
                                                bogus: 1, auth_type: "nonsense"}}));
    check("import applies known fields", $("target_name").value === "imported-target");
    check("import ignores secrets, unknown keys and invalid choices",
      $("api_key").value === "SECRET-KEY-456" && $("auth_type").value === "none", $("auth_type").value);
    await importConfig("{not json");
    check("a broken import file is reported", /not valid JSON/.test($("cfg-msg").textContent), $("cfg-msg").textContent);
    pick("saved_cfg", "ui-test-config");
    await sleep(50);
    $("cfg_delete").click();
    check("Delete removes the saved config", ![...$("saved_cfg").options].some(o => o.value === "ui-test-config"));
  } finally { window.prompt = realPrompt; window.confirm = realConfirm; }
  set("api_key", ""); set("token_bearer", "");

  // ---- templates
  pick("template", "openai");
  await until(() => $("response_path").value === "choices.0.message.content", 3000);
  check("OpenAI template fills the request and response shape",
    $("body_template").value.includes("{{messages}}") && $("auth_type").value === "bearer" && $("template").value === "");
  pick("template", "ws-sse");
  await until(() => $("body_template").value.includes('"text"'), 3000);
  check("WebSocket → SSE template fills the body and says what to set next",
    $("body_template").value === '{"data": {"text": "{{prompt}}"}}' && /SSE stream URL/.test($("cfg-msg").textContent));
  pick("auth_type", "none"); set("body_template", "");

  // ---- objectives picker
  const opts = () => [...document.querySelectorAll("label.objopt")];
  set("obj_search", "prompt");
  const shownOpts = opts().filter(visible);
  check("the objective filter narrows the list",
    shownOpts.length > 0 && shownOpts.length < opts().length && shownOpts.every(o => o.dataset.find.includes("prompt")),
    shownOpts.length);
  set("obj_search", "zzzz-no-match");
  check("a filter with no match says so", visible($("objectives").querySelector(".none")));
  set("obj_search", "");
  if (!$("obj_clear").disabled) $("obj_clear").click();
  const cat = document.querySelector("#objectives .cat"), catToggle = cat.querySelector(".cat-toggle");
  const inCat = cat.querySelectorAll(".obj").length;
  catToggle.click();
  check("a category toggle selects the whole category",
    [...cat.querySelectorAll(".obj")].every(c => c.checked)
    && $("obj_count").textContent.startsWith(`${inCat} of ${opts().length} objectives selected`), $("obj_count").textContent);
  cat.querySelector(".obj").click();
  check("a partly selected category shows as mixed", catToggle.indeterminate);
  check("the scan summary counts the selection", /objective\(s\)/.test($("sec-scan").querySelector(".sum").textContent));
  $("obj_clear").click();
  check("Clear returns to running every objective",
    /^All \d+ objectives will run/.test($("obj_count").textContent) && $("obj_clear").disabled, $("obj_count").textContent);

  // ---- Run scan
  set("url", "ftp://bad");
  const statusBefore = $("status").textContent;
  $("go").click();
  check("run: blocked by an invalid field with a form error",
    /Fix the highlighted field/.test($("form-err").textContent) && $("status").textContent === statusBefore, $("form-err").textContent);
  set("url", `${DEMO}/chat`); set("response_path", "choices.0.message.content");
  set("api_key", "demo"); set("base_url", "http://127.0.0.1:1");
  $("go").click();
  await until(() => !$("banner").hidden, 30000);
  check("run: a scan that fails raises the banner", !$("banner").hidden && /failed/i.test($("banner").textContent),
    $("banner").textContent);
  check("run: Run scan is re-enabled after a failure", await until(() => !$("go").disabled));
  $("banner").querySelector("button").click();
  check("run: banner can be dismissed", $("banner").hidden);
  check("run: a failed scan's error shows in the conversation view", !!$("convs").querySelector(".sysline.error"));

  set("base_url", RELAY);
  $("objectives").querySelectorAll("input.obj").forEach(c => {
    c.checked = OBJS.includes(c.value); c.dispatchEvent(new Event("change", {bubbles: true}));
  });
  $("go").click();
  check("run: switches to the run view", document.body.dataset.view === "run");
  const done = await until(() => $("status").textContent === "done" && !$("go").disabled, 60000);
  check("run: demo scan completes", done, $("status").textContent);
  check("run: log shows attacks and replies",
    $("log").querySelector(".l.attack") && $("log").querySelector(".l.reply"), $("log").children.length);
  check("run: no banner on success", $("banner").hidden, $("banner").textContent);
  check("run: the objective picker's counts ignore the results table",
    $("obj_count").textContent === `${OBJS.length} of ${opts().length} objectives selected`, $("obj_count").textContent);

  // ---- run view: status, progress, conversations
  check("run: status indicator shows done", $("status").dataset.s === "done");
  check("run: elapsed time shown", /^\d+:\d\d$/.test($("elapsed").textContent), $("elapsed").textContent);
  check("run: header names the scan", $("meta").textContent.includes($("scan_name").value), $("meta").textContent);
  const prog = $("progress").textContent, num = re => +(re.exec(prog) || [])[1];
  check("run: progress counts attacks and replies", num(/(\d+) attacks/) >= 2 && num(/(\d+) replies/) >= 2, prog);
  const cards = () => [...document.querySelectorAll("#convs .conv")];
  const objCards = cards().filter(c => !c.dataset.sid.startsWith("recon"));
  check("run: one conversation card per objective session", objCards.length === OBJS.length, objCards.length);
  check("run: each conversation shows its attacks and replies",
    objCards.every(c => c.querySelector(".bubble.attack") && c.querySelector(".bubble.reply")));
  check("run: finished conversations are marked closed",
    objCards.every(c => c.querySelector("summary .pill").textContent === "closed"),
    objCards.map(c => c.querySelector("summary .pill").textContent));
  check("run: the Results tab opens when the scan finishes",
    $("vt-results").getAttribute("aria-selected") === "true" && !$("pane-results").hidden);
  check("run: the Results tab shows the count", $("res-badge").textContent === String(OBJS.length));

  // ---- results: summary, sort, filter, drill-down
  const resRows = () => [...$("results").querySelectorAll("tr.res-row")];
  const rowVerdict = r => r.querySelector(".pill").textContent;
  check("results: one row per objective", resRows().length === OBJS.length, resRows().length);
  const summaryText = $("results").querySelector(".summary").textContent;
  check("results: summary shows the verdict and counts",
    /verdict/i.test(summaryText) && /Broken1/.test(summaryText) && /Held1/.test(summaryText), summaryText);
  check("results: worst verdict sorts first", rowVerdict(resRows()[0]) === "malicious", rowVerdict(resRows()[0]));
  const sortBy = label => [...$("results").querySelectorAll("th button")].find(b => b.textContent === label).click();
  sortBy("Score");
  check("results: sort by score ascending",
    resRows()[0].children[2].textContent === "0" && $("results").querySelector("th[aria-sort=ascending]"));
  sortBy("Score");
  check("results: sort by score descending", resRows()[0].children[2].textContent === "5");
  sortBy("Verdict");
  const pickFilter = f => { const r = $("results").querySelector(`input[name=resfilter][value=${f}]`); r.checked = true; r.dispatchEvent(new Event("change")); };
  pickFilter("safe");
  check("results: filter to safe objectives", resRows().length === 1 && rowVerdict(resRows()[0]) === "safe");
  pickFilter("problems");
  check("results: an empty filter says so", !resRows().length && /No result matches/.test($("results").textContent));
  pickFilter("all");
  const first = resRows()[0];
  first.click();
  const detail = first.nextElementSibling;
  check("results: clicking a row shows its explanation and conversation",
    first.getAttribute("aria-expanded") === "true" && visible(detail) && detail.querySelectorAll(".bubble").length === 2,
    detail.textContent.slice(0, 120));
  first.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", bubbles: true}));
  check("results: Enter toggles a row from the keyboard", first.getAttribute("aria-expanded") === "false" && !visible(detail));

  check("run panel shows no stray null/undefined text", !/\b(null|undefined)\b/.test($("run").innerText), $("run").innerText.match(/.{0,30}\b(null|undefined)\b.{0,10}/)?.[0]);

  // ---- export
  const json = JSON.parse(exportText("json"));
  check("export: JSON holds the run and its results",
    json.results.results.length === OBJS.length && json.verdict === "malicious" && json.run_id === currentRun);
  check("export: JSON carries no API key", !/"demo"/.test(exportText("json")));
  const csv = exportText("csv").trim().split("\r\n");
  check("export: CSV has a header and one line per objective",
    csv[0] === "objective,verdict,score,explanation" && csv.length === OBJS.length + 1, csv);
  check("export: CSV neutralises formulas and quotes cells",
    csvCell("=HYPERLINK(1)") === "'=HYPERLINK(1)" && csvCell('a,"b"') === '"a,""b"""' && csvCell("-1") === "'-1");
  const md = exportText("md");
  check("export: report has the verdict and a results table",
    md.includes("**Verdict:** malicious") && md.includes("| Objective | Verdict | Score | Explanation |"), md.slice(0, 200));

  // ---- raw log with filters
  $("vt-raw").click();
  check("raw log: tab shows the log", !$("pane-raw").hidden && $("log").children.length > 0);
  check("raw log: fields render as tags", !!$("log").querySelector(".tag"));
  const chip = level => $("filters").querySelector(`input[data-level=${level}]`);
  const toggleChip = level => { chip(level).checked = !chip(level).checked; chip(level).dispatchEvent(new Event("change")); };
  toggleChip("attack");
  check("raw log: hiding a level removes its lines", !$("log").querySelector(".l.attack") && $("log").querySelector(".l.reply"));
  toggleChip("attack");
  check("raw log: showing it again restores them", !!$("log").querySelector(".l.attack"));
  if (chip("noise").checked) toggleChip("noise");
  check("raw log: session open/close lines can be hidden",
    ![...$("log").querySelectorAll(".msg")].some(m => /^session (opened|closed)/.test(m.textContent)));
  toggleChip("noise");

  // ---- history and replay
  check("history: the finished run is listed and selected",
    await until(() => $("history").value === currentRun && /done/.test($("history").selectedOptions[0].textContent), 5000),
    $("history").value);
  const before = cards().length;
  listen(currentRun);
  await until(() => $("status").textContent === "done" && !$("go").disabled && cards().length === before, 10000);
  check("history: reattaching replays the run without duplicates", cards().length === before && resRows().length === OBJS.length,
    `${before} -> ${cards().length}`);

  // ---- a streamed (SSE) target: chunks grow a reply bubble that the full reply then replaces
  set("url", `${DEMO}/sse-chat`); set("response_path", ""); set("stream_url", "");
  $("go").click();
  await until(() => $("status").textContent === "done" && !$("go").disabled, 60000);
  const sseCards = cards().filter(c => !c.dataset.sid.startsWith("recon"));
  check("SSE scan: replies land in the conversation view",
    sseCards.length === OBJS.length && sseCards.every(c => c.querySelector(".bubble.reply")), sseCards.length);
  check("SSE scan: no reply is left half-streamed", !document.querySelector("#convs .bubble.streaming"));
  check("SSE scan: every streamed reply holds text",
    sseCards.every(c => [...c.querySelectorAll(".bubble.reply .text")].every(t => t.textContent.length > 0)));
  set("url", `${DEMO}/chat`); set("response_path", "choices.0.message.content");
  if (innerWidth <= 900) $("tab-config").click();

  const failed = results.filter(r => !r.ok);
  return { passed: results.length - failed.length, failed: failed.length, failures: failed };
}

// Run before reloading: sets values that should survive a reload, and some that must not.
function uiTestsBeforeReload() {
  const $ = id => document.getElementById(id);
  const set = (id, v) => { $(id).value = v; $(id).dispatchEvent(new Event("input", {bubbles: true})); };
  set("scan_name", "ui-test-reload-marker");
  set("api_key", "SECRET-RELOAD");
  $("sec-profile").open = false;
  $("sec-tls").open = true;
  return "now reload and run uiTestsAfterReload()";
}

async function uiTestsAfterReload() {
  const $ = id => document.getElementById(id);
  for (let i = 0; i < 100 && !document.body.dataset.ready; i++) await new Promise(r => setTimeout(r, 100));
  const results = [
    ["fields survive a reload", $("scan_name").value === "ui-test-reload-marker"],
    ["secrets do not survive a reload", $("api_key").value === ""],
    ["collapsed and opened sections are remembered", !$("sec-profile").open && $("sec-tls").open],
  ].map(([name, ok]) => ({name, ok}));
  for (let i = 0; i < 100 && $("status").textContent !== "done"; i++) await new Promise(r => setTimeout(r, 100));
  results.push({name: "the last run is reattached after a reload",
    ok: $("status").textContent === "done" && document.querySelectorAll("#results tr.res-row").length > 0
        && document.querySelectorAll("#convs .conv").length > 0});
  $("scan_name").value = "web-service scan"; $("scan_name").dispatchEvent(new Event("input", {bubbles: true}));
  const failed = results.filter(r => !r.ok);
  return { passed: results.length - failed.length, failed: failed.length, failures: failed };
}
