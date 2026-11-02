/* Monaco workbench and focused single-file editor. Repository text is never HTML. */
(function () {
    "use strict";
    const root = document.getElementById("webide");
    if (!root) return;
    const el = id => document.getElementById("ide-" + id);
    const originals = new Map(), models = new Map(), changes = new Map();
    const viewStates = new Map(), expanded = new Set(), opened = [];
    let snapshot, editor, diff, originalModel, deletedModel, active = null, busy = false, reviewing = false;
    const languageOverrides = new Map();
    // Language workbench (VS Code style): registry, auto detection, quick pick.
    const languageItems = [];  // unique {id, name, extensions}
    const languageById = new Map();
    function buildLanguages() {
        if (languageItems.length) return languageItems;
        const seen = new Set();  // Monaco registers aliases; one entry per id.
        for (const lang of monaco.languages.getLanguages()) {
            if (seen.has(lang.id)) continue;
            seen.add(lang.id);
            const item = {id: lang.id, name: lang.name || lang.id, extensions: [...(lang.extensions || [])]};
            languageItems.push(item); languageById.set(lang.id, item);
        }
        return languageItems;
    }
    function detectLanguage(filename) {
        const name = basename(filename).toLowerCase();
        const ext = name.includes(".") ? name.split(".").pop() : "";
        if (!ext) return "";
        for (const item of buildLanguages()) {
            if (item.extensions.some(value => value.toLowerCase() === "." + ext)) return item.id;
        }
        return "";
    }
    const effectiveLanguage = filename => languageOverrides.get(filename) ?? detectLanguage(filename);
    function languageLabel(filename) {
        if (!filename) return "Plain Text";
        const choice = effectiveLanguage(filename);
        const item = choice ? languageById.get(choice) : null;
        return item ? item.name : "Plain Text";
    }
    function syncLanguage() {
        const select = el("language");
        if (!select) return;
        select.textContent = languageLabel(active);
        select.setAttribute("aria-label", "Language: " + select.textContent +
            (active && languageOverrides.has(active) ? " (overridden)" : " (auto-detected)"));
        select.disabled = busy || !active || changes.get(active) === null;
    }
    function applyLanguage(filename, choice) {
        if (!choice) languageOverrides.delete(filename);
        else languageOverrides.set(filename, choice);
        // Recreate the model so the language applies from the first token.
        const wasReviewing = reviewing;
        closeDiff();
        const value = models.has(filename) ? models.get(filename).getValue() : originals.get(filename) || "";
        models.get(filename)?.dispose(); models.delete(filename);
        model(filename, value);
        if (wasReviewing) return review();
        show(filename, true);
        status(choice ? "Language mode changed to " + choice + "."
                      : "Auto-detect restored" + (detectLanguage(filename) ? ": " + detectLanguage(filename) : "."));
    }    const single = () => root.dataset.mode === "single";
    const resolveMode = () => root.dataset.mode === "resolve";
    const resolveState = () => resolveMode() && snapshot;
    function wordWrapPref() { try { return localStorage.getItem("pygithost_ide_wrap") === "on" ? "on" : "off"; } catch { return "off"; } }
    function syncWrap() {
        const on = wordWrapPref() === "on";
        el("wrap")?.setAttribute("aria-pressed", String(on));
        el("wrap")?.classList.toggle("ide-status-active", on);
    }
    const dirty = () => changes.size > 0;
    const status = text => { el("status").textContent = text; };
    const basename = filename => filename.split("/").at(-1);
    const validPath = filename => filename && !filename.split("/").some(p => !p || p === "." || p === ".." || p.toLowerCase() === ".git") && !/[\\\x00-\x1f]/.test(filename);

    async function api(action, params = {}, post, baseOverride = null) {
        const url = new URL((baseOverride || root.dataset.base) + "/" + action, location.origin);
        Object.entries(params).forEach(([key, value]) => url.searchParams.set(key, value));
        const response = await fetch(url, post ? {
            method: "POST", credentials: "same-origin",
            body: new URLSearchParams({csrf: root.dataset.csrf, payload: JSON.stringify(post)})
        } : {credentials: "same-origin"});
        if (response.redirected) throw new Error("Your session expired. Keep this tab open and sign in in another tab.");
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "Request failed.");
        return result;
    }
    function lock(value) {
        busy = value;
        root.querySelectorAll("button, select, input, textarea").forEach(node => { node.disabled = value; });
        if (resolveMode()) el("branch").disabled = true;
        if (editor) editor.updateOptions({readOnly: value || !active || changes.get(active) === null});
        if (diff) diff.updateOptions({readOnly: true});
    }
    async function run(fn) {
        if (busy) return;
        lock(true);
        try { await fn(); } catch (error) { status(error.message); }
        finally { lock(false); }
    }
    function setView(view, focus = false) {
        el("sidebar").dataset.view = view;
        el("explorer-view").setAttribute("aria-pressed", String(view === "explorer"));
        el("source-view").setAttribute("aria-pressed", String(view === "source"));
        el("search-view").setAttribute("aria-pressed", String(view === "search"));
        if (focus) el(view === "source" ? "message" : view === "search" ? "search-input" : "filter").focus();
    }
    function expandParents(filename) {
        const parts = filename.split("/");
        for (let i = 1; i < parts.length; i++) expanded.add(parts.slice(0, i).join("/") + "/");
    }
    function closeDiff() {
        if (diff) { diff.dispose(); diff = null; }
        if (originalModel) { originalModel.dispose(); originalModel = null; }
        if (deletedModel) { deletedModel.dispose(); deletedModel = null; }
        reviewing = false;
        el("review").setAttribute("aria-pressed", "false");
        el("write").setAttribute("aria-pressed", "true");
    }
    function saveView() {
        if (editor && active) viewStates.set(active, editor.saveViewState());
    }
    function updateLocation() {
        if (!snapshot || resolveMode()) return;
        const url = new URL(location.href);
        url.searchParams.set("branch", snapshot.branch);
        if (active) url.searchParams.set("path", active);
        else if (!single()) url.searchParams.delete("path");
        history.replaceState(null, "", url);
        const back = new URL(root.dataset.base.replace(/\/ide$/, ""), location.origin);
        back.pathname += active ? "/blob/" + encodeURIComponent(snapshot.branch) + "/" + active.split("/").map(encodeURIComponent).join("/") : "/tree/" + encodeURIComponent(snapshot.branch) + "/";
        el("exit").href = back.href;
        el("cancel").href = back.href;
    }
    function show(filename, focus = false) {
        saveView(); closeDiff();
        if (editor) { editor.dispose(); editor = null; }
        active = filename;
        if (filename && !opened.includes(filename)) opened.push(filename);
        el("filename").textContent = filename || "No file open";
        el("empty").hidden = !!filename;
        el("editor").replaceChildren();
        editor = monaco.editor.create(el("editor"), {
            model: filename ? models.get(filename) || null : null,
            theme: document.documentElement.dataset.theme === "light" ? "vs" : "vs-dark",
            automaticLayout: true, minimap: {enabled: false}, fontSize: 14,
            wordWrap: wordWrapPref(),
            scrollBeyondLastLine: false, readOnly: busy || !filename || changes.get(filename) === null
        });
        if (filename && viewStates.has(filename)) editor.restoreViewState(viewStates.get(filename));
        editor.onDidChangeCursorPosition(event => {
            el("cursor").textContent = "Ln " + event.position.lineNumber + ", Col " + event.position.column + " · UTF-8";
        });
        const position = editor.getPosition();
        el("cursor").textContent = position ? "Ln " + position.lineNumber + ", Col " + position.column + " · UTF-8" : "UTF-8";
        if (focus) editor.focus();
        updateLocation(); render(); syncLanguage();
    }
    function model(filename, content) {
        const result = monaco.editor.createModel(content, effectiveLanguage(filename) || undefined,
            monaco.Uri.parse("inmemory://webide/" + filename.split("/").map(encodeURIComponent).join("/")));
        models.set(filename, result);
        result.onDidChangeContent(() => {
            if (changes.get(filename) === null) return;
            const value = result.getValue();
            if (originals.has(filename) && originals.get(filename) === value) changes.delete(filename);
            else changes.set(filename, value);
            render();
        });
        return result;
    }
    function button(text, fn, options = {}) {
        const node = document.createElement("button");
        node.type = "button"; node.textContent = text; node.disabled = busy;
        node.onclick = fn;
        Object.entries(options).forEach(([key, value]) => node.setAttribute(key, value));
        return node;
    }
    function allFiles() {
        return [...new Set([...snapshot.files.map(file => file.path), ...changes.keys()])].sort((a, b) => a.localeCompare(b));
    }
    function explorerIcon(kind) {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("viewBox", "0 0 24 24");
        svg.setAttribute("aria-hidden", "true");
        svg.setAttribute("class", "ide-file-icon ide-icon-" + kind);
        svg.setAttribute("fill", "none");
        svg.setAttribute("stroke", "currentColor");
        svg.setAttribute("stroke-width", "1.5");
        const path = document.createElementNS(svg.namespaceURI, "path");
        path.setAttribute("d", kind === "folder" ? "M3 6h7l2 3h9v11H3zM3 6V4h7l2 2h7v3" :
            kind === "code" ? "M8 3h8l4 4v14H4V3h4M15 3v5h5M9 12l-3 3 3 3m6-6 3 3-3 3" :
            "M4 3h11l5 5v13H4zM14 3v6h6M8 13h8M8 17h6");
        svg.append(path);
        return svg;
    }
    function fileIconKind(filename) {
        return /\.(py|js|jsx|ts|tsx|html|css|sh|sql|java|cs|c|cpp|go|rs|rb|php)$/i.test(filename) ? "code" : "file";
    }
    const EXPLORER_CHUNK = 200;
    const compareEntries = (a, b) =>
        Number(!!b.children) - Number(!!a.children) ||
        a.name.localeCompare(b.name, undefined, {numeric: true, sensitivity: "base"}) ||
        a.name.localeCompare(b.name);
    // Sort each folder's children once per tree build; chunked rendering reads
    // the same order repeatedly as the user scrolls.
    function sortedEntries(entry) {
        if (!entry.sorted) entry.sorted = [...entry.children.values()].sort(compareEntries);
        return entry.sorted;
    }
    function fileEntry(entry) {
        const filename = entry.filename;
        const changed = changes.has(filename), deleted = changes.get(filename) === null;
        const node = button(basename(filename) + (changed ? deleted ? " (deleted)" : " •" : ""),
            () => run(() => open(filename)), {"aria-current": String(active === filename), title: filename, "data-path": filename});
        node.prepend(explorerIcon(fileIconKind(filename)));
        node.classList.toggle("ide-modified", changed);
        node.classList.toggle("ide-deleted", deleted);
        return node;
    }
    function appendChunk(container, entry, query, offset) {
        const entries = sortedEntries(entry);
        const end = Math.min(entries.length, offset + EXPLORER_CHUNK);
        const fragment = document.createDocumentFragment();
        for (let index = offset; index < end; index += 1) {
            const child = entries[index];
            fragment.append(child.children ? folderEntry(child, query) : fileEntry(child));
        }
        container.append(fragment);
        if (end >= entries.length) return;
        let loaded = false;
        function load() {
            if (loaded) return;
            loaded = true;
            more.remove();
            appendChunk(container, entry, query, end);
        }
        const more = button("Show " + (entries.length - end) + " more…", load, {class: "ide-more"});
        container.append(more);
        // Large folders load the next chunk only when the placeholder scrolls
        // into view, so thousands of rows never need DOM nodes up front.
        if (typeof IntersectionObserver === "function") {
            const observer = new IntersectionObserver(records => {
                if (!records.some(record => record.isIntersecting)) return;
                observer.disconnect();
                load();
            }, {rootMargin: "200px 0px"});
            observer.observe(more);
        }
    }
    function folderEntry(entry, query) {
        const key = entry.key;
        const details = document.createElement("details");
        details.open = !!query || expanded.has(key);
        const summary = document.createElement("summary");
        summary.append(explorerIcon("folder"), document.createTextNode(entry.name));
        details.append(summary);
        let loaded = false;
        function load() {
            if (loaded) return;
            loaded = true;
            appendChunk(details, entry, query, 0);
        }
        // Build a folder's contents only when it is actually shown: a collapsed
        // directory must not create thousands of detached nodes.
        if (details.open) load();
        details.addEventListener("toggle", () => {
            if (!details.isConnected) return;
            if (details.open) {
                load();
                if (!query) expanded.add(key);
            } else if (!query) {
                expanded.delete(key);
            }
        });
        return details;
    }
    function renderFiles() {
        const query = el("filter").value.trim().toLowerCase();
        const tree = {children: new Map()};
        allFiles().forEach(filename => {
            if (query && !filename.toLowerCase().includes(query)) return;
            const parts = filename.split("/");
            let node = tree, prefix = "";
            parts.slice(0, -1).forEach(part => {
                prefix += part + "/";
                if (!node.children.has(part + "/")) node.children.set(part + "/", {name: part, key: prefix, children: new Map()});
                node = node.children.get(part + "/");
            });
            node.children.set(basename(filename), {name: basename(filename), filename});
        });
        const fragment = document.createDocumentFragment();
        appendChunk(fragment, tree, query, 0);
        el("files").replaceChildren(fragment);
    }
    function closeTab(filename) {
        const index = opened.indexOf(filename);
        if (index < 0) return;
        opened.splice(index, 1);
        // Closing a tab never discards its changes; Source Control retains them.
        if (active === filename) show(opened[Math.min(index, opened.length - 1)] || null);
        else renderTabs();
    }
    function renderTabs() {
        const fragment = document.createDocumentFragment();
        opened.forEach(filename => {
            const tab = document.createElement("div");
            tab.className = "ide-tab";
            tab.setAttribute("role", "presentation");
            tab.dataset.active = String(active === filename);
            tab.classList.toggle("ide-modified", changes.has(filename));
            const select = button(basename(filename) + (changes.has(filename) ? " •" : ""), () => run(() => open(filename)),
                {role: "tab", "aria-selected": String(active === filename), tabindex: active === filename ? "0" : "-1", title: filename, "data-path": filename});
            select.onkeydown = event => {
                const offset = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
                if (!offset) return;
                event.preventDefault();
                const next = opened[(opened.indexOf(filename) + offset + opened.length) % opened.length];
                run(async () => { await open(next); el("tabs").querySelector('[role="tab"][aria-selected="true"]')?.focus(); });
            };
            const close = button("×", () => { if (!busy) closeTab(filename); }, {"aria-label": "Close " + filename, class: "ide-tab-close"});
            tab.append(select, close); fragment.append(tab);
        });
        el("tabs").replaceChildren(fragment);
    }
    function renderChanges() {
        const fragment = document.createDocumentFragment();
        changes.forEach((value, filename) => {
            const row = document.createElement("div"); row.className = "ide-change";
            const kind = value === null ? "D" : snapshot.files.some(file => file.path === filename) ? "M" : "A";
            const compare = button(kind + " " + filename, () => run(async () => { await open(filename); await review(); }), {title: "View changes to " + filename});
            const discard = button("↶", () => run(async () => {
                if (!confirm("Discard changes to " + filename + "?")) return;
                discardFile(filename); show(active && models.has(active) ? active : null); status("File changes discarded.");
            }), {class: "ide-change-discard", "aria-label": "Discard changes to " + filename});
            row.append(compare, discard); fragment.append(row);
        });
        el("changes").replaceChildren(fragment);
        el("count").textContent = changes.size;
        el("source-count").textContent = changes.size;
        el("change-summary").textContent = changes.size ? changes.size + " changed file(s)" : "No changes";
    }
    let explorerSignature = "";
    function render() {
        if (!snapshot) return;
        // Editing a file fires this on every keystroke; the explorer only needs
        // rebuilding when the visible state (active file / changed set) changes.
        const signature = active + "\u0000" + [...changes.keys()].sort()
            .map(name => name + (changes.get(name) === null ? "\u0001D" : "\u0001M")).join("\u0000");
        if (signature !== explorerSignature) {
            explorerSignature = signature;
            renderFiles();
        }
        renderTabs(); renderChanges();
    }
    async function open(filename) {
        if (changes.get(filename) !== null && !models.has(filename)) {
            const data = await api("file", {branch: snapshot.branch, commit: snapshot.commit, path: filename});
            originals.set(filename, data.content); model(filename, data.content);
        }
        expandParents(filename); show(filename);
        status(changes.get(filename) === null ? "File marked for deletion. Discard its changes to restore it." : changes.size + " pending change(s). Changes are not saved until committed.");
    }
    function clear() {
        closeDiff();
        if (editor) { editor.dispose(); editor = null; }
        models.forEach(value => value.dispose());
        models.clear(); originals.clear(); changes.clear(); viewStates.clear(); opened.length = 0; active = null;
        explorerSignature = "";  // force the explorer to rebuild on the next render
    }
    async function load() {
        clear();
        if (resolveMode()) return loadResolve();
        const next = await api("snapshot", {branch: el("branch").value});
        snapshot = next; expanded.clear();
        if (root.dataset.folder) expandParents(root.dataset.folder + "/placeholder");
        const filename = root.dataset.path;
        if (filename && snapshot.files.some(file => file.path === filename)) await open(filename);
        else if (single()) throw new Error("This file does not exist on the selected branch.");
        else show(null);
        if (!filename) status("Branch " + snapshot.branch + " at " + snapshot.commit.slice(0, 10) + ". Choose a file to edit.");
    }
    async function loadResolve() {
        // Resolve mode rebuilds the workbench from the conflict list instead of
        // a branch snapshot; every conflicted file starts as a pending change.
        const pr = root.dataset.pr;
        const targets = JSON.parse(root.dataset.conflicts || "[]");
        snapshot = {branch: root.dataset.branch, commit: root.dataset.commit, files: []};
        for (const filename of targets) {
            const data = await api("conflict", {pr: pr, branch: snapshot.branch, path: filename});
            if (data.content === null) {
                originals.set(filename, ""); changes.set(filename, null);
            } else {
                originals.set(filename, data.content);
                model(filename, data.content);
                changes.set(filename, data.content);
            }
            opened.push(filename);
        }
        show(targets[0] || null);
        status(targets.length
            ? "Edit every conflicted file until the <<<<<<<, ======= and >>>>>>> markers are gone, then apply the resolution."
            : "No conflicted files remain. Back to the pull request to merge.");
    }
    function discardFile(filename) {
        changes.delete(filename);
        if (originals.has(filename)) {
            if (models.has(filename)) models.get(filename).setValue(originals.get(filename));
            else model(filename, originals.get(filename));
        } else if (models.has(filename)) {
            models.get(filename).dispose(); models.delete(filename);
        }
        if (!snapshot.files.some(file => file.path === filename)) {
            const index = opened.indexOf(filename);
            if (index >= 0) opened.splice(index, 1);
        }
    }
    async function review() {
        if (!active) { status("Select a file to preview changes."); return; }
        if (reviewing) { show(active); return; }
        saveView();
        let original = originals.get(active) || "";
        if (changes.get(active) === null && !originals.has(active)) {
            original = (await api("file", {branch: snapshot.branch, commit: snapshot.commit, path: active})).content;
            originals.set(active, original);
        }
        if (editor) { editor.dispose(); editor = null; }
        closeDiff();
        const language = models.get(active)?.getLanguageId();
        originalModel = monaco.editor.createModel(original, language,
            monaco.Uri.parse("inmemory://webide-original/" + active.split("/").map(encodeURIComponent).join("/")));
        if (changes.get(active) === null) deletedModel = monaco.editor.createModel("", originalModel.getLanguageId());
        diff = monaco.editor.createDiffEditor(el("editor"), {automaticLayout: true, readOnly: true, originalEditable: false,
            wordWrap: wordWrapPref(),
            renderSideBySide: !single() && innerWidth > 800, minimap: {enabled: false}, scrollBeyondLastLine: false});
        diff.setModel({original: originalModel, modified: deletedModel || models.get(active)});
        reviewing = true;
        el("review").setAttribute("aria-pressed", "true"); el("write").setAttribute("aria-pressed", "false");
        status("Previewing changes to " + active + ". Select Write to continue editing.");
    }
    let pickerMode = "files";
    function pickerHeadingLabels() {
        const heading = el("picker").querySelector("label");
        if (heading) heading.textContent = pickerMode === "languages" ? "Select language" : "Go to file";
        el("picker-input").placeholder = pickerMode === "languages" ? "Select a language…" : "Search files by name…";
    }
    function openPicker(mode = "files") {
        if (busy || !snapshot || (single() && mode !== "languages")) return;
        pickerMode = mode;
        pickerHeadingLabels();
        el("picker-input").value = ""; renderPicker();
        el("picker").showModal(); el("picker-input").focus();
    }
    function renderPicker() {
        const query = el("picker-input").value.toLowerCase();
        if (pickerMode === "languages") return renderLanguagePicker(query);
        const results = allFiles().filter(filename => filename.toLowerCase().includes(query)).slice(0, 100);
        el("picker-results").replaceChildren(...results.map(filename => button(filename, () => {
            el("picker").close(); run(() => open(filename));
        })));
    }
    function renderLanguagePicker(query) {
        const current = effectiveLanguage(active);
        const entries = [{id: "", name: "Auto Detect", extensions: [], detected: !languageOverrides.has(active) && !!current,
                          override: false}].concat(
            buildLanguages().map(item => ({...item, detected: !languageOverrides.has(active) && item.id === current,
                                           override: languageOverrides.has(active) && item.id === current}))
        ).filter(item => item.name.toLowerCase().includes(query) || item.id.toLowerCase().includes(query));
        el("picker-results").replaceChildren(...entries.map(item => {
            const label = item.name + (item.id ? " (" + item.id + ")" : "");
            const node = button(label, () => {
                el("picker").close(); run(() => applyLanguage(active, item.id));
            }, {"aria-current": String((item.id || "") === current), title: item.extensions.slice(0, 6).join(" ") || undefined});
            node.setAttribute("data-language", item.id || "auto");
            if (item.detected || item.override) node.classList.add("ide-picker-selected");
            if (item.detected) node.textContent += " · auto-detected";
            if (item.override) node.textContent += " · manual";
            return node;
        }));
    }
    el("branch").onchange = () => {
        if (dirty() && !confirm("Discard all pending changes and switch branches?")) { el("branch").value = snapshot.branch; return; }
        run(async () => {
            try { await load(); } catch (error) { if (snapshot) el("branch").value = snapshot.branch; throw error; }
        });
    };
    el("explorer-view").onclick = () => setView("explorer");
    el("search-view").onclick = () => setView("search", true);
    el("source-view").onclick = el("show-changes").onclick = () => setView("source");
    el("filter").oninput = renderFiles;
    el("collapse").onclick = () => { el("filter").value = ""; expanded.clear(); renderFiles(); };
    el("search-form").onsubmit = event => {
        event.preventDefault();
        run(async () => {
            const query = el("search-input").value;
            if (!query.trim()) return;
            el("search-results").replaceChildren();
            el("search-status").textContent = "Searching…";
            let response;
            try { response = await api("search", {branch: snapshot.branch, commit: snapshot.commit, q: query}); }
            catch (error) { el("search-status").textContent = error.message; throw error; }
            const results = response.results.filter(result => !changes.has(result.path));
            const needle = query.toLowerCase();
            let pendingTruncated = false;
            for (const [filename, content] of changes) {
                if (content === null) continue;
                const lines = content.split(/\r\n|\r|\n/);
                for (let i = 0; i < lines.length; i++) {
                    if (!lines[i].toLowerCase().includes(needle)) continue;
                    if (results.length >= 200) { pendingTruncated = true; break; }
                    results.push({path: filename, line: i + 1, text: lines[i].slice(0, 300)});
                }
            }
            results.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
            results.slice(0, 200).forEach(result => {
                const node = button("", () => run(async () => {
                    await open(result.path);
                    editor.setPosition({lineNumber: result.line, column: 1});
                    editor.revealLineInCenter(result.line); editor.focus();
                }), {"data-path": result.path, "data-line": result.line});
                const name = document.createElement("strong"); name.textContent = result.path + ":" + result.line;
                const text = document.createElement("span"); text.textContent = result.text;
                node.append(name, text); el("search-results").append(node);
            });
            el("search-status").textContent = results.length + " matching line(s)." +
                (response.truncated || pendingTruncated ? " Results limited; narrow your search." : "");
        });
    };
    el("quick-open").onclick = openPicker;
    el("picker-input").oninput = renderPicker;
    el("picker-input").onkeydown = event => {
        if (event.key === "Enter" || event.key === "ArrowDown") {
            event.preventDefault();
            const first = el("picker-results").querySelector("button");
            if (event.key === "Enter") first?.click(); else first?.focus();
        }
    };
    el("expand") && (el("expand").onclick = event => {
        event.preventDefault();
        if (busy) return;
        root.dataset.mode = "workspace";
        root.querySelector(".ide-mode-label").textContent = "Web IDE";
        const url = new URL(el("expand").href);
        if (active) url.searchParams.set("path", active);
        if (snapshot) url.searchParams.set("branch", snapshot.branch);
        // Switch layouts without navigating: the model, undo history and edits survive.
        history.replaceState(null, "", url); render(); editor?.layout(); diff?.layout();
    });
    function addFile(filename) {
        if (!validPath(filename)) throw new Error("Invalid path.");
        if (allFiles().some(existing => existing === filename || existing.startsWith(filename + "/") || filename.startsWith(existing + "/"))) {
            throw new Error("That path already exists or conflicts with an existing file or folder.");
        }
        model(filename, ""); changes.set(filename, ""); expandParents(filename); show(filename);
    }
    el("new") && (el("new").onclick = () => run(async () => {
        const filename = prompt("New file path (relative to repository root):", root.dataset.folder ? root.dataset.folder + "/" : "");
        if (!filename) return;
        addFile(filename); status("New file added to pending changes.");
    }));
    el("explorer-new") && (el("explorer-new").onclick = () => el("new").click());
    el("new-folder") && (el("new-folder").onclick = () => run(async () => {
        const answer = prompt("New folder path (relative to repository root). A .gitkeep file will be added because Git does not track empty folders:", root.dataset.folder ? root.dataset.folder + "/" : "");
        if (!answer) return;
        const folder = answer.replace(/\/$/, "");
        if (!validPath(folder)) throw new Error("Invalid folder path.");
        if (allFiles().some(existing => existing === folder || existing.startsWith(folder + "/"))) throw new Error("That file or folder already exists.");
        addFile(folder + "/.gitkeep");
        status("New folder " + folder + " added with .gitkeep. Commit to save it, or discard its changes to remove it.");
    }));
    el("delete").onclick = () => run(async () => {
        if (!active || !confirm("Mark " + active + " for deletion?")) return;
        // Resolve mode keeps a model so the file stays visible and can be restored.
        if (resolveMode() || snapshot.files.some(file => file.path === active)) changes.set(active, null);
        else { discardFile(active); active = null; }
        show(active); status("Deletion is pending until committed.");
    });
    el("discard-file").onclick = () => run(async () => {
        if (!active || !changes.has(active) || !confirm("Discard changes to " + active + "?")) return;
        const filename = active; discardFile(filename); show(models.has(filename) ? filename : null); status("File changes discarded.");
    });
    el("discard").onclick = () => run(async () => {
        if (!dirty() || !confirm("Discard ALL pending changes? This cannot be undone.")) return;
        [...changes.keys()].forEach(discardFile); show(active && models.has(active) ? active : null);
        status("All pending changes discarded. Repository is unchanged.");
    });
    el("write").onclick = () => run(async () => { if (active) show(active, true); });
    el("review").onclick = () => run(review);
    el("language") && (el("language").onclick = () => openPicker("languages"));
    el("wrap") && (el("wrap").onclick = async () => {
        const on = wordWrapPref() ? "off" : "on";
        try { localStorage.setItem("pygithost_ide_wrap", on); } catch { /* private mode */ }
        if (editor) editor.updateOptions({wordWrap: on});
        if (diff) diff.updateOptions({wordWrap: on});
        syncWrap();
        status("Word wrap " + (on === "on" ? "enabled. Hard-wrapped lines are display-only; the saved text is unchanged." : "disabled."));
    });
    el("commit").onsubmit = event => {
        event.preventDefault();
        run(async () => {
            if (!dirty()) throw new Error("No pending changes.");
            if (resolveMode()) {
                // The resolver expects every conflicted file as a pending change.
                const result = await api("commit", {}, {branch: snapshot.branch, base: snapshot.commit,
                    message: el("message").value, changes: Object.fromEntries(changes)}, root.dataset.commitUrl);
                el("message").value = "";
                changes.clear(); render();
                status("Resolution committed to " + snapshot.branch + (result.warning ? ". " + result.warning : "") + ". Returning to the pull request…");
                setTimeout(() => { location.href = root.dataset.return; }, 800);
                return;
            }
            const wasReviewing = reviewing;
            const result = await api("commit", {}, {branch: snapshot.branch, base: snapshot.commit,
                message: el("message").value, changes: Object.fromEntries(changes)});
            // Only confirmed Git commits clear pending changes. Keep open tabs/models.
            const committedFiles = new Map(snapshot.files.map(file => [file.path, file]));
            const deleted = [];
            changes.forEach((value, filename) => {
                if (value === null) { committedFiles.delete(filename); deleted.push(filename); }
                else { committedFiles.set(filename, {path: filename}); originals.set(filename, value); }
            });
            changes.clear(); snapshot.commit = result.commit; snapshot.files = [...committedFiles.values()];
            deleted.forEach(filename => {
                models.get(filename)?.dispose(); models.delete(filename); originals.delete(filename);
                const index = opened.indexOf(filename); if (index >= 0) opened.splice(index, 1);
            });
            show(active && !deleted.includes(active) ? active : opened[0] || null);
            if (wasReviewing && active) await review();
            el("message").value = "";
            status("Committed " + result.commit.slice(0, 12) + " to " + snapshot.branch + "." + (result.warning ? " " + result.warning : ""));
        });
    };
    document.addEventListener("keydown", event => {
        if (!(event.ctrlKey || event.metaKey || event.altKey)) return;
        const key = event.key.toLowerCase();
        if (key === "z" && event.altKey) { event.preventDefault(); event.stopPropagation(); el("wrap")?.click(); }
        if ((event.ctrlKey || event.metaKey) && event.altKey) return;
        if (key === "p" && !event.shiftKey && !single()) { event.preventDefault(); event.stopPropagation(); openPicker(); }
        if (key === "s" && !event.shiftKey) { event.preventDefault(); event.stopPropagation(); status("Edits are held in this tab. Use Source Control to commit them to Git when ready."); }
        if (event.shiftKey && (key === "e" || key === "g" || key === "f") && !single()) { event.preventDefault(); setView(key === "e" ? "explorer" : key === "f" ? "search" : "source", true); }
    }, true);
    window.addEventListener("beforeunload", event => {
        if (dirty()) { event.preventDefault(); event.returnValue = ""; }
    });
    new MutationObserver(() => {
        if (window.monaco) monaco.editor.setTheme(document.documentElement.dataset.theme === "light" ? "vs" : "vs-dark");
    }).observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
    if (!window.require) { status("Monaco failed to load. Reload this page."); return; }
    lock(true);
    require.config({paths: {vs: new URL("/static/vendor/monaco/vs", location.origin).href}});
    require(["vs/editor/editor.main"], () => {
        buildLanguages(); syncWrap();
        lock(false); run(load);
    }, error => { lock(false); status("Unable to load Monaco: " + error); });
})();
