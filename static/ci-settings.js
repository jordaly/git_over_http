/* Progressive enhancement: the named textarea remains the submitted value. */
(function () {
    "use strict";
    const textarea = document.getElementById("ci-config-json");
    const container = document.getElementById("ci-config-editor");
    const status = document.getElementById("ci-editor-status");
    const format = document.getElementById("ci-format-json");
    if (!textarea || !container) return;
    function fallback(error) {
        textarea.hidden = false; container.hidden = true; format.hidden = true;
        status.textContent = "Monaco could not load. You can still edit and save the JSON below.";
    }
    if (!window.require) { fallback(); return; }
    require.config({paths: {vs: new URL("/static/vendor/monaco/vs", location.origin).href}});
    require(["vs/editor/editor.main"], function () {
        let editor;
        try {
            // Strict JSON syntax errors should appear immediately, even while
            // Monaco's optional worker/language services are still starting.
            monaco.languages.json.jsonDefaults.setModeConfiguration({
                ...monaco.languages.json.jsonDefaults.modeConfiguration, diagnostics: false
            });
            const model = monaco.editor.createModel(textarea.value, "json",
                monaco.Uri.parse("inmemory://ci-settings/configuration.json"));
            container.hidden = false;
            editor = monaco.editor.create(container, {
                model, language: "json", automaticLayout: true,
                theme: document.documentElement.dataset.theme === "light" ? "vs" : "vs-dark",
                minimap: {enabled: false}, fontSize: 14, tabSize: 2,
                insertSpaces: true, scrollBeyondLastLine: false,
                ariaLabel: "CI configuration JSON"
            });
            // Sync on every edit so the existing save/validation/retention handlers
            // always receive the current value, including programmatic submits.
            function validateSyntax() {
                const markers = [];
                try { JSON.parse(model.getValue()); }
                catch (error) {
                    const offset = /at position (\d+)/.exec(error.message);
                    const position = model.getPositionAt(offset ? Number(offset[1]) : model.getValueLength());
                    markers.push({severity: monaco.MarkerSeverity.Error, message: error.message,
                        startLineNumber: position.lineNumber, endLineNumber: position.lineNumber,
                        startColumn: position.column, endColumn: position.column + 1});
                }
                monaco.editor.setModelMarkers(model, "ci-json-syntax", markers);
            }
            model.onDidChangeContent(function () {
                textarea.value = model.getValue();
                validateSyntax();
                status.textContent = new TextEncoder().encode(textarea.value).length > 262144 ?
                    "Configuration exceeds the 256 KiB limit." : "JSON editor · Ctrl/⌘+S to save configuration";
            });
            validateSyntax();
            textarea.hidden = true; format.hidden = false;
            status.textContent = "JSON editor · Ctrl/⌘+S to save configuration";
            document.getElementById("ci-config-label").onclick = event => { event.preventDefault(); editor.focus(); };
            format.onclick = () => {
                try {
                    const source = model.getValue();
                    if (new TextEncoder().encode(source).length > 262144) throw new Error("Configuration exceeds 256 KiB.");
                    JSON.parse(source);
                    // Format tokens rather than reserializing parsed values:
                    // preserve duplicate keys and large numeric literals for
                    // authoritative server validation. No worker is required.
                    const tokens = source.match(/"(?:\\.|[^"\\])*"|[{}\[\],:]|[^\s{}\[\],:]+/g);
                    const output = [];
                    let depth = 0;
                    const newline = () => output.push("\n" + "  ".repeat(depth));
                    tokens.forEach((token, index) => {
                        if (token === "{" || token === "[") {
                            output.push(token); depth++;
                            if (depth > 100) throw new Error("JSON nesting exceeds 100 levels.");
                            if (tokens[index + 1] !== (token === "{" ? "}" : "]")) newline();
                        } else if (token === "}" || token === "]") {
                            depth--;
                            if (tokens[index - 1] !== (token === "}" ? "{" : "[")) newline();
                            output.push(token);
                        } else if (token === ",") { output.push(token); newline(); }
                        else output.push(token === ":" ? ": " : token);
                    });
                    const formatted = output.join("");
                    if (new TextEncoder().encode(formatted).length > 262144) {
                        throw new Error("Formatted JSON would exceed 256 KiB.");
                    }
                    editor.pushUndoStop();
                    editor.executeEdits("format-json", [{range: model.getFullModelRange(), text: formatted}]);
                    editor.pushUndoStop();
                } catch (error) {
                    status.textContent = "Cannot format JSON: " + error.message;
                }
            };
            editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => textarea.form.requestSubmit());
            new MutationObserver(() => monaco.editor.setTheme(
                document.documentElement.dataset.theme === "light" ? "vs" : "vs-dark"
            )).observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
            window.addEventListener("pagehide", event => {
                if (!event.persisted) { editor.dispose(); model.dispose(); }
            }, {once: true});
        } catch (error) {
            if (editor) editor.dispose();
            fallback(error);
        }
    }, fallback);
})();
