/* Toast UI Markdown editors (comment/issue forms) and stored-markdown rendering. */
(function () {
    "use strict";

    const isDark = () => document.documentElement.dataset.theme === "dark";

    function mdBodyValue(node) {
        // GitHub-style rendering: stored Markdown -> sanitized HTML. The Toast UI
        // viewer runs DOMPurify over raw HTML fragments before injection. The
        // full viewer tree is kept in place (not re-parented) so its styles —
        // image/table/code block rules under .toastui-editor-contents — apply.
        const source = node.textContent;
        if (!source.trim()) return;
        const factory = window.toastui.Editor.factory;
        // GitHub keeps single newlines in comments; GFM hard breaks read the same.
        const normalized = source.replace(/([^\n])\n(?!\n|$)/g, "$1  \n");
        // Older versions clipped bodies at 50,000 characters, cutting data-URL
        // images in half. That markup cannot be parsed as an image, so show a
        // short note instead of dumping tens of thousands of base64 chars.
        const cleaned = normalized.replace(/!\[([^\]\n]{0,200})\]\(data:[^\n)]*$/gm,
            (match, alt) => "_(image " + (alt || "upload") + " unavailable: it was stored incompletely — please upload it again)_");
        const holder = document.createElement("div");
        holder.classList.add("markdown-render-target");
        node.replaceChildren(holder);
        factory({el: holder, viewer: true, initialValue: cleaned});
        applyTheme();
    }

    function mountEditors() {
        document.querySelectorAll("form textarea[data-markdown]").forEach(textarea => {
            const form = textarea.closest("form");
            if (textarea.dataset.mdEditor === "1" || !form) return;
            if (!(window.toastui && window.toastui.Editor)) return;
            textarea.dataset.mdEditor = "1";
            const holder = document.createElement("div");
            holder.className = "markdown-editor-holder";
            textarea.hidden = true;
            textarea.insertAdjacentElement("afterend", holder);
            const editor = new window.toastui.Editor({
                el: holder, height: "240px", initialEditType: "markdown",
                previewStyle: "tab", usageStatistics: false, hideModeSwitch: true,
                initialValue: textarea.value || "",
                extendedAutolinks: true,
                linkAttribute: {rel: "noreferrer noopener", target: "_blank"},
                hooks: {
                    // Toolbar image (upload) button: images embed as data URLs.
                    // Oversize images are resized (scaled down, lossy) after a
                    // confirmation, then inserted as a normal Markdown image so
                    // the inline preview matches the saved comment exactly.
                    // The data URL must also fit the server's stored-body cap
                    // (MARKDOWN_BODY_LIMIT = 1,000,000 characters); exceeding it
                    // truncates the Markdown and breaks the image.
                    addImageBlobHook: (blob, callback) => {
                        const maxImage = 512 * 1024;
                        const maxBody = 1000000;
                        const name = (blob.name || "image").replace(/\.[a-zA-Z0-9]+$/, "");
                        const current = editor ? editor.getMarkdown().length : 0;
                        // Room left for `![name](…)` in the stored body.
                        const budget = Math.max(0, maxBody - current - name.length - 8);
                        const limit = Math.min(maxImage, budget);
                        if (limit < 2048) {
                            alert("This comment is too long to fit another image.");
                            return false;
                        }
                        const reader = new FileReader();
                        reader.onerror = () => alert("The image could not be read.");
                        reader.onload = () => {
                            const insert = dataUrl => callback(dataUrl, name);
                            if (reader.result.length <= limit) { insert(reader.result); return; }
                            const reason = reader.result.length > maxImage
                                ? "This image is about " + Math.round(blob.size / 1024) + " KiB — above the 512 KiB inline limit."
                                : "There is not enough room left in this comment for the full image.";
                            if (!confirm(reason + "\n\nResizing is lossy (it will be scaled down to fit). Continue with resizing?")) {
                                return false;
                            }
                            const probe = new Image();
                            probe.onerror = () => { alert("The image could not be resized; it was not inserted."); };
                            probe.onload = () => {
                                const canvas = document.createElement("canvas");
                                const type = blob.type === "image/png" ? "image/png" : "image/jpeg";
                                // Encoded bytes scale with area; estimate the
                                // needed scale, then halve until it fits.
                                let scale = Math.min(1, Math.sqrt(limit / reader.result.length));
                                let dataUrl = "";
                                for (let attempts = 0; attempts < 10; attempts += 1, scale /= 2) {
                                    canvas.width = Math.max(1, Math.round(probe.width * scale));
                                    canvas.height = Math.max(1, Math.round(probe.height * scale));
                                    canvas.getContext("2d").drawImage(probe, 0, 0, canvas.width, canvas.height);
                                    dataUrl = canvas.toDataURL(type, 0.92);
                                    if (dataUrl.length <= limit) break;
                                }
                                if (dataUrl.length > limit) {
                                    alert("The image is still too large after resizing; it was not inserted.");
                                    return;
                                }
                                insert(dataUrl);
                            };
                            probe.src = reader.result;
                        };
                        reader.readAsDataURL(blob);
                        return true;
                    },
                },
            });
            textarea._toastEditor = editor;
            // The hidden textarea keeps `required` for no-JS only — it would
            // silently block submission because Chrome cannot focus it for the
            // balloon; the server re-validates empty bodies anyway.
            textarea.removeAttribute("required");
            form.addEventListener("submit", () => { textarea.value = editor.getMarkdown(); });
            applyTheme();
        });
    }

    function applyTheme() {
        const dark = isDark();
        document.querySelectorAll(".toastui-editor-defaultUI").forEach(node => {
            node.classList.toggle("toastui-editor-dark", dark);
        });
        // `Editor.factory({viewer: true})` renders into our own container and
        // does not add `.toastui-editor-defaultUI`, so the dark theme class
        // must be set on the render target itself — otherwise stored Markdown
        // keeps the light `#222` text on a dark background.
        document.querySelectorAll(".md-body .markdown-render-target").forEach(node => {
            node.classList.toggle("toastui-editor-dark", dark);
        });
    }

    new MutationObserver(applyTheme).observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});

    function boot() {
        document.querySelectorAll(".md-body:not([data-rendered])").forEach(node => {
            node.dataset.rendered = "1";
            try { mdBodyValue(node); } catch (error) { console.error("Markdown rendering failed", error); }
        });
        mountEditors();
        applyTheme();
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
    else boot();
})();
