/* Pull request "Files changed" interactions.
 * Markup is produced by pygithost/diffview.py. No dependencies, no build step.
 */
(function () {
  "use strict";

  var MODE_KEY = "pygithost_diff_mode";
  var HIGHLIGHT_MAX_LINES = 1500;
  var PRISM_BASE = "/static/assets/prismjs/components";
  var PRISM_DEPS = {
    c: ["clike"],
    cpp: ["c"],
    csharp: ["clike"],
    cshtml: ["markup", "csharp"],
    dart: ["clike"],
    fsharp: ["clike"],
    go: ["clike"],
    groovy: ["clike"],
    java: ["clike"],
    javascript: ["clike"],
    json5: ["json"],
    jsx: ["markup", "javascript"],
    kotlin: ["clike"],
    less: ["css"],
    markdown: ["markup"],
    "markup-templating": ["markup"],
    objectivec: ["c"],
    php: ["markup-templating"],
    plsql: ["sql"],
    protobuf: ["clike"],
    ruby: ["clike"],
    sass: ["css"],
    scala: ["java"],
    scss: ["css"],
    tsx: ["jsx", "typescript"],
    typescript: ["javascript"],
    vbnet: ["basic"]
  };

  function storageGet(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function storageSet(key, value) {
    try { window.localStorage.setItem(key, value); } catch (e) { /* ignore */ }
  }

  function closest(el, selector) {
    return el && el.closest ? el.closest(selector) : null;
  }

  function fileOf(el) { return closest(el, "details.diff-file"); }

  function isSplit(details) {
    return !!(details && details.querySelector("table.diff-split"));
  }

  /* ---------------------------------------------------------- diff mode */
  function modeFromHref(href) {
    try { return new URL(href, window.location.href).searchParams.get("diff"); } catch (e) { return null; }
  }

  function maybeRedirectToStoredMode(root) {
    var params;
    try { params = new URL(window.location.href).searchParams; } catch (e) { return false; }
    if (params.has("diff")) return false;
    var stored = storageGet(MODE_KEY);
    var rendered = root.getAttribute("data-mode") || "";
    if ((stored === "split" || stored === "unified") && rendered && stored !== rendered) {
      var url = new URL(window.location.href);
      url.searchParams.set("diff", stored);
      window.location.replace(url.toString());
      return true;
    }
    return false;
  }

  /* ---------------------------------------------------------- viewed */
  function updateViewedCount(root) {
    var counter = document.getElementById("pr-viewed-count");
    if (!counter) return;
    var boxes = root.querySelectorAll("input.diff-viewed");
    var checked = 0;
    for (var i = 0; i < boxes.length; i++) if (boxes[i].checked) checked++;
    counter.textContent = checked + " / " + boxes.length + " files viewed";
  }

  function markTree(path, viewed) {
    var items = document.querySelectorAll(".diff-tree-file");
    for (var i = 0; i < items.length; i++) {
      if (items[i].getAttribute("data-path") === path) items[i].classList.toggle("is-viewed", viewed);
    }
  }

  function postViewed(root, box) {
    var url = root.getAttribute("data-viewed-url");
    var details = fileOf(box);
    var path = box.getAttribute("data-path") || "";
    var viewed = box.checked;
    var apply = function (state) {
      box.checked = state;
      if (details) {
        details.classList.toggle("is-viewed", state);
        if (state) details.open = false;
      }
      markTree(path, state);
      updateViewedCount(root);
    };
    apply(viewed);
    if (!url) return;
    box.disabled = true;
    var body = new URLSearchParams();
    body.set("path", path);
    body.set("viewed", viewed ? "1" : "0");
    body.set("csrf", root.getAttribute("data-csrf") || "");
    fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    }).then(function (response) {
      if (!response.ok) throw new Error("HTTP " + response.status);
    }).catch(function () {
      apply(!viewed);
      if (details && viewed) details.open = true;
    }).then(function () {
      box.disabled = false;
    });
  }

  function onViewedClick(root, event) {
    var label = closest(event.target, ".diff-viewed-label");
    if (!label) return false;
    var box = label.querySelector("input.diff-viewed");
    if (!box || box.disabled) { event.preventDefault(); return true; }
    // Cancel the click so the surrounding <summary> does not toggle the <details>.
    // When the checkbox itself was clicked, the browser has already flipped it and
    // will revert it after the cancelled dispatch, so compute the target state now.
    var desired = event.target === box ? box.checked : !box.checked;
    event.preventDefault();
    event.stopPropagation();
    window.setTimeout(function () {
      box.checked = desired;
      postViewed(root, box);
    }, 0);
    return true;
  }

  /* ---------------------------------------------------------- comments */
  var formState = new WeakMap(); // details -> {row, side, start, end}

  function lineRow(details, side, line) {
    var cells = details.querySelectorAll('td.diff-num[data-side="' + side + '"][data-line="' + line + '"]');
    return cells.length ? closest(cells[0], "tr") : null;
  }

  function clearSelection(details) {
    var rows = details.querySelectorAll("tr.diff-selected");
    for (var i = 0; i < rows.length; i++) rows[i].classList.remove("diff-selected");
  }

  function highlightRange(details, side, start, end) {
    clearSelection(details);
    var cells = details.querySelectorAll('td.diff-num[data-side="' + side + '"][data-line]');
    for (var i = 0; i < cells.length; i++) {
      var n = parseInt(cells[i].getAttribute("data-line"), 10);
      if (n >= start && n <= end) {
        var row = closest(cells[i], "tr");
        if (row) row.classList.add("diff-selected");
      }
    }
  }

  function closeNewForm(details) {
    var state = formState.get(details);
    if (state && state.row && state.row.parentNode) state.row.parentNode.removeChild(state.row);
    formState.delete(details);
    clearSelection(details);
  }

  function setField(form, name, value) {
    var input = form.querySelector('input[name="' + name + '"]');
    if (input) input.value = value;
  }

  function placeFormRow(row, anchorRow) {
    var after = anchorRow;
    while (after.nextElementSibling && after.nextElementSibling.classList.contains("diff-thread-row")) {
      after = after.nextElementSibling;
    }
    after.parentNode.insertBefore(row, after.nextSibling);
  }

  function buildFormRow(details, side) {
    var template = document.getElementById("diff-comment-template");
    if (!template || !template.content) return null;
    var row = document.createElement("tr");
    row.className = "diff-form-row";
    var cell = document.createElement("td");
    cell.className = "diff-form-cell";
    cell.appendChild(template.content.cloneNode(true));
    if (isSplit(details)) {
      cell.colSpan = 2;
      var empty = document.createElement("td");
      empty.colSpan = 2;
      empty.className = "diff-thread-empty";
      if (side === "LEFT") { row.appendChild(cell); row.appendChild(empty); }
      else { row.appendChild(empty); row.appendChild(cell); }
    } else {
      cell.colSpan = 3;
      row.appendChild(cell);
    }
    return row;
  }

  function onAddComment(button, event) {
    var details = fileOf(button);
    if (!details) return;
    var side = button.getAttribute("data-side");
    var line = parseInt(button.getAttribute("data-line"), 10);
    if (!side || isNaN(line)) return;
    var state = formState.get(details);
    var start = line;
    var end = line;
    var row;
    if (event.shiftKey && state && state.side === side && state.row && state.row.parentNode) {
      start = Math.min(state.anchor, line);
      end = Math.max(state.anchor, line);
      row = state.row;
    } else {
      closeNewForm(details);
      row = buildFormRow(details, side);
      if (!row) return;
      state = { row: row, side: side, anchor: line };
    }
    var anchorRow = lineRow(details, side, end) || closest(button, "tr");
    if (!anchorRow) return;
    placeFormRow(row, anchorRow);
    state.start = start;
    state.end = end;
    formState.set(details, state);
    var form = row.querySelector("form");
    if (form) {
      setField(form, "path", details.getAttribute("data-path") || "");
      setField(form, "side", side);
      setField(form, "line", String(end));
      setField(form, "start_line", start < end ? String(start) : "");
      setField(form, "start_side", start < end ? side : "");
    }
    highlightRange(details, side, start, end);
    var textarea = row.querySelector("textarea");
    if (textarea) textarea.focus();
  }

  function lineText(details, side, n) {
    var cell = details.querySelector('td.diff-code-cell[data-side="' + side + '"][data-line="' + n + '"]');
    if (!cell) return null;
    if (cell.hasAttribute("data-text")) return cell.getAttribute("data-text");
    var code = cell.querySelector("code.diff-code");
    return code ? code.textContent : "";
  }

  function onInsertSuggestion(button) {
    var form = closest(button, "form");
    var details = fileOf(button);
    if (!form || !details) return;
    var textarea = form.querySelector("textarea");
    if (!textarea) return;
    var sideInput = form.querySelector('input[name="side"]');
    var lineInput = form.querySelector('input[name="line"]');
    var startInput = form.querySelector('input[name="start_line"]');
    var side = sideInput && sideInput.value ? sideInput.value : "RIGHT";
    var end = lineInput ? parseInt(lineInput.value, 10) : NaN;
    var start = startInput && startInput.value ? parseInt(startInput.value, 10) : end;
    var lines = [];
    if (!isNaN(end)) {
      for (var n = start; n <= end; n++) {
        var text = lineText(details, side, n);
        if (text !== null) lines.push(text);
      }
    }
    var block = "```suggestion\n" + lines.join("\n") + "\n```";
    var pos = textarea.selectionStart || 0;
    var before = textarea.value.slice(0, pos);
    if (before && before.charAt(before.length - 1) !== "\n") block = "\n" + block;
    if (typeof textarea.setRangeText === "function") {
      textarea.setRangeText(block, pos, textarea.selectionEnd || pos, "end");
    } else {
      textarea.value = before + block + textarea.value.slice(textarea.selectionEnd || pos);
    }
    textarea.focus();
  }

  function onCancel(button) {
    var replyForm = closest(button, ".diff-reply-form");
    if (replyForm) {
      replyForm.hidden = true;
      var container = replyForm.parentElement;
      var toggle = container ? container.querySelector(".diff-reply-toggle") : null;
      if (toggle) { toggle.hidden = false; toggle.setAttribute("aria-expanded", "false"); toggle.focus(); }
      return;
    }
    var details = fileOf(button);
    if (details && closest(button, "tr.diff-form-row")) {
      closeNewForm(details);
      return;
    }
    var form = closest(button, "form");
    if (form) form.hidden = true;
  }

  function onReplyToggle(button) {
    var container = button.parentElement;
    var form = null;
    var sibling = button.nextElementSibling;
    while (sibling) {
      if (sibling.classList.contains("diff-reply-form")) { form = sibling; break; }
      sibling = sibling.nextElementSibling;
    }
    if (!form && container) form = container.querySelector(".diff-reply-form");
    if (!form) return;
    form.hidden = !form.hidden;
    button.setAttribute("aria-expanded", form.hidden ? "false" : "true");
    if (!form.hidden) {
      button.hidden = true;
      var textarea = form.querySelector("textarea");
      if (textarea) textarea.focus();
    }
  }

  /* ---------------------------------------------------------- large diffs */
  function onLoadDiff(button) {
    var holder = closest(button, ".diff-large");
    if (!holder) return;
    var template = holder.querySelector("template");
    if (!template || !template.content) return;
    holder.parentNode.replaceChild(template.content.cloneNode(true), holder);
  }

  /* ---------------------------------------------------------- tree filter */
  function filterTree(input, root) {
    var query = (input.value || "").trim().toLowerCase();
    var tree = closest(input, ".diff-tree") || document;
    var items = tree.querySelectorAll(".diff-tree-file");
    var visible = {};
    var any = false;
    for (var i = 0; i < items.length; i++) {
      var path = items[i].getAttribute("data-path") || "";
      var match = !query || path.toLowerCase().indexOf(query) !== -1;
      items[i].hidden = !match;
      if (match) { visible[path] = true; any = true; }
    }
    var dirs = Array.prototype.slice.call(tree.querySelectorAll(".diff-tree-dir")).reverse();
    for (var j = 0; j < dirs.length; j++) {
      dirs[j].hidden = !dirs[j].querySelector(".diff-tree-file:not([hidden])");
    }
    var empty = tree.querySelector(".diff-tree-empty");
    if (empty) empty.hidden = any;
    if (root) {
      var files = root.querySelectorAll("details.diff-file");
      for (var k = 0; k < files.length; k++) {
        files[k].hidden = !!query && !visible[files[k].getAttribute("data-path") || ""];
      }
    }
  }

  /* ---------------------------------------------------------- Prism */
  var scriptPromises = {};
  function loadScript(src) {
    if (!scriptPromises[src]) {
      scriptPromises[src] = new Promise(function (resolve, reject) {
        var script = document.createElement("script");
        script.src = src;
        script.async = false;
        script.onload = function () { resolve(); };
        script.onerror = function () {
          script.remove();
          delete scriptPromises[src];
          reject(new Error("Failed to load " + src));
        };
        document.head.appendChild(script);
      });
    }
    return scriptPromises[src];
  }

  function ensureCore() {
    if (window.Prism && window.Prism.highlightElement) return Promise.resolve();
    window.Prism = window.Prism || {};
    window.Prism.manual = true;
    return loadScript(PRISM_BASE + "/prism-core.min.js");
  }

  var languagePromises = {};
  function loadLanguage(lang) {
    if (window.Prism && window.Prism.languages && window.Prism.languages[lang]) return Promise.resolve();
    if (!languagePromises[lang]) {
      var deps = PRISM_DEPS[lang] || [];
      languagePromises[lang] = deps.reduce(function (chain, dep) {
        return chain.then(function () { return loadLanguage(dep); });
      }, Promise.resolve()).then(function () {
        return loadScript(PRISM_BASE + "/prism-" + lang + ".min.js");
      });
      languagePromises[lang].catch(function () { delete languagePromises[lang]; });
    }
    return languagePromises[lang];
  }

  function highlightFile(details) {
    if (details.getAttribute("data-highlighted")) return;
    var lang = details.getAttribute("data-lang");
    var lines = parseInt(details.getAttribute("data-lines") || "0", 10);
    if (!lang || lang === "none" || lines > HIGHLIGHT_MAX_LINES) return;
    if (!details.querySelector("table.diff-table")) return;
    details.setAttribute("data-highlighted", "pending");
    ensureCore().then(function () { return loadLanguage(lang); }).then(function () {
      if (!window.Prism || !window.Prism.languages[lang]) throw new Error("unavailable");
      var codes = Array.prototype.slice.call(details.querySelectorAll("table.diff-table code.diff-code"));
      var index = 0;
      (function batch() {
        try {
          var stop = Math.min(index + 200, codes.length);
          for (; index < stop; index++) {
            codes[index].className = "diff-code language-" + lang;
            window.Prism.highlightElement(codes[index]);
          }
        } catch (e) { return; }
        if (index < codes.length) window.setTimeout(batch, 0);
      })();
      details.setAttribute("data-highlighted", "done");
    }).catch(function () {
      details.setAttribute("data-highlighted", "failed");
    });
  }

  function setupHighlighting(root) {
    var files = root.querySelectorAll("details.diff-file[data-lang]");
    if (!files.length) return;
    if (!("IntersectionObserver" in window)) return;
    var observer = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        var details = entries[i].target;
        details._diffVisible = entries[i].isIntersecting;
        if (entries[i].isIntersecting && details.open) highlightFile(details);
      }
    }, { rootMargin: "400px 0px" });
    for (var i = 0; i < files.length; i++) {
      if (files[i].getAttribute("data-lang")) {
        observer.observe(files[i]);
        files[i].addEventListener("toggle", function (event) {
          var details = event.currentTarget;
          if (details.open && details._diffVisible) highlightFile(details);
        });
      }
    }
  }

  /* ---------------------------------------------------------- init */
  function init() {
    var root = document.getElementById("pr-files");
    if (!root) return;
    if (maybeRedirectToStoredMode(root)) return;

    document.addEventListener("click", function (event) {
      var target = event.target;
      if (!(target instanceof Element)) return;
      if (root.contains(target) && onViewedClick(root, event)) return;

      var el;
      if ((el = closest(target, "a.diff-mode-link"))) {
        var mode = modeFromHref(el.getAttribute("href") || "");
        if (mode === "split" || mode === "unified") storageSet(MODE_KEY, mode);
        return;
      }
      if ((el = closest(target, "button.diff-add-comment"))) { event.preventDefault(); onAddComment(el, event); return; }
      if ((el = closest(target, "button.diff-insert-suggestion"))) { event.preventDefault(); onInsertSuggestion(el); return; }
      if ((el = closest(target, "button.diff-cancel"))) { event.preventDefault(); onCancel(el); return; }
      if ((el = closest(target, "button.diff-reply-toggle"))) { event.preventDefault(); onReplyToggle(el); return; }
      if ((el = closest(target, "button.diff-load"))) { event.preventDefault(); onLoadDiff(el); return; }
      if ((el = closest(target, "#pr-expand-all, #pr-collapse-all"))) {
        var open = el.id === "pr-expand-all";
        var files = root.querySelectorAll("details.diff-file");
        for (var i = 0; i < files.length; i++) files[i].open = open;
      }
    });

    var filters = document.querySelectorAll("input.diff-tree-filter");
    for (var i = 0; i < filters.length; i++) {
      filters[i].addEventListener("input", function (event) { filterTree(event.currentTarget, root); });
    }

    var rendered = root.getAttribute("data-mode");
    if (rendered === "split" || rendered === "unified") {
      var params = new URLSearchParams(window.location.search);
      if (params.has("diff")) storageSet(MODE_KEY, rendered);
    }

    updateViewedCount(root);
    setupHighlighting(root);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
