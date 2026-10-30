/* Highlight documentation JSON using the bundled Prism grammar. Plain text is
 * kept readable when JavaScript or the grammar is unavailable. */
(function () {
    function highlight() {
        if (!window.Prism || !Prism.languages.json) return;
        document.querySelectorAll(".ci-guide code.language-json").forEach(function (code) {
            Prism.highlightElement(code);
        });
    }

    function start() {
        if (!document.querySelector(".ci-guide code.language-json")) return;
        if (!window.Prism) return;
        if (Prism.languages.json) {
            highlight();
            return;
        }
        const script = document.createElement("script");
        script.src = "/static/assets/prismjs/components/prism-json.min.js";
        script.onload = highlight;
        document.head.appendChild(script);
    }

    // The shared page loads Prism near the end of the document.
    if (document.readyState === "complete") start();
    else window.addEventListener("load", start, {once: true});
})();
