(function () {
    "use strict";
    document.querySelectorAll("[data-inherits]").forEach(box => {
        const control = box.closest("[data-setting]").querySelector("select, input:not([type=checkbox])");
        const update = () => { control.disabled = box.checked; };
        box.addEventListener("change", update); update();
    });
    document.querySelectorAll(".settings-env-form").forEach(form => {
        form.querySelector(".settings-add-env").onclick = () => {
            const count = form.elements.env_count;
            if (Number(count.value) >= 256) return;
            const row = form.querySelector("template").content.cloneNode(true);
            row.querySelectorAll("[name]").forEach(input => { input.name = input.name.replace("__index__", count.value); });
            if (form.querySelector(".settings-show-env").textContent === "Hide values") {
                row.querySelectorAll(".settings-env-value").forEach(input => { input.type = "text"; });
            }
            count.value = Number(count.value) + 1;
            form.querySelector(".settings-env-rows").append(row);
        };
        form.querySelector(".settings-show-env").onclick = event => {
            const visible = event.currentTarget.textContent === "Show values";
            form.querySelectorAll(".settings-env-value").forEach(input => { input.type = visible ? "text" : "password"; });
            event.currentTarget.textContent = visible ? "Hide values" : "Show values";
        };
    });
})();
