// QRShield 1.0.0 — CSP-compliant progressive enhancement (no inline scripts, no eval).
(function () {
  "use strict";

  // 1. Theme persistence (Precision Light / Tactical Dark)
  var THEME_KEY = "qrshield_theme";
  function applyTheme(theme) {
    if (theme === "dark") {
      document.documentElement.setAttribute("data-theme", "dark");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
    var label = document.querySelector("[data-theme-label]");
    if (label) {
      label.textContent = theme === "dark" ? "Dark Slate" : "Light Mode";
    }
  }

  try {
    var saved = localStorage.getItem(THEME_KEY);
    if (saved === "dark" || saved === "light") {
      applyTheme(saved);
    }
  } catch (_) {}

  // 2. Delegated change listeners (SVG layer toggles, file input preview, candidate radio focus)
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!t || !t.matches) return;

    // SVG bounding-box layer toggles
    if (t.matches("input[data-layer]")) {
      var scope = t.closest(".viewer");
      if (!scope) return;
      scope.querySelectorAll("[data-layer-group='" + t.getAttribute("data-layer") + "']").forEach(function (g) {
        g.classList.toggle("hidden", !t.checked);
      });
    }

    // File input preview pill inside dropzone
    if (t.matches("input[type='file']#image")) {
      var preview = document.getElementById("file-preview");
      if (preview && t.files && t.files.length > 0) {
        var f = t.files[0];
        var kb = Math.max(1, Math.round(f.size / 1024));
        preview.textContent = "Selected: " + f.name + " (" + kb + " KB)";
        preview.classList.remove("hidden");
      }
    }

    // Auto-focus edit text box when user selects "Edit" on an OCR candidate
    if (t.matches("input[type='radio'][name^='cand_']") && t.value === "edit") {
      var fs = t.closest("fieldset");
      if (fs) {
        var textInput = fs.querySelector("input[type='text']");
        if (textInput) textInput.focus();
      }
    }
  });

  // 3. Drag-and-drop visual feedback on .dropzone
  document.addEventListener("dragover", function (e) {
    var dz = e.target && e.target.closest ? e.target.closest(".dropzone") : null;
    if (dz) {
      e.preventDefault();
      dz.classList.add("dragover");
    }
  });

  document.addEventListener("dragleave", function (e) {
    var dz = e.target && e.target.closest ? e.target.closest(".dropzone") : null;
    if (dz) {
      dz.classList.remove("dragover");
    }
  });

  document.addEventListener("drop", function (e) {
    var dz = e.target && e.target.closest ? e.target.closest(".dropzone") : null;
    if (dz) {
      dz.classList.remove("dragover");
      var input = dz.querySelector("input[type='file']");
      if (input && e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        e.preventDefault();
        input.files = e.dataTransfer.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    }
  });

  // 4. Delegated click actions (theme toggle, use-confident, reset-ignore, copy payload, filter evidence)
  document.addEventListener("click", function (e) {
    var el = e.target && e.target.closest ? e.target : null;
    if (!el) return;

    // Theme toggle
    var themeBtn = el.closest("[data-action='toggle-theme']");
    if (themeBtn) {
      var isDark = document.documentElement.getAttribute("data-theme") === "dark";
      var next = isDark ? "light" : "dark";
      applyTheme(next);
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch (_) {}
      return;
    }

    // Use all high/medium-confidence OCR suggestions
    var useConfBtn = el.closest("[data-action='use-confident']");
    if (useConfBtn) {
      var form = useConfBtn.closest("form");
      if (!form) return;
      form.querySelectorAll("input[type=radio][data-confidence]").forEach(function (r) {
        var conf = r.getAttribute("data-confidence");
        if (r.value === "use" && (conf === "high" || conf === "medium")) r.checked = true;
      });
      return;
    }

    // Reset all OCR suggestions to Ignore
    var resetBtn = el.closest("[data-action='reset-ignore']");
    if (resetBtn) {
      var rForm = resetBtn.closest("form");
      if (!rForm) return;
      rForm.querySelectorAll("input[type=radio][value='ignore']").forEach(function (r) {
        r.checked = true;
      });
      return;
    }

    // Copy decoded payload text to clipboard
    var copyBtn = el.closest("[data-action='copy-payload']");
    if (copyBtn) {
      var wrap = copyBtn.closest(".payload-wrap");
      var box = wrap ? wrap.querySelector(".payload") : null;
      if (box && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(box.textContent.trim()).then(function () {
          var orig = copyBtn.textContent;
          copyBtn.textContent = "Copied";
          setTimeout(function () {
            copyBtn.textContent = orig;
          }, 1400);
        }).catch(function () {});
      }
      return;
    }

    // Print report button
    var printBtn = el.closest("[data-action='print-report']");
    if (printBtn) {
      window.print();
      return;
    }

    // Filter evidence ledger rows by severity
    var filterBtn = el.closest("[data-filter-sev]");
    if (filterBtn) {
      var targetSev = filterBtn.getAttribute("data-filter-sev");
      var article = filterBtn.closest(".result");
      if (!article) return;
      article.querySelectorAll("[data-filter-sev]").forEach(function (b) {
        b.classList.toggle("active", b === filterBtn);
      });
      article.querySelectorAll(".ledger .row").forEach(function (row) {
        var rowSev = row.getAttribute("data-row-sev") || "";
        row.classList.toggle("hidden", targetSev !== "all" && rowSev !== targetSev);
      });
      return;
    }
  });

  // 5. Instant text search across evidence rows
  document.addEventListener("input", function (e) {
    var t = e.target;
    if (!t || !t.matches || !t.matches("[data-evidence-search]")) return;
    var q = (t.value || "").trim().toLowerCase();
    var article = t.closest(".result");
    if (!article) return;
    article.querySelectorAll(".ledger .row").forEach(function (row) {
      var text = (row.textContent || "").toLowerCase();
      row.classList.toggle("hidden", q.length > 0 && text.indexOf(q) === -1);
    });
  });

  // 6. Update workflow stepper and scroll smoothly after HTMX swaps
  document.body.addEventListener("htmx:afterSwap", function (e) {
    var target = e.detail && e.detail.target;
    if (!target) return;
    if (target.id === "workspace") {
      var s1 = document.getElementById("step-1");
      var s2 = document.getElementById("step-2");
      if (s1) s1.classList.remove("active");
      if (s2) s2.classList.add("active");
      target.scrollIntoView({ behavior: "auto", block: "start" });
    } else if (target.id === "results") {
      var s2b = document.getElementById("step-2");
      var s3 = document.getElementById("step-3");
      if (s2b) s2b.classList.remove("active");
      if (s3) s3.classList.add("active");
      target.scrollIntoView({ behavior: "auto", block: "start" });
    }
  });
})();
