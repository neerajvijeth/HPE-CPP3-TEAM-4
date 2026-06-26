/**
 * secdebt.js
 * Frontend logic for the SecDebt-Optimizer dashboard.
 * Uses vanilla JS + the Chart.js CDN (loaded inline) — no build step needed.
 */

(function () {
  "use strict";

  /* -----------------------------------------------------------------------
   * 1. Debt score trend chart (Chart.js loaded from CDN)
   * --------------------------------------------------------------------- */

  function initChart() {
    const history = window.__DEBT_HISTORY__;
    const canvas = document.getElementById("debt-chart");
    if (!history || !canvas) return;

    // Dynamically load Chart.js from CDN (already allowed by CSP for self)
    const script = document.createElement("script");
    script.src = "https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js";
    script.onload = function () {
      const ctx = canvas.getContext("2d");
      new Chart(ctx, {
        type: "line",
        data: {
          labels: history.labels,
          datasets: [
            {
              label: "Total Debt Score",
              data: history.scores,
              borderColor: "#58a6ff",
              backgroundColor: "rgba(88,166,255,0.1)",
              fill: true,
              tension: 0.3,
              pointBackgroundColor: "#58a6ff",
              pointRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: "#1c2128",
              borderColor: "#30363d",
              borderWidth: 1,
              titleColor: "#e6edf3",
              bodyColor: "#8b949e",
            },
          },
          scales: {
            x: {
              ticks: { color: "#6e7681", font: { size: 11 } },
              grid: { color: "#21262d" },
            },
            y: {
              ticks: { color: "#6e7681", font: { size: 11 } },
              grid: { color: "#21262d" },
              beginAtZero: true,
            },
          },
        },
      });
    };
    document.head.appendChild(script);
  }

  /* -----------------------------------------------------------------------
   * 2. Filter bar (tool + severity)
   * --------------------------------------------------------------------- */

  let activeToolFilter = "";
  let activeSevFilter = "";
  let showResolved = false;

  function applyFilters() {
    const rows = document.querySelectorAll(".finding-row");
    rows.forEach(function (row) {
      const tool = row.dataset.tool || "";
      const sev = row.dataset.sev || "";
      const resolved = row.dataset.resolved === "true";

      const toolMatch = !activeToolFilter || tool === activeToolFilter;
      const sevMatch = !activeSevFilter || sev === activeSevFilter;
      const resolvedMatch = showResolved ? true : !resolved;

      row.classList.toggle("hidden", !(toolMatch && sevMatch && resolvedMatch));
    });
  }

  function initFilters() {
    // Tool filter buttons
    document.querySelectorAll("[data-filter-tool]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        document
          .querySelectorAll("[data-filter-tool]")
          .forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        activeToolFilter = btn.dataset.filterTool;
        applyFilters();
      });
    });

    // Severity filter buttons
    document.querySelectorAll("[data-filter-sev]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        document
          .querySelectorAll("[data-filter-sev]")
          .forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        activeSevFilter = btn.dataset.filterSev;
        applyFilters();
      });
    });

    // Show resolved checkbox
    const checkbox = document.getElementById("show-resolved");
    if (checkbox) {
      checkbox.addEventListener("change", function () {
        showResolved = checkbox.checked;
        applyFilters();
      });
    }
  }

  /* -----------------------------------------------------------------------
   * 3. Resolve finding (admin only)
   * --------------------------------------------------------------------- */

  function initResolveButtons() {
    document.querySelectorAll(".btn-resolve").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const id = btn.dataset.id;
        if (!id) return;
        if (!confirm("Mark finding #" + id + " as resolved?")) return;

        var csrfMeta = document.querySelector('meta[name="csrf-token"]');
        var csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';
        fetch("/secdebt/api/resolve/" + id, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        })
          .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.json();
          })
          .then(function () {
            const row = document.querySelector('[data-id="' + id + '"]');
            if (row) {
              row.dataset.resolved = "true";
              row.style.opacity = "0.4";
              btn.textContent = "✓ Done";
              btn.disabled = true;
              if (!showResolved) {
                setTimeout(function () {
                  row.classList.add("hidden");
                }, 600);
              }
            }
          })
          .catch(function (err) {
            alert("Failed to resolve: " + err.message);
          });
      });
    });
  }

  /* -----------------------------------------------------------------------
   * 4. Manual ingest trigger (admin only)
   * --------------------------------------------------------------------- */

  function initManualIngest() {
    const btn = document.getElementById("btn-manual-ingest");
    if (!btn) return;

    btn.addEventListener("click", function () {
      const origText = btn.textContent;
      btn.disabled = true;
      btn.textContent = "⏳ Scanning…";

      var csrfMeta = document.querySelector('meta[name="csrf-token"]');
      var csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';
      fetch("/secdebt/api/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ triggered_by: "manual-dashboard" }),
      })
        .then(function (res) {
          if (!res.ok) throw new Error("HTTP " + res.status);
          return res.json();
        })
        .then(function (data) {
          if (data.status === "ok") {
            alert(
              "✅ Ingest complete!\n" +
                "Total findings: " +
                data.total_findings +
                "\n" +
                "New: " +
                data.new_findings +
                "\n" +
                "Resolved: " +
                data.resolved_findings +
                "\n" +
                "Debt score: " +
                data.total_debt_score
            );
            location.reload();
          } else {
            alert("❌ Ingest error: " + (data.message || "unknown"));
          }
        })
        .catch(function (err) {
          alert("❌ Request failed: " + err.message);
        })
        .finally(function () {
          btn.disabled = false;
          btn.textContent = origText;
        });
    });
  }

  /* -----------------------------------------------------------------------
   * 5. Init
   * --------------------------------------------------------------------- */

  document.addEventListener("DOMContentLoaded", function () {
    initChart();
    initFilters();
    initResolveButtons();
    initManualIngest();
  });
})();
