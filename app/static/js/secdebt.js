function getSecDebtCsrfToken() {
    const tokenMeta = document.querySelector('meta[name="csrf-token"]');
    return tokenMeta ? tokenMeta.content : '';
}

function applySecDebtFilters() {
    const activeTool = document.querySelector('.filter-btn.active[data-filter-tool]')?.dataset.filterTool || '';
    const activeSeverity = document.querySelector('.filter-btn.active[data-filter-sev]')?.dataset.filterSev || '';

    document.querySelectorAll('.finding-row').forEach(row => {
        const matchesTool = !activeTool || row.dataset.tool === activeTool;
        const matchesSeverity = !activeSeverity || row.dataset.sev === activeSeverity;
        row.classList.toggle('hidden', !(matchesTool && matchesSeverity));
    });
}

function setupSecDebtFilters() {
    document.querySelectorAll('[data-filter-tool]').forEach(button => {
        button.addEventListener('click', () => {
            document.querySelectorAll('[data-filter-tool]').forEach(item => item.classList.remove('active'));
            button.classList.add('active');
            applySecDebtFilters();
        });
    });

    document.querySelectorAll('[data-filter-sev]').forEach(button => {
        button.addEventListener('click', () => {
            document.querySelectorAll('[data-filter-sev]').forEach(item => item.classList.remove('active'));
            button.classList.add('active');
            applySecDebtFilters();
        });
    });
}

function setupSecDebtResolveButtons() {
    document.querySelectorAll('.btn-resolve').forEach(button => {
        button.addEventListener('click', async () => {
            const findingId = button.dataset.id;
            if (!findingId) return;

            button.disabled = true;
            try {
                const response = await fetch(`/secdebt/api/resolve/${findingId}`, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': getSecDebtCsrfToken() },
                });

                if (!response.ok) {
                    button.disabled = false;
                    button.textContent = 'Failed';
                    return;
                }

                button.closest('tr')?.remove();
            } catch {
                button.disabled = false;
                button.textContent = 'Failed';
            }
        });
    });
}

function setupManualIngest() {
    const button = document.getElementById('btn-manual-ingest');
    if (!button) return;

    button.addEventListener('click', async () => {
        button.disabled = true;
        button.textContent = 'Scanning...';

        try {
            const response = await fetch('/secdebt/api/ingest', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getSecDebtCsrfToken(),
                },
                body: JSON.stringify({ triggered_by: 'manual-ui' }),
            });

            if (!response.ok) {
                button.textContent = 'Scan failed';
                button.disabled = false;
                return;
            }

            globalThis.location.reload();
        } catch {
            button.textContent = 'Scan failed';
            button.disabled = false;
        }
    });
}

function renderSeverityChart() {
    const canvas = document.getElementById("severityChart");
    if (!canvas) return;

    new Chart(canvas, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low", "Info"],
            datasets: [{
                label: "Findings",
                data: [
                    Number(canvas.dataset.critical),
                    Number(canvas.dataset.high),
                    Number(canvas.dataset.medium),
                    Number(canvas.dataset.low),
                    Number(canvas.dataset.info)
                ],
                backgroundColor: "#58a6ff",
                borderColor: "#58a6ff",
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: "#c9d1d9"
                    },
                    grid: {
                        color: "#30363d"
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#c9d1d9"
                    },
                    grid: {
                        color: "#30363d"
                    }
                }
            }
        }
    });
}

function renderToolChart() {
    const canvas = document.getElementById("toolChart");
    if (!canvas) return;

    const labels = JSON.parse(canvas.dataset.labels);
    const values = JSON.parse(canvas.dataset.values);

    new Chart(canvas, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Findings",
                data: values,
                backgroundColor: "#58a6ff",
                borderColor: "#58a6ff",
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: "#c9d1d9"
                    },
                    grid: {
                        color: "#30363d"
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#c9d1d9"
                    },
                    grid: {
                        color: "#30363d"
                    }
                }
            }
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    setupSecDebtFilters();
    setupSecDebtResolveButtons();
    setupManualIngest();
    renderSeverityChart();
    renderToolChart();
});
