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

document.addEventListener('DOMContentLoaded', () => {
    setupSecDebtFilters();
    setupSecDebtResolveButtons();
    setupManualIngest();
});
