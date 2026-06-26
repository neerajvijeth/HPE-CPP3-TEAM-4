function getCsrfToken() {
    const tokenMeta = document.querySelector('meta[name="csrf-token"]');
    return tokenMeta ? tokenMeta.content : '';
}

function setText(parent, className, text) {
    const element = document.createElement('div');
    element.className = className;
    element.textContent = text;
    parent.replaceChildren(element);
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
}

async function revealPassword(entryId, btn) {
    const pwSpan = document.getElementById(`pw-${entryId}`);
    if (!pwSpan) return;

    if (btn.dataset.revealed === 'true') {
        pwSpan.textContent = '••••••••••';
        btn.textContent = 'Show';
        btn.dataset.revealed = 'false';
        return;
    }

    btn.textContent = '...';
    try {
        const response = await fetch(`/vault/reveal/${entryId}`);
        const data = await response.json();
        if (data.password !== undefined) {
            pwSpan.textContent = data.password;
            btn.textContent = 'Hide';
            btn.dataset.revealed = 'true';
        }
    } catch (e) {
        btn.textContent = 'Error';
    }
}

async function fetchSiteInfo() {
    const urlInput = document.getElementById('site_url');
    if (!urlInput || !urlInput.value.trim()) return;

    const preview = document.getElementById('site-preview');
    const formData = new FormData();
    formData.append('url', urlInput.value.trim());

    try {
        const response = await fetch('/fetcher/fetch-site', {
            method: 'POST',
            body: formData,
            headers: { 'X-CSRF-Token': getCsrfToken() },
        });
        const data = await response.json();
        if (preview) {
            preview.classList.remove('hidden');
            preview.classList.remove('text-danger');
            if (data.title) {
                preview.textContent = `Site title: ${data.title}`;
                const siteNameInput = document.querySelector('input[name="site_name"]');
                if (siteNameInput && !siteNameInput.value) {
                    siteNameInput.value = data.title;
                }
            } else if (data.error) {
                preview.textContent = `Error: ${data.error}`;
                preview.classList.add('text-danger');
            } else {
                preview.textContent = 'No title found';
                preview.classList.remove('text-danger');
            }
        }
    } catch (e) {
        if (preview) {
            preview.classList.remove('hidden');
            preview.textContent = 'Request failed';
            preview.classList.add('text-danger');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-toggle-password]').forEach(button => {
        button.addEventListener('click', () => togglePassword(button.dataset.togglePassword));
    });

    document.querySelectorAll('[data-action="reveal-password"]').forEach(button => {
        button.addEventListener('click', () => revealPassword(button.dataset.entryId, button));
    });

    document.querySelectorAll('[data-action="fetch-site-info"]').forEach(button => {
        button.addEventListener('click', fetchSiteInfo);
    });

    document.querySelectorAll('.delete-entry-form').forEach(form => {
        form.addEventListener('submit', event => {
            if (!window.confirm('Delete this entry?')) {
                event.preventDefault();
            }
        });
    });

    document.querySelectorAll('.flash-close').forEach(button => {
        button.addEventListener('click', () => button.closest('.flash')?.remove());
    });

    document.querySelectorAll('.flash').forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            flash.style.transition = 'opacity 0.3s';
            setTimeout(() => flash.remove(), 300);
        }, 4000);
    });

    const fetchForm = document.getElementById('fetch-form');
    if (fetchForm) {
        fetchForm.addEventListener('submit', async event => {
            event.preventDefault();
            const resultDiv = document.getElementById('fetch-result');
            const contentDiv = document.getElementById('result-content');
            const formData = new FormData(fetchForm);

            if (!formData.get('url')?.trim()) return;

            setText(contentDiv, 'loading', 'Fetching...');
            resultDiv.classList.remove('hidden');

            try {
                const response = await fetch('/fetcher/fetch-site', {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-CSRF-Token': getCsrfToken() },
                });
                const data = await response.json();

                if (data.error) {
                    setText(contentDiv, 'result-error', `Error: ${data.error}`);
                    return;
                }

                const titleRow = document.createElement('div');
                titleRow.className = 'result-row';
                titleRow.textContent = `Title: ${data.title || '(none)'}`;

                const statusRow = document.createElement('div');
                statusRow.className = 'result-row';
                statusRow.textContent = `Status: ${data.status}`;

                contentDiv.replaceChildren(titleRow, statusRow);
            } catch (error) {
                setText(contentDiv, 'result-error', `Request failed: ${error.message}`);
            }
        });
    }
});
