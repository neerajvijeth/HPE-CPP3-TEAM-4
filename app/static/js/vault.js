function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
}

// A01: No ownership check server-side — any user can reveal any password by ID
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

// A10: Triggers server-side SSRF via URL fetcher
async function fetchSiteInfo() {
    const urlInput = document.getElementById('site_url');
    if (!urlInput || !urlInput.value.trim()) return;

    const preview = document.getElementById('site-preview');
    const formData = new FormData();
    formData.append('url', urlInput.value.trim());

    try {
        const response = await fetch('/fetcher/fetch-site', { method: 'POST', body: formData });
        const data = await response.json();
        if (preview) {
            preview.classList.remove('hidden');
            if (data.title) {
                preview.innerHTML = `<strong>Site title:</strong> ${data.title}`;
                const siteNameInput = document.querySelector('input[name="site_name"]');
                if (siteNameInput && !siteNameInput.value) {
                    siteNameInput.value = data.title;
                }
            } else if (data.error) {
                preview.innerHTML = `<span style="color:var(--red)">Error: ${data.error}</span>`;
            } else {
                preview.innerHTML = '<span style="color:var(--text-muted)">No title found</span>';
            }
        }
    } catch (e) {
        if (preview) {
            preview.classList.remove('hidden');
            preview.innerHTML = `<span style="color:var(--red)">Request failed</span>`;
        }
    }
}

// Auto-dismiss flash messages
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.flash').forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            flash.style.transition = 'opacity 0.3s';
            setTimeout(() => flash.remove(), 300);
        }, 4000);
    });
});
