async function doFetch() {
    const url = document.getElementById('fetch-url').value.trim();
    if (!url) return;

    const resultDiv = document.getElementById('fetch-result');
    const contentDiv = document.getElementById('result-content');

    contentDiv.innerHTML = '<div class="loading">Fetching...</div>';
    resultDiv.classList.remove('hidden');

    const formData = new FormData();
    formData.append('url', url);

    try {
        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        const response = await fetch('/fetcher/fetch-site', {
            method: 'POST',
            body: formData,
            headers: { 'X-CSRFToken': csrfToken }
        });
        const data = await response.json();

        if (data.error) {
            contentDiv.innerHTML = `<div class="result-error"><strong>Error:</strong> ${data.error}</div>`;
        } else {
            contentDiv.innerHTML = `
                <div class="result-row"><strong>Title:</strong> ${data.title || '(none)'}</div>
                <div class="result-row"><strong>Status:</strong> ${data.status}</div>
            `;
        }
    } catch (e) {
        contentDiv.innerHTML = `<div class="result-error">Request failed: ${e.message}</div>`;
    }
}
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('btn-do-fetch');
    if (btn) btn.addEventListener('click', doFetch);
});
