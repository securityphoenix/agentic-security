// Safe: textContent — no HTML parsing, no mutation.
function renderUser(userText) {
  document.getElementById('out').textContent = userText;
}
