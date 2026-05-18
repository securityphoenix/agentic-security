// Vuln: DOMParser round-trip — known mXSS vector.
function renderUser(userHtml) {
  const parsed = new DOMParser().parseFromString(userHtml, 'text/html').body.innerHTML;
  document.getElementById('out').innerHTML = parsed;
}
