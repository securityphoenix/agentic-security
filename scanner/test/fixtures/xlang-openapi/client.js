// Client-side fetch from a SPA. Should be flagged cross_language:true
// because the server-side handler has high+ findings.
async function loadUser(id) {
  const r = await fetch('/users/' + id);
  const data = await r.json();
  document.body.innerHTML = data.bio;  // potential XSS sink
}
