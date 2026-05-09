// NEGATIVE: file mentions "shell" and has user input + innerHTML, but
// no LLM SDK is imported and no LLM call is made. Must NOT trigger.
export function execute_shell(cmd) {
  return cmd;
}

export function render(req) {
  const html = String(req.body.html);
  document.body.innerHTML = html;
}
