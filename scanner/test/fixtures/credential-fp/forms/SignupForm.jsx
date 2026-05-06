// JSX form with placeholder attributes — should NOT be flagged.
import React from 'react';

export default function SignupForm() {
  return (
    <form>
      <input type="text" placeholder="username" />
      <input type="password" placeholder="password is at least 8 chars" />
      <input type="text" aria-label="api_key value" />
    </form>
  );
}
