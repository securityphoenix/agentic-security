const fs = require('fs');

function readUserFile(p) {
  // Safe: open directly, handle errors atomically.
  fs.readFile(p, 'utf8', (err, data) => {
    if (err) return null;
    return data;
  });
}
