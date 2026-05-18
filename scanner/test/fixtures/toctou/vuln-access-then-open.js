const fs = require('fs');

function readUserFile(p) {
  fs.access(p, fs.constants.R_OK, (err) => {
    if (err) throw err;
    const data = fs.readFile(p, 'utf8', (e, d) => console.log(d));  // Vuln: TOCTOU
  });
}
