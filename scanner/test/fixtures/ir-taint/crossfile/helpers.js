const { exec } = require('child_process');

exports.run = function (input) {
  exec('echo ' + input, (err, out) => console.log(out));
};
