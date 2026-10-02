const crypto = require('crypto');

function digest(value) {
  return crypto.createHash('md5').update(value).digest('hex');
}

module.exports = { digest };
