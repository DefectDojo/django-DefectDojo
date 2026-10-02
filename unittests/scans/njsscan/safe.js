const crypto = require('crypto');

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

module.exports = { digest };
