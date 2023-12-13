const crypto = require('crypto');

function genPassword(password) {
    var salt = crypto.randomBytes(32).toString('hex'); // gen new salt for each user to prevent rainbow tables
    var genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');  // PBKDF2 algo, large hash
    
    return {
      salt: salt,
      hash: genHash
    };
}

function validPassword(password, hash, salt) {
    var hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === hashVerify;
}

module.exports.validPassword = validPassword;
module.exports.genPassword = genPassword;