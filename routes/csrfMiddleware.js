const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const csrfProtection = csrf({ cookie: true });
module.exports = { csrfProtection, cookieParser, bodyParser };
