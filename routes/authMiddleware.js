const logger = require('../middleware/logging');
const mongoSanitize = require('express-mongo-sanitize');
const connection = require('../middleware/database');
const User = connection.models.User;

module.exports.trackActivity = (req, res, next) => {
    req.session.lastActivity = Date.now(); // Update last activity timestamp
    next();
}
  
  
module.exports.checkForInactivity = (req, res, next) => {
    const maxInactiveDuration = 30 * 60 * 1000; // 5 mins
    const currentTime = Date.now();
    const lastActivityTime = req.session.lastActivity || currentTime;

    if (currentTime - lastActivityTime > maxInactiveDuration) {
        req.session = null;
        req.session = {};
    }

    next();
}

module.exports.isAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
        next();
    } else {
        res.status(401).render('error.ejs', { errorMessage: 'Not authorized', loggedIn: false });
        logger.warn('Unauthorized attempt to access merchant panel', { metadata: { route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress }
        });
    }
}

module.exports.isAdmin = (req, res, next) => {
    return new Promise((resolve, reject) => {
        if (req.isAuthenticated()) {
            var username = mongoSanitize.sanitize(req.user.username); 
            User.findOne({ username: username })
                .then((user) => {
                    if (user && user.admin) {
                        resolve(true);
                    } else {
                        resolve(false);
                    }
                })
                .catch((err) => {
                    logger.warn('Failed to find user', { metadata: { username, err: err } });
                    reject(err);
                });
        } else {
            res.status(401).render('error.ejs', { errorMessage: 'Not authorized', loggedIn: req.isAuthenticated() });
            logger.warn('Unauthorized attempt to access admin panel', { metadata: { route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress } });
            resolve(false);
        }
    });
};
