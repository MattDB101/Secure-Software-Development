const router = require('express').Router();
const connection = require('../middleware/database');
const User = connection.models.User;
const FileUpload = connection.models.FileUpload
const isAuth = require('./authMiddleware').isAuth;
const authMiddleware = require('./authMiddleware');
const { csrfProtection, cookieParser, bodyParser } = require('./csrfMiddleware')
const logger = require("../middleware/logging")
const xss = require('xss');
const mongoSanitize = require('express-mongo-sanitize');

router.use(bodyParser.urlencoded({ extended: false }))
router.use(cookieParser())

router.get('/', (req, res, next) => {
    res.render("index.ejs", { loggedIn: req.isAuthenticated() });
});

router.get('/login', (req, res, next) => {
    res.render("login.ejs", { loggedIn: req.isAuthenticated() });
});

router.get('/register', (req, res, next) => {

    res.render("register.ejs", { loggedIn: req.isAuthenticated() });
    
});

router.get('/admin-route',  async (req, res, next) => {
        try {
            const isAdmin = await authMiddleware.isAdmin(req, res, next);
                if (isAdmin) {
                const files = await FileUpload.find({});
            
                const sanitizedFiles = files.map(file => {
                    return {
                        username: xss(file.username), // username and file are user controlled inputs
                        fileName: xss(file.fileName),
                        fileSize: file.fileSize,
                        uploadDate: file.uploadDate
                    };
                });
                sanitizedFiles.reverse();
                res.render('admin.ejs', { files: sanitizedFiles });
            } else {
                logger.warn('Unauthorized merchant attempt to access admin panel', { metadata: { route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress } });
            
                res.render('error.ejs', { errorMessage: "Not Authorised.", loggedIn: req.isAuthenticated() });
            }
        } catch (error) {
            res.status(500).render('error.ejs', {errorMessage: 'Error retrieving files.', loggedIn: req.isAuthenticated()});
            logger.warn('Failed to retrive merchant files', { metadata: { route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress, error:error } });
        
        }
    
});


router.get('/logout', (req, res, next) => {

    req.logout(function(err) {
        if (err) {
            logger.warn('Failed to properly logout', { metadata: { route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress, err:err } });
    
        } else {
            res.clearCookie("connect.sid");
            res.redirect('/protected-route');  // comment this out or a new session will be created immediately, this is just to prove protected routes work.
        }
    });
    
});

router.get('/login-success', (req, res, next) => {
    res.send('<p>You successfully logged in. --> <a href="/protected-route">Go to protected route</a></p>');
});

router.get('/login-failure', (req, res, next) => {
    res.send('Login failure');
});

router.get('/protected-route', isAuth, csrfProtection, async (req, res) => {
    const isAdmin = await authMiddleware.isAdmin(req, res);
    if (!isAdmin) {
        res.render('upload.ejs', { csrfToken: req.csrfToken(), loggedIn: req.isAuthenticated() });
    } else {
        logger.warn('Unauthorized admin attempt to access merchant panel', { metadata: { route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress } });
            
        res.render('error.ejs', { errorMessage: "Not Authorised.", loggedIn: req.isAuthenticated() });
    }
});

module.exports = router;