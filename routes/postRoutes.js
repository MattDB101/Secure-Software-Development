const router = require('express').Router();
const passport = require('passport');
const multer = require('multer');
const fs = require('fs');
const genPassword = require('../middleware/passwordUtils').genPassword;
const connection = require('../middleware/database');
const User = connection.models.User;
const FileUpload = connection.models.FileUpload
const isAuth = require('./authMiddleware').isAuth;
const authMiddleware = require('./authMiddleware');
const { check, validationResult } = require('express-validator');
const { csrfProtection, cookieParser, bodyParser } = require('./csrfMiddleware')
const xss = require('xss');
const logger = require('../middleware/logging');
const crypto = require('crypto');
const { Binary } = require('mongodb');



const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, '' + Date.now()); 
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 1000000 }, // Limit file size to 1MB
    fileFilter: function (req, file, cb) {
        if (file.mimetype !== 'application/pdf') {
            logger.warn('Attempt to upload invalid file type', {
                metadata: { route: req.originalUrl, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress } });
            return cb(new Error('Not a PDF.'), false);
        }
        cb(null, true);
    }
}).single('uploadedFile');


router.post('/login', async function(req, res, next) {
    try {
        req.body.uname = xss(req.body.uname);
        passport.authenticate('local', function(err, user, info) {
            if (!user) {
                // Handle invalid credentials
                logger.warn('Invalid credentials', { route: req.originalUrl, status: 401, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress });
                return res.status(401).render('login.ejs', { errorMessage: 'Invalid credentials. Please try again.' });
            }
            req.login(user, async function(err) {
                if (err) {
                    logger.error('Passport Auth Failure', { route: req.originalUrl, status: 500, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress });
                    return res.status(500).render('login.ejs', { errorMessage: 'An unexpected error occurred. Please try again.' });
                }
                try {
                    const isAdmin = await authMiddleware.isAdmin(req, res, next);
                    if (isAdmin) {
                        return res.redirect('/admin-route');
                    } else {
                        return res.redirect('/protected-route');
                    }
                } catch (error) {
                    res.status(500).render('error.ejs', { errorMessage: 'Error checking admin status.', loggedIn: req.isAuthenticated() });
                    logger.error('Error checking admin status', { route: req.originalUrl, status: 500, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress, error: error });
                }
            });
        })(req, res, next);
    } catch (error) {
        res.render('login.ejs', { errorMessage: 'Login Error, please try again.' });
        logger.error('Login error', { route: req.originalUrl, status: 500, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress, error: error });
    }
});


router.post('/register', [
    check('uname').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    check('pw').isStrongPassword({minLength: 8,minNumbers: 1, minUppercase: 1, minLowercase: 1, minSymbols: 1}).withMessage('Password must be between 8 and 30 characters long, contain at least one uppercase letter, one lowercase letter, and one number.')
], (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMessage = errors.array().map(err => err.msg).join(', ');
        return res.render('register.ejs', { 
            errorMessage: errorMessage,
            loggedIn: false
        });
    }

    const saltHash = genPassword(req.body.pw); 
    
    const salt = saltHash.salt;
    const hash = saltHash.hash;
    const newUser = new User({
        username: xss(req.body.uname),
        hash: hash,
        salt: salt,
        admin: false
    });
    try { 
        newUser.save()
            .then((user) => {
                res.redirect('/login');
            })
    }  catch (error) {
        res.render('register.ejs', { errorMessage: 'Registration failed due to an unexpected error. Please try again.', loggedIn: false});
        logger.error('Registration error', {route: req.originalUrl,status: 500,userAgent: req.headers['user-agent'],remoteIP: req.socket.remoteAddress});
    }
});


router.post('/protected-route', isAuth, csrfProtection, function (req, res, next) {
    upload(req, res, function (err) {
        if (err) {
            if (err == "Error: Not a PDF.") {
                logger.error('Merchant attempt to upload non-PDF file', {
                    route: req.originalUrl,
                    status: 413,
                    userAgent: req.headers['user-agent'],
                    remoteIP: req.socket.remoteAddress
                });
                
                return res.status(413).render('error.ejs', {
                    errorMessage: 'Only files in PDF format are accepted.',
                    loggedIn: req.isAuthenticated()
                    
                });
            }

            if (err.code == 'LIMIT_FILE_SIZE') {
                logger.error('File size limit exceeded', {
                    route: req.originalUrl,
                    status: 413,
                    userAgent: req.headers['user-agent'],
                    remoteIP: req.socket.remoteAddress
                });
                
                return res.status(413).render('error.ejs', {
                    errorMessage: 'File too large. Please upload a file smaller than 1MB.',
                    loggedIn: req.isAuthenticated()
                    
                });
            } else {
                logger.error('General file upload error', {
                    route: req.originalUrl,
                    status: 409,
                    userAgent: req.headers['user-agent'],
                    remoteIP: req.socket.remoteAddress
                });
                return res.status(409).render('error.ejs', {
                    errorMessage: "General file upload error",
                    loggedIn: req.isAuthenticated()
                });
            }
        } 

        if (!req.file) {
            return res.status(400).render('error.ejs', {
                errorMessage: 'No file uploaded.',
                loggedIn: req.isAuthenticated()
            });
        }
        const isFileSafe = simulateVirusScan(req.file);

        if (isFileSafe) {
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', process.env.ENCRYPTION_KEY, iv);
            const buffers = [];
    
            cipher.on('data', (data) => {
                buffers.push(data);
            });
    
            cipher.on('end', () => {
                const encryptedData = Buffer.concat(buffers);
                const encryptedFile = new Binary(encryptedData);
    
                const newFileUpload = new FileUpload({
                    username: req.user.username,
                    fileName: req.file.filename,
                    fileSize: req.file.size,
                    file: encryptedFile
                });

                newFileUpload.save()
                .then(() => { 
                    res.send('File successfully encrypted & uploaded.');
                })
                .catch((err) => {
                    logger.error('Error Saving file.', {route: req.originalUrl,status: 500,userAgent: req.headers['user-agent'],remoteIP: req.socket.remoteAddress});   
                    res.render('error.ejs', { errorMessage: "File upload failed, please try again.", loggedIn: req.isAuthenticated()});
                });
                
                fs.unlink(req.file.path, (err) => { // delete the file  regardless of save outcome
                    if (err) {
                        logger.error('File could not be deleted.', {
                            route: req.originalUrl,
                            status: 500,
                            userAgent: req.headers['user-agent'],
                            remoteIP: req.socket.remoteAddress
                        });                       
                    }
                })
            });
    
            const input = fs.createReadStream(req.file.path);
            input.pipe(cipher);
        
        } else { // File failed the virus scan, delete the file
        
            fs.unlink(req.file.path, (err) => {
                if (err) {
                    logger.error('File could not be deleted.', {
                        route: req.originalUrl,
                        status: 500,
                        userAgent: req.headers['user-agent'],
                        remoteIP: req.socket.remoteAddress
                      });
                    return res.status(500).send('Error processing file.');
                    
                }
                logger.warn('File failed virus scan', { metadata: {route: req.originalUrl,status: res.statusCode, userAgent: req.headers['user-agent'],}});
                res.status(400).send('File failed the virus scan and was deleted.');

            });
        }
    });
});



function simulateVirusScan(file) {
    return Math.random() < 0.5;
}

module.exports = router;