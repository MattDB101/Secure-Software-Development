const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const crypto = require('crypto');
const getRoutes = require('./routes/getRoutes');
const postRoutes = require('./routes/postRoutes');
const connection = require('./middleware/database');
const cors = require('cors');
const permissionsPolicy = require("permissions-policy");
const helmet = require('helmet');
const MongoStore = require('connect-mongo')(session);
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const logger = require('./middleware/logging');
const mongoSanitize = require('express-mongo-sanitize');
const trackActivity = require('./routes/authMiddleware').trackActivity;
const checkForInactivity = require('./routes/authMiddleware').checkForInactivity;

require('dotenv').config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static('./public'));
app.use(mongoSanitize())

app.use(cors({ // cors was causing issues in development to begin with
    origin: 'http://localhost:3000', 
    methods: ['GET', 'POST'], 
    credentials: true
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 30,
    message: 'Too many requests from your IP.',
    handler: (req, res, next) => {
        logger.warn('Rate limit exceeded', {metadata: {route: req.originalUrl,status: 429,userAgent: req.headers['user-agent'],remoteIP: req.socket.remoteAddress || null } });
        res.status(429).render('error.ejs', { errorMessage: 'Too many requests from your IP, please try again later.' , loggedIn: false });
      },
});


app.use(limiter);

app.use(morgan('combined'));

const sessionStore = new MongoStore({ mongooseConnection: connection, collection: 'sessions' });

app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    next();
});

app.use(
     helmet.contentSecurityPolicy({
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", 'https://stackpath.bootstrapcdn.com'],
                imgSrc: ["'self'"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'", 'https://stackpath.bootstrapcdn.com'],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"],
                upgradeInsecureRequests: [],
            },
     })
);

app.use(
    helmet.hsts({
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true, 
      preload: true 
    })
);

app.use(
    permissionsPolicy({
        features: {
        camera: ["none"],
        microphone: ["none"],
        geolocation: ["none"],
        notifications: ["none"],
        fullscreen: ["self"]

        }
    })
);

app.use(helmet.frameguard({ action: 'deny' })); // disallow embeds
app.use(helmet.referrerPolicy({ policy: 'no-referrer' })); // turn off refer header details
app.use(helmet.noSniff()); // prevent browser MIME sniffing
app.use(helmet.xssFilter()); // further xss protection

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    unset: 'destroy',
    store: sessionStore,
    cookie: {
        //secure: true, // won't be set due to localhost
        httpOnly: true,
        sameSite: "strict",
        domain: "localhost",
        maxAge: 1000 * 60 * 15 // 15 mins
    }
}));

require('./middleware/passport');

app.use(passport.initialize());
app.use(passport.session());

app.use(trackActivity)
app.use(checkForInactivity)

app.use((req, res, next) => {
    next();
});

app.use(getRoutes);
app.use(postRoutes);

app.use((req, res, next) => {
    res.status(404).render('error.ejs', {errorMessage: 'Error 404, Page not found.', loggedIn: req.isAuthenticated()});
});


app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        logger.warn('Failed CSRF check', {metadata: {route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress || null}});
        req.logout(function(err) {
            if (err) {
                logger.warn('Failed to properly logout', { metadata: { route: req.originalUrl, status: res.statusCode, userAgent: req.headers['user-agent'], remoteIP: req.socket.remoteAddress, err:err } });
        
            } else {
                res.clearCookie("connect.sid");
                res.render('error.ejs', {errorMessage: 'Failed CSRF Check', loggedIn: req.isAuthenticated()});
            }
        });
    } else {
        res.status(err.status || 500).render('error.ejs', { errorMessage: err, loggedIn: req.isAuthenticated() });
        logger.warn('Server error occured', { metadata: {route: req.originalUrl,status: res.statusCode,userAgent: req.headers['user-agent'],remoteIP: req.socket.remoteAddress, err:err}});
    }
});

app.listen(3000);