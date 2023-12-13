const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;
const validPassword = require('./passwordUtils').validPassword;
const mongoSanitize = require('express-mongo-sanitize');
const logger = require('./logging');
const customFields = {
    usernameField: 'uname',
    passwordField: 'pw'
};

const verifyCallback = (username, password, done) => {
    var username = mongoSanitize.sanitize(username); // sanitise before querying DB
    User.findOne({ username: username })
        .then((user) => {

            if (!user) { return done(null, false) }
            
            const isValid = validPassword(password, user.hash, user.salt);
            
            if (isValid) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        })
        .catch((err) => {   
            logger.warn('Failed to find user', {metadata: { username, err:err } });
            done(err);
        });

}

const strategy  = new LocalStrategy(customFields, verifyCallback);

passport.use(strategy);

passport.serializeUser((user, done) => { // serialize the user's identity and store it in the session.
    done(null, user.id);
});

passport.deserializeUser((userId, done) => {
    User.findById(userId)
        .then((user) => {
            done(null, user);
        })
        .catch(err => done(err))
});

