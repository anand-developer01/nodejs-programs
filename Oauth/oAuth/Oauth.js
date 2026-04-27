// Oauth.js

// Import required libraries
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');

/**
 * OAuth configuration function
 * @param {Object} app - Express app instance
 * @param {Array} users - In-memory user database
 * @param {String} SECRET_KEY - JWT secret key
 * @param {Function} saveUsersToFile - Function to persist users
 */
module.exports = function(app, users, SECRET_KEY, saveUsersToFile) {

    /**
     * Initialize Passport middleware
     * Required for authentication flow
     */
    app.use(passport.initialize());

    /**
     * Google OAuth Strategy Configuration
     * Handles authentication with Google
     */
    passport.use(new GoogleStrategy({

        // Google OAuth credentials (move to .env in production)
        clientID: "remmove919872984552-remmove-ev0qrmc79njgqgocttuect5j243jqa00.apps.googleusercontent.com", // Use process.env in real apps
        clientSecret: "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",

        // Callback URL Google will redirect to after login
        callbackURL: "http://localhost:5000/auth/google/callback"

    },
    /**
     * This function runs after Google successfully authenticates user
     * @param accessToken - Google access token
     * @param refreshToken - Google refresh token
     * @param profile - User profile from Google
     * @param done - Passport callback
     */
    (accessToken, refreshToken, profile, done) => {

        // Check if user already exists in DB
        let user = users.find(u =>
            u.googleId === profile.id ||
            u.username === profile.emails[0].value
        );

        // If user does not exist, create new user
        if (!user) {
            user = {
                id: Date.now().toString(), // simple unique ID
                googleId: profile.id, // Google unique user ID
                username: profile.emails[0].value, // email from Google
                balance: 0, // app-specific field
                transactions: [], // app-specific field
            };

            // Save new user into memory DB
            users.push(user);

            // Persist users to file (your custom function)
            saveUsersToFile(users);
        }

        // Pass user object to Passport
        return done(null, user);
    }));

    /**
     * STEP 1: Start Google Login Flow
     * User is redirected to Google login page
     * Scope defines what data we want (email + profile)
     */
    app.get('/auth/google',
        passport.authenticate('google', {
            scope: ['profile', 'email']
        })
    );

    /**
     * STEP 2: Google redirects back here after login
     * Passport processes authentication result
     */
    app.get('/auth/google/callback',

        passport.authenticate('google', {
            session: false, // we are using JWT, not sessions
            failureRedirect: '/login' // redirect on failure
        }),

        /**
         * STEP 3: Generate JWT after successful login
         */
        (req, res) => {

            const token = jwt.sign(
                {
                    id: req.user.id,
                    username: req.user.username
                },
                SECRET_KEY,
                { expiresIn: "1h" }
            );

            /**
             * Redirect user back to React app
             * Token is passed in URL (OK for dev, not ideal for production)
             */
            res.redirect(
                `http://localhost:5173/login-success?token=${token}`
            );
        }
    );
};
