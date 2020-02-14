const passport = require("passport");
const User = require("../models/user");
const config = require("../config");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local");

// Create local strategy
// Will use username instead of email by default, so we specify a custom usernameField.
const localOptions = { usernameField: "email" };
const localLogin = new LocalStrategy(localOptions, function(
  email,
  password,
  done
) {
  // Verify this email and password, call done with the user
  // if it is the correct email and password,
  // otherwise, call done with false.
  User.findOne({ email }, function(err, user) {
    if (err) {
      return done(err);
    }

    if (!user) {
      return done(null, false);
    }

    // Compare passwords logic -
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        return done(err);
      }
      if (!isMatch) {
        return done(null, false);
      }

      return done(null, user);
    });
  });
});

// Set up options for JWT strategy
const jwtOptions = {
  // Tells passport where to look for token - In Header: Authorization
  jwtFromRequest: ExtractJwt.fromHeader("authorization"),
  // Tells passport secret to use from token.
  secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if the user ID in the payload exists in our database
  // If it does, call "done" with that user and eventually allow access

  // Otherwise, call doine without a user object, no access will be allowed.

  User.findById(payload.sub, function(err, user) {
    if (err) {
      return done(err, false);
    }

    if (user) {
      // User found.
      done(null, user);
    }
    // No user found.
    else {
      done(null, false);
    }
  });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
