const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcrypt-nodejs");

// Define our model - create a schema that defines the types on the properties...
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true }, // Email needs to be unique... lowercase and unique handle this...
  password: String
});

// On Save Hook, encrypt password

// Before saving a model, run this function (pre)
userSchema.pre("save", function(next) {
  // Get access to user model
  const user = this;

  // Generate a salt, then run callback
  bcrypt.genSalt(10, function(err, salt) {
    if (err) {
      return next(err);
    }

    // Hash (encrypt) our password using the salt, then run callback
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) {
        return next(err);
      }

      // Overwrite plain text password with encrypted password
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) {
      return callback(err);
    }
    callback(null, isMatch);
  });
};

// Create the model class - loads model into mongoose
const ModelClass = mongoose.model("user", userSchema);

// Export the model
module.exports = ModelClass;
