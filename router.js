const Authenticaiton = require("./controllers/authentication");
const passportService = require("./services/passport");
const passport = require("passport");

const requireAuth = passport.authenticate("jwt", { session: false });
const requireSignIn = passport.authenticate("local", { session: false });

module.exports = app => {
  app.get("/", requireAuth, function(req, res) {
    res.send({ hi: "there" });
  });
  app.post("/signin", requireSignIn, Authenticaiton.signin);
  app.post("/signup", Authenticaiton.signup);
};
