const controller = require("../controllers/auth.controller");
const authJwt = require("../middlewares/authJwt");
const signValidate = require("../middlewares/signValidate");

module.exports = function (app) {
  app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept");
    next();
  });

  app.post(
    "/api/auth/signup",
    [signValidate.signupandinValidate, signValidate.signupValidate],
    controller.signup
  );

  app.post("/api/auth/signup/verify", controller.signupverify);

  app.post(
    "/api/auth/signin",
    [signValidate.signupandinValidate],
    controller.signin
  );
  app.post(
    "/api/auth/signin/token",
    [authJwt.verifyToken],
    controller.signinwithtoken
  );

  app.post("/api/auth/forgotpassword", controller.forgotpassword);

  app.post("/api/auth/changeemail", controller.changeemail);

  app.post("/api/auth/forgotpassword/verify", controller.forgotpasswordverify);

  app.post("/api/auth/signout", controller.signout);
};
