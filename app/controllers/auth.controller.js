const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const mailchimpClient = require("@mailchimp/mailchimp_transactional")(
  "md-NoaHDun1FDsLRr5ONLzEvw"
);

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
  const user = new User({
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8),
  });

  user.save((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 300, // 24 hours
    });

    async function send(_email, _token) {
      try {
        const response = await mailchimpClient.messages.send({
          message: {
            subject: "Test Email",
            from_email: "support@kitchenft.io",
            to: [
              {
                email: _email,
                type: "to",
              },
            ],
            html: `<!DOCTYPE html>
            <html lang="en">
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
              </head>
              <body>
                <h1 style="color: #fff">Hi there!</h1>
            
                <p style="color: #fff">Please click below button to verify your email.</p>
                <a href="http://localhost:3000/signup/verify/${_token}" style="color: #fff; background-color: #61777f;text-decoration: none; padding: 10px 20px; border-radius: 20px;">Click Me</a>
            
                <p>Thank you!</p>
            
              </body>
            </html>
            `,
          },
        });
      } catch (err) {
        console.log(err);
      }
    }
    send(user.email, token);
    res.status(200).send({
      message: "Email will be sent",
    });
  });
};

exports.signupverify = (req, res) => {
  const decodedId = jwt.decode(req.body.token, config.secret);

  User.findOne({
    _id: decodedId.id,
  }).exec((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    if (!user) {
      return res.status(404).send({ message: "Expired time is over." });
    }

    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400, // 24 hours
    });

    req.session.token = token;

    res.status(200).send({
      message: "User was registered successfully!",
      user: {
        id: user._id,
        email: user.email,
      },
      token: token,
    });
  });
};

exports.signin = (req, res) => {
  User.findOne({
    email: req.body.email,
  }).exec((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    if (!user) {
      return res.status(404).send({ message: "User Not found." });
    }

    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

    if (!passwordIsValid) {
      return res.status(401).send({ message: "Invalid Password!" });
    }

    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400, // 24 hours
    });

    req.session.token = token;

    res.status(200).send({
      message: "User was logined successfully!",
      user: {
        id: user._id,
        email: user.email,
      },
      token: token,
    });
  });
};

exports.forgotpassword = (req, res) => {
  User.findOne({
    email: req.body.email,
  }).exec((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    if (!user) {
      return res.status(404).send({ message: "User Not found." });
    }

    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 300, // 24 hours
    });

    req.session.token = token;

    async function sendforgotpasswordmail(_email, _token) {
      try {
        const response = await mailchimpClient.messages.send({
          message: {
            subject: "Forgot Password",
            from_email: "support@kitchenft.io",
            to: [
              {
                email: _email,
                type: "to",
              },
            ],
            html: `<!DOCTYPE html>
            <html lang="en">
              <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
              </head>
              <body>
                <h1 style="color: #fff">Hi there!</h1>
            
                <p style="color: #fff">Please click below button. I have to check your email before change your password.</p>
                <a href="http://localhost:3000/forgotpassword/verify/${_token}" style="color: #fff; background-color: #61777f;text-decoration: none; padding: 10px 20px; border-radius: 20px;">Click Me</a>
            
                <p>Thank you!</p>
            
              </body>
            </html>
            `,
          },
        });
      } catch (err) {
        console.log(err);
      }
    }
    sendforgotpasswordmail(user.email, token);
    res.status(200).send({
      message: "Email will be sent",
    });
  });
};

exports.forgotpasswordverify = (req, res) => {
  const decodedId = jwt.decode(req.body.token, config.secret);

  User.findOneAndUpdate(
    {
      _id: decodedId.id,
    },
    { password: bcrypt.hashSync(req.body.newpassword, 8) }
  ).exec((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    if (!user) {
      return res.status(404).send({ message: "Expired time is over." });
    }

    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400, // 24 hours
    });

    req.session.token = token;

    res.status(200).send({
      message: "Password is changed successfully!",
      user: {
        id: user._id,
        email: user.email,
      },
      token: token,
    });
  });
};

exports.signout = async (req, res) => {
  try {
    req.session = null;
    return res.status(200).send({ message: "You've been signed out!" });
  } catch (err) {
    this.next(err);
  }
};
