const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
const mailsend = require("../utils/mailsend");

exports.signup = (req, res) => {
  console.log("signup params : ", req.body);
  const user = new User({
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8),
    verify: false,
  });

  user.save((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 300, // 24 hours
    });

    mailsend(
      "Email Verify",
      user.email,
      `http://localhost:3000/signup/verify/${token}`,
      "Please click below button to verify your email"
    );
    res.status(200).send({
      message: "Email will be sent",
    });
  });
};

exports.signupverify = (req, res) => {
  console.log("request data of sign up verify : ", req.body);
  const decodedId = jwt.decode(req.body.token, config.secret);
  console.log("Decode Id : ", decodedId);

  User.findOneAndUpdate(
    {
      _id: decodedId.id,
    },
    { verify: true }
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

    if (!user.verify) {
      return res.status(404).send({
        message: "You are not verified yet. Please verify your email!",
      });
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

    mailsend(
      "Forgot Password",
      user.email,
      `http://localhost:3000/forgotpassword/verify/${token}`,
      "Please click below button to verify your email"
    );
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

exports.changeemail = (req, res) => {
  User.findOneAndUpdate(
    {
      email: req.body.email,
    },
    { email: req.body.newemail }
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

    mailsend(
      "Email Verify",
      req.body.newemail,
      `http://localhost:3000/signup/verify/${token}`,
      "Please click below button to verify your new email"
    );
    res.status(200).send({
      message: "Email will be sent",
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
