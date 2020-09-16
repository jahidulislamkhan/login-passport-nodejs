const express = require('express')
const bcrypt = require('bcryptjs');
const passport = require('passport');
const router = express.Router();
const { forwardAuthenticated, ensureAuthenticated } = require("../config/auth");
// User model
const User = require('../models/User');

// Login route
router.get("/login", forwardAuthenticated, (req, res) => res.render("login"));
// Register route
router.get("/register", forwardAuthenticated, (req, res) =>
  res.render("register")
);
// Handle register
router.post("/register", forwardAuthenticated, (req, res) => {
  const { name, email, password, password2 } = req.body;
  const errors = [];
  // Check required fields
  if (!name || !email || !password || !password2) {
    errors.push({ msg: "Please fill in all the required fields" });
  }
  // Check passwords match
  if (password !== password2) {
    errors.push({ msg: "Passwords do not match" });
  }
  // Check password length
  if (password && password.length < 6) {
    errors.push({ msg: "Password must be at least 6 characters" });
  }
  if (errors.length > 0) {
    res.render("register", {
      errors,
      name,
      email,
      password,
      password2,
    });
  } else {
    // Validation passed
    User.findOne({ email }).then((user) => {
      if (user) {
        // User exists
        errors.push({ msg: "This email has already been taken" });
        res.render("register", {
          errors,
          name,
          email,
          password,
          password2,
        });
      } else {
        const newUser = new User({
          name,
          email,
          password,
        });
        // Hashed Password
        bcrypt.genSalt(10, (err, salt) => {
          if (err) throw err;
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then((user) => {
                req.flash(
                  "success_msg",
                  "Registered successfully and login now"
                );
                res.redirect("/users/login");
              })
              .catch((err) => console.log(err));
          });
        });
      }
    });
  }
});
// Login route
router.post("/login", forwardAuthenticated, (req, res, next) => {
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true,
  })(req, res, next);
});
// Logout route
router.get("/logout", ensureAuthenticated, (req, res) => {
  req.logOut();
  req.flash("success_msg", "You are now logged out!");
  res.redirect("/users/login");
});

module.exports = router;
