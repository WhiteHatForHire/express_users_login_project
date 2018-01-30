var express = require("express");
var router = express.Router();

var expressValidator = require('express-validator');

var bcrypt = require('bcrypt');
const saltRounds = 10;


/* GET register page. */
router.get("/register", function(req, res, next) {
  res.render("register", { title: "Registration" });
});
/* GET home page. */
router.get("/", function(req, res) {
  res.render("home", { title: "Home" });
});

// add user to db
router.post("/register", function(req, res, next) {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  // VALIDATION with express-validator
  req.checkBody('username', 'Username fields cannot be empty.').notEmpty();
  req.checkBody('username', 'Username must be between 4-15 characters long').len(4, 15);
  req.checkBody('email', 'The email you entered is invalid, please try again').isEmail();
  req.checkBody('email', 'Email address must be between 4-100 characters long, please try again.').len(4, 100);
  req.checkBody('password', 'Password must be between 8-100 characters long.').len(8, 100);
  req.checkBody('password', 'Password must include one lowercase character, one uppercase character, a number, and a special character.').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i");
  req.checkBody('passwordMatch', 'Re-entered password must be between 8-100 characters long.').len(8, 100);
  req.checkBody('passwordMatch', 'Passwords do not match, please try again.').equals(password);

  const errors = req.validationErrors();

  if (errors) {
    console.log(`errors: ${JSON.stringify(errors)}`);

    res.render("register", { title: "Registration Error", errors: errors });
    return;
  } else {
    const db = require("../db.js");

    bcrypt.hash(password, saltRounds, function(err, hash) {
      // Store hash in your password DB.
      db.query(
      // Entering with auto escaping to protect against malicious code
        "INSERT INTO  users (username, email, password) VALUES (?,?,?)",
        [username, email, hash],
        function(error, result, fields) {
          if (error) throw error;

          res.render("register", {
            title: "Registration Complete",
            success: "You have successfully registered"
          });
        }
      );
    });
  }
  
});

module.exports = router;
