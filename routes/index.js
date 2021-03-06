var express = require("express");
var router = express.Router();

var expressValidator = require('express-validator');
var passport = require('passport');



var bcrypt = require('bcrypt');
const saltRounds = 10;


/* GET register page. */
router.get("/register", function(req, res, next) {
  res.render("register", { title: "Registration" });
});
/* GET home page. */
router.get("/", function(req, res) {
	console.log(req.user);
	console.log(req.isAuthenticated());
  res.render("home", { title: "Home" });
});

/* GET profile page. */
// Here we call the authenticationMiddleware function to restrict access to this
// particular view, the profile page. Users without permission will get redirected to the 
// Login page 
// THIS CAN BE CHANGED I THINK TO DIRECT TO OTHER PAGES DEPENDING ON CIRCUMSTANCES
router.get('/profile', authenticationMiddleware(),function(req, res){
  res.render('profile', {title: 'Profile'});
});
/* GET login page. */
router.get('/login', function(req, res){
  res.render('login', {title: 'Login'});
});
/* GET logout page and session logout. */
router.get('/logout', function(req, res){
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

// POST LOGIN
router.post("/login", passport.authenticate(
  'local', {
    successRedirect : '/profile',
    failureRedirect: '/login'
  }));


// add user to db
router.post("/register", function(req, res, next) {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  // VALIDATION with express-validator
  // THESE ARE VERY STRICT, MAY WANT TO REVISIT
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
    // return;
  } else {
    const db = require("../db.js");

    bcrypt.hash(password, saltRounds, function(err, hash) {
      // Store hash in your password DB.
      db.query(
      // Entering with auto escaping to protect against malicious code
        "INSERT INTO  users (username, email, password) VALUES (?,?,?)",
        [username, email, hash],
        function(error, results, fields) {
          if (error) throw error;


          db.query('SELECT LAST_INSERT_ID() as user_id', function(error, results, fields){
						if(error) throw error;
						

						const user_id = results[0];
						console.log(results[0]);
            req.login(user_id, function(err) {
							res.redirect('/');
						});
						// res.render("register", {
						// 	title: "Registration Complete",
						// 	success: "You have successfully registered"
						// });	
            
          });
        }

      );
    });
  }
});

          
passport.serializeUser(function(user_id, done) {
  done(null, user_id);
});

passport.deserializeUser(function(user_id, done) {
    done(null, user_id);
});

// Restricted access
function authenticationMiddleware () {  
	return (req, res, next) => {
		console.log(`req.session.passport.user: ${JSON.stringify(req.session.passport)}`);

	    if (req.isAuthenticated()) return next();
	    res.redirect('/login');
	};
}

module.exports = router;
