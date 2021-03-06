var express = require("express");
var path = require("path");
var favicon = require("serve-favicon");
var logger = require("morgan");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");
var expressValidator = require("express-validator");

// Authentication Packages
var session = require("express-session");
var passport = require("passport");
var LocalStrategy = require("passport-local")
  .Strategy; /* this should be after passport*/
var MySQLStore = require("express-mysql-session")(session);
var bcrypt = require('bcrypt');


var index = require("./routes/index");
var users = require("./routes/users");

var app = express();

require("dotenv").config();

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "hbs");

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(expressValidator());
app.use(cookieParser());

// MYSQL SESSION
var options = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
};

var sessionStore = new MySQLStore(options);

// Express Session Cookie
app.use(
  session({
    secret: "eiwokdjflaehinfoow",
    resave: false,
    store: sessionStore,
    saveUninitialized: false
    // cookie: { secure: true }
  })
);

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

app.use(function(req, res, next){
    res.locals.isAuthenticated = req.isAuthenticated();
    next();
});

app.use(express.static(path.join(__dirname, "public")));

app.use("/", index);
app.use("/users", users);

// PASSPORT LOCAL STRATEGY
passport.use(new LocalStrategy(
    function(username, password, done) {
    console.log(username);
    console.log(password);
    const db = require("./db");
    // VALIDATE USER
    db.query("SELECT id, password FROM users WHERE username = ?",[username],function(err, results, fields) {
        if(err) {done(err)};

        if(results.length === 0) {
          done(null, false);
        } else {
          // COMPARE PASWORD TO HASHED IN DB (must convert from buffer with toString())
          const hash = (results[0].password.toString());
          bcrypt.compare(password, hash, function(err, response){
          if (response === true) {
            return done(null, {user_id: results[0].id});
          } else {
            return done(null, false);
          }
        });
        }
    })
  }
));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error("Not Found");
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

// Handlebars default config
const hbs = require("hbs");
const fs = require("fs");

const partialsDir = __dirname + "/views/partials";

const filenames = fs.readdirSync(partialsDir);

filenames.forEach(function(filename) {
  const matches = /^([^.]+).hbs$/.exec(filename);
  if (!matches) {
    return;
  }
  const name = matches[1];
  const template = fs.readFileSync(partialsDir + "/" + filename, "utf8");
  hbs.registerPartial(name, template);
});

hbs.registerHelper("json", function(context) {
  return JSON.stringify(context, null, 2);
});

module.exports = app;
