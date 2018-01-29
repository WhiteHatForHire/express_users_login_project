var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Registration' });
});

router.post('/register', function(req, res, next) {
  console.log(req.body.username);
  console.log(req.body.email);
  console.log(req.body.password);

  const db = require('../db.js');
  res.render('index', { title: 'Registration Complete' });
});



module.exports = router;
