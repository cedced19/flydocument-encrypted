var express = require('express');
var passport = require('passport');
var router = express.Router();

/* GET home page */
router.get('/', function(req, res, next) {
  var config = require('../configuration.json');
  if (config.users.length == 0) {
    res.redirect('/users/new');
  } else if (!req.isAuthenticated()) {
    res.redirect('/login');
  } else {
    res.render('index');
  }
});

router.get('/login', function(req, res) {
    res.render('login');
});

router.post('/login', passport.authenticate('local'), function(req, res) {
    if (req.xhr) {
        res.json(req.user);
    } else {
        res.redirect('/');
    }
});

router.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

module.exports = router;
