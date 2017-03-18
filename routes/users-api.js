var express = require('express');
var router = express.Router();
var auth = require('../policies/auth');
var fs = require('fs');
var bcrypt = require('bcrypt');
var config = require('../configuration.json');

var getUser = function (email) {
  for (var i in config.users) {
    if (config.users[i].email == email) {
      return {user: config.users[i], key: i };
    }
  }
  return false;
};

var saveConfiguration = function (cb) {
  fs.writeFile('./configuration.json', JSON.stringify(config), cb);
};

/* GET Users: get all users */
router.get('/', auth, function(req, res) {
    res.render('users-list');
});

/* GET New user: create new account */
router.get('/new/', auth, function(req, res) {
    res.render('new-account');
});

/* POST New user: save new user */
router.post('/new/', auth, function(req, res, next) {
    if (!getUser(req.body.email)) {
      bcrypt.hash(req.body.password, 10, function(err, hash) {
        config.users.push({
          password: hash,
          email: req.body.email
        });
        saveConfiguration(function(err) {
            if(err) {
              err = new Error('Error saving the new user.');
              err.status = 500;
              return next(err);
            }
            res.locals.success = 'user-saved';
            res.render('success-page');
        });
      });
    } else {
      var err = new Error('Email already exists.');
      err.status = 400;
      return next(err);
    }
});

module.exports = router;
