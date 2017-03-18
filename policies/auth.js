var getUser = function (config, email) {
  for (var i in config.users) {
    if (config.users[i].email == email)  {
      return config.users[i];
    }
  }
  return false;
};
var auth = require('basic-auth');
var bcrypt = require('bcrypt');

module.exports = function(req, res, next) {
  var config = require('../configuration.json');
  if (config.users.length == 0) {
    next();
  } else {
    var credentials = auth(req);
    if (!credentials) {
      res.set('WWW-Authenticate', 'Basic realm="You have to give an email and a password."');
      var err = new Error('You have to give an email and a password.');
      err.status = 401;
      return next(err);
    }
    var user = getUser(config, credentials.name);
    if (!user) {
      var err = new Error('Bad email.');
      err.status = 401;
      return next(err);
    }
    bcrypt.compare(credentials.pass, user.password, function(err, res) {
      console.log(err)
      if (res) {
        next();
      } else {
        var err = new Error('Bad password.');
        err.status = 401;
        return next(err);
      }
    });
  }
};
