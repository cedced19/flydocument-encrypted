var express = require('express');
var router = express.Router();
var auth = require('../policies/auth');
var crypto = require('crypto');
var fs = require('fs');
var tika = require('tika');
var config = require('../configuration.json');
var existsFile = require('exists-file');
var multer = require('multer')({
  dest: config.files_folder
});

/* GET Files: get all files */
router.get('/', auth, function(req, res, next) {
    fs.readdir(config.files_folder, function (err, files) {
      if (err) {
        err = new Error('Cannot get files.');
        err.status = 500;
        return next(err);
      }
      res.locals.files = files.map(function (name) {
        return name.replace('.enc', '')
      });
      res.render('files-list', {error: req.flash('error'), message: req.flash('message'), file: req.flash('file')});
    });
});

/* GET Delete file: delete an user */
router.get('/delete/:id', auth, function(req, res, next) {
    fs.unlink(config.files_folder + req.params.id + '.enc', function (err) {
      if (err) {
        res.status = 500;
        req.flash('error', 'file-deleting-error');
        req.flash('file', req.params.id);
      } else {
        req.flash('message', 'file-deleted');
      }
      res.redirect('/files/');
    });
});

/* POST File: create a file */
router.post('/new', auth, multer.single('file'), function(req, res, next) {
    if (req.file === undefined) {
      err = new Error('You must upload a file.');
      err.status = 400;
      return next(err);
    }
    var path = config.files_folder + req.file.filename;

    var cipher = crypto.createCipher('aes256', crypto.createHmac('sha256', config.hashsecret).update(req.body.passphrase).digest('hex'));
    var input = fs.createReadStream(path);
    var output = fs.createWriteStream(path + '.enc');
    input.pipe(cipher).pipe(output);
    fs.unlink(path, function (err) {
      if (req.xhr || req.headers.accept.indexOf('json') > -1) {
        res.json({
          filename: req.file.filename
        });
      } else {
        res.locals.filename = req.file.filename;
        res.render('file-uploaded');
      }
    });
});

/* GET File: get a file */
router.get('/:filename', function(req, res, next) {
    var path = config.files_folder + req.params.filename;
    if (req.query.passphrase === undefined) {
      err = new Error('You must give a passphrase.');
      err.status = 400;
      return next(err);
    }
    existsFile(path + '.enc', function (err, exists) {
      if (exists) {
        var decipher = crypto.createDecipher('aes256', crypto.createHmac('sha256', config.hashsecret).update(req.query.passphrase).digest('hex'));
        var input = fs.createReadStream(path + '.enc');
        var output = fs.createWriteStream(path);
        input.pipe(decipher).pipe(output);
        decipher.on('error', function (err) {
            decipher.emit('close');
            fs.unlink(path, function (err) {
              var err = new Error('Bad passphrase.');
              err.status = 400;
              next(err);
            });
        });
        decipher.on('end', function () {
          tika.type(path, function(err, result) {
              if (err) next(err);
              res.setHeader('Content-Type', result);
              fs.createReadStream(path).pipe(res);
              fs.unlink(path);
          });
        });
      } else {
        var err = new Error('No file available at this adress.');
        err.status = 400;
        next(err);
      }
    });
});

/* GET File: render view to give the passphrase */
router.get('/access/:filename/', function(req, res) {
  existsFile(config.files_folder + req.params.filename + '.enc', function (err, exists) {
    if (exists) {
      res.locals.filename = req.params.filename;
      res.render('access-file');
    } else {
      var err = new Error('No file available at this adress.');
      err.status = 400;
      next(err);
    }
  });

});

module.exports = router;
