var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var i18n = require('i18n-express');
var compression = require('compression');
var minifyTemplate = require('express-beautify').minify;
var minifyCSS = require('express-minify');

var index = require('./routes/index');
var files = require('./routes/files-api');
var users = require('./routes/users-api');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

if (app.get('env') === 'development') {
  app.use(logger('dev'));
} else {
  app.use(compression());
  app.use(minifyTemplate());
  app.use(minifyCSS());
}

app.use(express.static(path.join(__dirname, 'public')));

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(i18n({
  translationsPath: path.join(__dirname, 'i18n'),
  cookieLangName: 'language',
  paramLangName: 'lang',
  siteLangs: ['en','fr']
}));

app.use('/', index);
app.use('/files', files);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  var code = (err.status || 500);

  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.code = code;
  res.locals.error = req.app.get('env') === 'development' ? err : {};


  // render the error page
  res.status(code);
  res.render('error');
});

module.exports = app;
