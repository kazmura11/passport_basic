var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
//var usersRouter = require('./routes/users'); // delete

// add start ------
const memberOnlyRouter = require('./routes/member_only');

const session = require('express-session');
const crypto = require('crypto');
const secretKey = 'some_random_secret';
const getHash = (target) => {
  const sha = crypto.createHmac('sha256', secretKey);
  sha.update(target);
  return sha.digest('hex');
};
const flash = require('connect-flash');
const passport = require('passport');
const LocalStorategy = require('passport-local').Strategy;

// Create User Model
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/passport_test',
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

const UserSchema = new mongoose.Schema({
  email: {type: String, required: true},
  password: {type: String, required: true}
});
var User = mongoose.model('User', UserSchema);

// if there are no data, then create new user for debugging
User.countDocuments({}, (err, count) => {
  if (count == 0) {
    console.log('create test user');
    var someone = new User();
    someone.email = 'someone@exmaple.com';
    someone.password = getHash('someone');
    someone.save();
  } else {
    console.log('User already exists.');
  }
});

// session for passport
passport.serializeUser((user, done) => {
  done(null, {email: user.email, _id: user._id});
});
passport.deserializeUser((serializedUser, done) => {
  User.findById(serializedUser._id, function(err, user) {
    done(err, user);
  });
});

passport.use(new LocalStorategy({usernameField: 'email', passwordField: 'password'},
  (email, password, done) => {
    // asynchronously called
    process.nextTick(() => {
      User.findOne({email: email}, (err, user) => {
        console.log('Find user......');
        if (err) {
          console.log('Error occurred');
          return done(err);
        }
        if (!user) {
          console.log('Not found');
          return done(null, false, {message: 'Not found'});
        }
        console.log('check password...');
        const hashedPassword = getHash(password);
        if (user.password !== hashedPassword) {
          return done(null, false, {message: 'Invalid password'});
        }
        console.log('Found');
        return done(null, user);
      })
    });
  }
));

// check if the user logged in
const isLogined = (req, res, next) => {
 if (req.isAuthenticated()) {
   return next();
 }
 // if not, redirect to login page
 res.redirect('/login');
};
// add end ------

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// add start ------
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
// add end ------


app.use('/', indexRouter);
// add start ------
app.use('/member_only', memberOnlyRouter, isLogined);  // check if logged in

app.get('/login', (req, res) => {
  res.render('login', {title: 'Login page', user: req.user, message: req.flash('error')});
});

app.post('/login', passport.authenticate('local',
  {
    failureRedirect: '/login',
    successRedirect: '/',
    failureFlash: true,
  }
));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});
// add end ------

//app.use('/users', usersRouter);   // delete

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
