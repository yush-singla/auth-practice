//jshint esversion:6
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const app = express();
require('dotenv').config();
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy; //this is a strategy just like local strategy to verify / authenticate using passport
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');


app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
//this sets up our session
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());

app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: [String],
  googleId: String,
  facebookId: String,
});
//plugins must be applied to mongoose schema and not just a javascript object
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
//here we create a strategy that we use later on in the code to authenticate the user
passport.use(User.createStrategy());
//this is basically creating the cookie and breaking that cookie as and when required(ie at each session)
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //it searches our database and finds or create a person with the google id
    //we must store the google id in our schema to make it work
    // console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});
app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/secrets", function(req, res) {
  //isAuthenticated basically comes from passport and looks for a cookie in the
  //session that shows that our request isAuthenticated or not if it is not
  //then it return false else it returns true
  if (req.isAuthenticated()) {
    User.find({
      "secret": {
        $ne: null
      }
    }, function(err, foundUsers) {
      if (err) {
        console.log(err);
      }

      res.render("secrets", {
        user: foundUsers
      });
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit")
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile']
}));

app.get('/auth/google/secrets', passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect secretes.
    res.redirect("/secrets");
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.post("/register", function(req, res) {
  //register is a passportLocalMongoose feature which we are able to use here cause of
  //the plugin that we made earlier and it basically creates a user for us and
  //saves it into our database after doing all the hashing and salting with the help
  //of passport hence we don't even need to directly interact with mongoose any longer to
  //save the user into the databaser
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      //here we are authenticating the user using the local Strategy via passport
      //when they are logged in we also set up a logged in session for them
      //and save a cookie in their browser so that they don't need to login again till browser is open
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", function(req, res) {


    const submittedSecret = req.body.secret;
    if (req.user) {
      User.findById(req.user.id, function(err, foundUser) {
        if (err) {
          console.log(err);
        } else if (foundUser) {
          foundUser.secret.push(submittedSecret.substr(0,1).toUpperCase()+submittedSecret.substr(1));
          foundUser.save();
        }
        res.redirect("/secrets");
      });

    } else {
      res.redirect("/login");
    }

});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  //here passport searches the db for the matching username and then when it does'nt
  //find one it returns back err
  //after Successful login it also stores a user in req to be able to be accesed anywhere we
  //want to acces it
  req.login(user, function(err) {
    // console.log("got here");
    //even if the password is wrong then also it will come here
    //it is only at the authenticate point that we actually verify the password
    //if not verified we indeed return Unauthorized
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, function() {
        // console.log("auth");
        res.redirect("/secrets");
      });
    }
  });

});






app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
