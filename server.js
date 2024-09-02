require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcrypt');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MongoStore = require('connect-mongo');

const app = express();

// Connect to MongoDB using a connection string with environment variables
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User schema and model
const userSchema = new mongoose.Schema({
  googleId: String,
  email: { type: String, unique: true, required: true },
  password: String,
});

const User = mongoose.model('User', userSchema);

// Middleware setup
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: 'secretkey',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
    }),
    cookie: {
      maxAge: 1000 * 60 * 60, // 1 hour session time
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Passport config for Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const existingUser = await User.findOne({ googleId: profile.id });
        if (existingUser) {
          return done(null, existingUser);
        }

        const newUser = await new User({
          googleId: profile.id,
          email: profile.emails[0].value,
        }).save();
        done(null, newUser);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => User.findById(id).then((user) => done(null, user)));

// Routes
app.get('/', (req, res) => res.render('index'));

// Handle Signup
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  // Check if the user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.send('User already exists. Please login.');
  }

  // Hash the password before saving to the database
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create a new user
  const newUser = new User({
    email,
    password: hashedPassword,
  });

  try {
    await newUser.save();
    res.redirect('http://127.0.0.1:5000/'); // Redirect after successful signup
  } catch (err) {
    res.status(500).send('Error signing up. Please try again.');
  }
});

// Handle Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  const user = await User.findOne({ email });
  if (!user) {
    return res.send('Incorrect email or password.');
  }

  // Check if the password matches
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.send('Incorrect email or password.');
  }

  // Successful login
  res.redirect('http://127.0.0.1:5000/'); // Redirect after successful login
});

// Google Auth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Successful authentication, redirect to the desired URL
    res.redirect('http://127.0.0.1:5000/');
  }
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('http://127.0.0.1:5000/')); // Redirect after logout
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
