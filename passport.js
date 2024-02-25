const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const db = require('./firestore');
const User = db.collection('users');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_EXPIRATION = process.env.JWT_EXPIRATION || '1h';
const JWT_REFRESH_EXPIRATION = process.env.JWT_REFRESH_EXPIRATION || '7d';

const generateAccessToken = (user) => {
  return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: JWT_EXPIRATION });
};

const generateRefreshToken = (user) => {
  return jwt.sign(user, process.env.JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRATION });
};

const storeRefreshToken = async (userId, refreshToken) => {
  const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
  await User.doc(userId).update({ refreshToken: hashedRefreshToken });
};

const invalidateRefreshToken = async (userId) => {
  await User.doc(userId).update({ refreshToken: null });
};

passport.use(
  new LocalStrategy({ usernameField: 'username' }, (username, password, done) => {
    User.where('username', '==', username).get()
      .then(snapshot => {
        if (snapshot.empty) {
          return done(null, false, { message: 'No user found with this username.' });
        }

        const user = snapshot.docs[0].data();
        bcrypt.compare(password, user['password'], (err, match) => {
          if (err) {
            throw err;
          }

          if (!match) {
            return done(null, false, { message: 'Password does not match.' });
          } else {
            // JWT payload should contain only the necessary user details
            const payload = {
              id: user.id,
              username: user.username,
              role: user.role,
            };
            return done(null, payload);
          }
        });
      })
      .catch(err => {
        console.log(err);
        return done(null, false, { message: 'Failed to retrieve user.' });
      });
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = User.doc(id).get()
    .then(user => done(null, user))
    .catch(err => done(err, user));
});

module.exports = (app) => {
  app.use(passport.initialize());
  app.use(passport.session());

  app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
      if (err) {
        return next(err);
      }

      if (!user) {
        return res.status(401).json({ success: false, error: info.message });
      }

      req.logIn(user, function (err) {
        if (err) {
          return next(err);
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        storeRefreshToken(user.id, refreshToken);

        return res.status(200).json({
          success: true,
          user, 
          accessToken,
          refreshToken,
        });
      });
    })(req, res, next);
  });

  app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, error: "Username and password are required." });
    }
    
    const usernameOrEmailPattern = /^[a-zA-Z0-9-_.@ ]+$/;
    if (!usernameOrEmailPattern.test(username)) {
      return res.status(400).json({ error: "Username contains invalid characters." });
    }

    User.where('username', '==', username).get()
      .then(snapshot => {
        if (!snapshot.empty) {
          // If user already exists, return an error
          return res.status(400).json({ success: false, error: "Username already exists." });
        }

        // If user does not exist, continue with registration
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
            console.log(err);
            return res.status(500).json({ success: false, message: "Server error." });
          }
          const user = {
            id: username,
            username: username,
            password: hashedPassword,
            role: 'user',
          };

          User.doc(user.id).set(user)
            .then(() => {
              res.status(201).json({ success: true });
            })
            .catch((err) => {
              console.log(err);
              res.status(500).json({ success: false, message: "Server error." });
            });
        });
      })
      .catch(err => {
        console.log(err);
        res.status(500).json({ success: false, message: "Server error." });
      });
  });

  app.post('/api/logout', isAuth, async (req, res) => {
    const userId = req.user.id;
    invalidateRefreshToken(userId);
    // req.logout();
    res.status(200).json({ success: true });
  });

  // function to validate invite code
  app.post('/api/validate-invite', (req, res) => {
    const { inviteCode } = req.body;

    if (inviteCode === process.env.INVITE_CODE) {
      res.status(200).json({ success: true });
    } else {
      res.status(401).json({ success: false, message: "Invalid invite code." });
    }
  });

  // function to create a guest account
  app.post('/api/guest', async (req, res) => {
    try {
      const guestId = uuidv4();

      const guestUser = {
        id: guestId, 
        role: 'guest',
        created: Date.now(),
      };

      await User.doc(guestId).set(guestUser);

      const accessToken =  generateAccessToken(guestUser);
      const refreshToken = generateRefreshToken(guestUser);

      storeRefreshToken(guestId, refreshToken);

      return res.status(200).json({
        success: true,
        user: guestUser, 
        accessToken,
        refreshToken,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error while creating guest account." });
    }
  });

  // function to upgrade a guest account to a full account
  app.post('/api/upgrade', isAuth, isGuest, async (req, res) => {
    console.log('upgrade request');
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ success: false, message: "Username and password are required." });
      }

      // Check if username already exists
      const snapshot = await User.where('username', '==', username).get();
      if (!snapshot.empty) {
        return res.status(400).json({ success: false, message: "Username already exists." });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Update the guest account to a full account
      const userId = req.user.id;

      const upgradedUser = {
        username,
        password: hashedPassword,
        role: 'user',
        upgradedFromGuest: Date.now(),
      }

      await User.doc(userId).update(upgradedUser);

      const upgradedUserWithId = { ...upgradedUser, id: userId, };

      const accessToken = generateAccessToken(upgradedUserWithId);
      const refreshToken = generateRefreshToken(upgradedUserWithId);
      storeRefreshToken(userId, refreshToken);

      return res.status(200).json({
        success: true,
        accessToken,
        refreshToken,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: "Server error during account upgrade." });
    }
  });

  app.post('/api/token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ success: false, error: 'Refresh token is required' });
    }
  
    // Decode the refresh token without verifying to extract the user ID
    let payload = null;
    try {
      payload = jwt.decode(refreshToken);
      if (!payload) {
        return res.status(401).json({ success: false, error: 'Invalid refresh token' });
      }
    } catch (err) {
      return res.status(401).json({ success: false, error: err.message });
    }
  
    // Retrieve the stored hashed refresh token from the database
    let storedRefreshToken;
    try {
      const userData = await User.doc(payload.id).get();
      storedRefreshToken = userData.data().refreshToken;
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to retrieve refresh token' });
    }
  
    // Verify the stored refresh token with the provided token
    bcrypt.compare(refreshToken, storedRefreshToken, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ success: false, error: 'Refresh token is invalid' });
      }
  
      // Verify the actual content of the refresh token
      jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, user) => {
        if (err) {
          return res.status(403).json({ success: false, error: 'Refresh token is expired or invalid' });
        }

        const userWithoutExp = {
          id: user.id,
          username: user.username,
          role: user.role,
        };
  
        // Issue a new access token
        const accessToken = generateAccessToken(userWithoutExp);

        res.status(200).json({
          success: true,
          accessToken,
        });
      });
    });
  });

  // endpoint to check if the user is authenticated
  app.get('/api/authenticated', isAuth, (req, res) => {
    res.status(200).json({ success: true, user: req.user });
  });
}

function isAuth(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ error: "Access denied: no token provided." });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: "Access denied: invalid auth format." });
  }

  const token = parts[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ error: `Access denied: ${err.message}` });
    }

    req.user = user;
    next();
  });
}

function isGuest(req, res, next) {
  if (req.user && req.user.role === 'guest') {
    next();
  } else {
    res.status(403).json({ message: "Access denied: not a guest account." });
  }
}

module.exports.isAuth = isAuth;
module.exports.isGuest = isGuest;
