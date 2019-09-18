const bcrypt = require('bcryptjs');
const secrets = require('../config/secrets.js');
const Users = require('../users/users-model.js');

const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
      if (err) {
        //token is bad
        res.status(401).json({ message: 'your shall not pass!' });
      } else {
        //token is good
        // could add the user to the req object
        req.user = { username: decodedToken.username };
        next();
      }
    });
  } else {
    res.status(400).json({ message: 'no credentials provided' });
  }
};
