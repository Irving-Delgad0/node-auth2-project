const bcrypt = require('bcryptjs')
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model')

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body
  const hash = bcrypt.hashSync(user.password, 8)
  user.password = hash

  Users.add(user)
  .then(user => {
    res.status(201).json(user)
  }).catch(next)

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let {username, password} = req.body

  Users.findBy({username})
  .then(([user]) => {
    if(user && bcrypt.compareSync(password, user.password)) {
      const token = generateToken(user)
      res.status(200).json({message: `${user.username} is back!`, token})
    } else {
      next({status: 401, message: 'invalid credentials'})
    }
  })
  .catch(next)
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

const generateToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name, //must match table names!!!!
  }; 
  const options = { expiresIn: '1d' };
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
