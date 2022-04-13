const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const url = require('url');
const generator = require('generate-password');
const { google } = require('googleapis');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const auth = require('../middleware/auth');
const User = require('../model/User');
const Token = require('../model/Token');
const {
  loginValidation,
  registerValidation,
  editUserValidation,
} = require('../validation');

// @desc    Get All Users
// @route   GET /auth/users
// @access  admin
router.get('/users', paginatedResults(User), auth, async (req, res) => {
  const user = await User.findById(req.user._id);

  // Validate if admin
  if (!user.isAdmin) {
    return res.status(401).send('Unauthorized');
  }

  try {
    res.status(200).json(res.paginatedResults);
  } catch (err) {
    res.status(500).json(err.message);
  }
});

// @desc    Register a new user
// @route   POST /auth/register
// @access  public
router.post('/register', async (req, res) => {
  // Validation
  const { error } = registerValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  // Check for duplicates
  const emailExists = await User.findOne({ email: req.body.email });
  if (emailExists) return res.status(400).send('Email already exists');

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(req.body.password, salt);

  // Create a new user
  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashPassword,
  });

  try {
    const newUser = await user.save();
    res.status(201).send(newUser);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Init OAuth2
const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.REDIRECT_URL,
);

const scopes = [
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/userinfo.email',
];

// @desc Send the OAuth2 link to client
// @route GET /auth/google/
// @access public
router.get('/google', async (req, res) => {
  // Generate OAuth2 link for OAuth2 workflow
  const authorizeUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
  });

  // Go through the OAuth2 content workflow.
  try {
    res.status(200).send(authorizeUrl);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// @desc Retrieve the full client from OAuth2 workflow
// @route GET /auth/google/callback
// @access public
router.get('/google/callback', async (req, res) => {
  // Acquire the code from the querystring
  const qs = new url.URL(req.url, 'http://localhost:8080').searchParams;
  const code = qs.get('code');

  // Acquire tokens with code & set the credentials on the OAuth2 client
  const { tokens } = await oAuth2Client.getToken(code);
  oAuth2Client.setCredentials(tokens);

  // Get token info from OAuth2Client response
  const tokenInfo = await oAuth2Client.getTokenInfo(oAuth2Client.credentials.access_token);

  // Get user credentials from Google people API
  const peopleAPIResponse = await oAuth2Client.request({ url: 'https://people.googleapis.com/v1/people/me?personFields=names' });

  // User data
  const userEmail = tokenInfo.email;
  const userName = peopleAPIResponse.data.names[0].displayName;
  const userGoogleId = peopleAPIResponse.data.names[0].metadata.source.id;

  // Find the user with the same Email as OAuth Email
  let user = await User.findOne({ email: userEmail });

  // If user without googleId exists in database, verify
  if (user && !user.googleId) {
    const pathName = 'http://localhost:3000/account/validation';
    const query = `?userId=${user._id}&googleId=${userGoogleId}&email=${userEmail}&name=${userName}`;

    return res.redirect(302, `${pathName}/${query}`);
  }

  // If user with googleId exists in database
  if (user && user.googleId) {
    // Create and assign jwt token
    const token = jwt.sign({ _id: user._id }, process.env.JWT_TOKEN_SECRET);

    const pathName = 'http://localhost:3000';
    const query = `?token=${token}`;

    // Log user in, redirect to /
    return res.redirect(302, `${pathName}/${query}`);
  }

  // If OAuth user does not exists in database
  if (!user) {
    // Make a random password that is required by User model
    const password = generator.generate({
      length: 40,
      numbers: true,
      symbols: true,
    });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    // Make a new user, add to database
    const newUser = new User({
      googleId: userGoogleId,
      name: userName,
      email: userEmail,
      password: hashPassword,
    });

    try {
      await newUser.save();

      // Request a new user to get user._id
      user = await User.findOne({ email: userEmail });

      // Create and assign jwt token
      const token = jwt.sign({ _id: user._id }, process.env.JWT_TOKEN_SECRET);

      const pathName = 'http://localhost:3000';
      const query = `?token=${token}`;

      // Log user in, redirect to /
      return res.redirect(302, `${pathName}/${query}`);
    } catch (err) {
      res.status(400).send(err.message);
    }
  }
});

// @desc    Validate user & add google sign in method
// @route   PATCH /auth/validation
// @access  public
router.patch('/validation', async (req, res) => {
  // Check if the email exists
  const user = await User.findById(req.body.userId);
  if (!user) return res.status(500).send('Validation error, please try again later');

  // Check if password is correct
  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass) return res.status(400).send('Invalid Password!');

  user.googleId = req.body.googleId;

  // Update user password
  try {
    await user.save();

    // Create, assign jwt token & send user credentials
    const token = jwt.sign({ _id: user._id }, process.env.JWT_TOKEN_SECRET);
    res.status(201).header('x-auth-token', token).send({
      token,
      id: user._id,
      name: user.name,
      email: user.email,
      wishList: user.wishList,
      admin: user.isAdmin,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @desc    Log in
// @route   POST /auth/login
// @access  public
router.post('/login', async (req, res) => {
  // Validation
  const { error } = loginValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  // Check if the email exists
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send('Incorrect credentials');

  // Check if password is correct
  const validPass = await bcrypt.compare(req.body.password, user.password);
  if (!validPass) return res.status(400).send('Invalid Password!');

  if (user.isBanned) return res.status(401).send('Your account has been banned. Please contact the staff for more information');

  // Create and assign jwt token
  const token = jwt.sign({ _id: user._id }, process.env.JWT_TOKEN_SECRET);
  res.header('x-auth-token', token).send({
    token,
    id: user._id,
    name: user.name,
    email: user.email,
    wishList: user.wishList,
    admin: user.isAdmin,
  });
});

// @desc  Get user data w/o password
// @route GET /auth/user
// @access private
router.get('/user', auth, (req, res) => {
  User.findById(req.user._id)
    .select('-password')
    .then((user) => res.json(user))
    .catch((err) => res.json(err));
});

// @desc    Edit user password
// @route   PATCH /auth/password:id
// @access  private
router.patch('/password/:id', auth, async (req, res) => {
  const user = await User.findById(req.params.id);
  const { oldPassword, password, confirmPassword } = req.body;

  // Check for user input
  if (oldPassword === '' || password === '' || confirmPassword === '') {
    return res.status(400).send('Please fill in all fields');
  }

  if (password !== confirmPassword) {
    return res.status(400).send('Passwords do not match');
  }

  // Check if password is correct
  const validPass = await bcrypt.compare(oldPassword, user.password);
  if (!validPass) return res.status(400).send('Invalid Password!');

  // Validation
  const { error } = editUserValidation({ password });
  if (error) return res.status(400).send(error.details[0].message);

  // Hash password and set new password
  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(req.body.password, salt);

  user.password = hashPassword;

  // Update user password
  try {
    await user.save();
    res.status(201).send('Password changed');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// @desc    Change user wishlist
// @route   PATCH /auth/wishlist/:id
// @access  private
router.patch('/wishlist/:id', auth, async (req, res) => {
  const user = await User.findById(req.params.id);
  const { productID } = req.body;

  if (user.wishList.includes(productID)) {
    user.wishList = user.wishList.filter((product) => product !== productID);
  } else {
    user.wishList.push(productID);
  }

  // Update user wishList
  try {
    await user.save();
    res.status(201).send(user.wishList);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// @desc    Rewrite users wishlist
// @route   PATCH /auth/wishlist/rewrite/:id
// @access  private
router.patch('/wishlist/rewrite/:id', auth, async (req, res) => {
  const user = await User.findById(req.params.id);
  const { newWishListArray } = req.body;

  user.wishList = newWishListArray;

  // Update user wishList
  try {
    await user.save();
    res.status(201).send(user.wishList);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// @desc    Make user admin
// @route   PATCH /auth/admin/:id
// @access  admin
router.patch('/admin/:id', auth, async (req, res) => {
  const user = await User.findById(req.user._id);
  const dbUser = await User.findById(req.params.id);

  // Validate if admin
  if (!user.isAdmin) {
    return res.status(401).send('Unauthorized');
  }

  dbUser.isAdmin = true;

  // Update user admin status
  try {
    await dbUser.save();
    res.status(201).send(`${dbUser.name} is now admin`);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// @desc    Ban user
// @route   PATCH /auth/ban/:id
// @access  admin
router.patch('/ban/:id', auth, async (req, res) => {
  const user = await User.findById(req.user._id);
  const dbUser = await User.findById(req.params.id);

  // Validate if admin
  if (!user.isAdmin) {
    return res.status(401).send('Unauthorized');
  }

  if (dbUser.isBanned) {
    dbUser.isBanned = false;
    dbUser.banComment = '';
  } else {
    if (req.body.banComment) {
      dbUser.banComment = req.body.banComment;
    }
    dbUser.isBanned = true;
  }

  // Save ban status to db
  try {
    await dbUser.save();
    res.status(201).send(`${dbUser.name} account is now ${dbUser.isBanned ? 'banned' : 'unbanned'}`);
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// @desc    Delete user
// @route   DELETE /auth/:id
// @access  private
router.delete('/:id', auth, async (req, res) => {
  const user = await User.findById(req.params.id);

  try {
    await user.remove();
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// @desc    Send reset user password link to Email
// @route   POST /auth/reset/password
// @access  public
router.post('/reset/password', async (req, res) => {
  const { email } = req.body;
  const resetToken = crypto.randomBytes(32).toString('hex');

  const re = /^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i;
  if (!re.test(email)) return res.status(400).send('Please enter a valid Email address');

  const user = await User.findOne({ email }).select('-password');
  if (!user) return res.status(400).send('User with that Email does not exist');

  // Reset token
  const token = await Token.findOne({ userId: user._id });
  if (token) await token.deleteOne();

  // Hash Token
  const salt = await bcrypt.genSalt(10);
  const hashToken = await bcrypt.hash(resetToken, salt);

  // token.token = hashToken;
  const newToken = new Token({
    userId: user._id,
    token: hashToken,
    createdAt: Date.now(),
  });

  // Send email to user
  const link = `http://localhost:3000/account/reset_password_confirm?token=${resetToken}&id=${user._id}`;
  const output = `
    <div style="padding:1.5rem 1rem; background: rgba(255, 96, 10, 0.2); color: black;">
      <h3 style="font-size: 1.5rem;">Password Reset</h3>
      <p>You're receiving this E-mail because you requested a password reset for your user account at VRA-Ecommerce.</p>
      <p>If you didn't request this change, you can disregard this email - we have not yet reset your password.</p>
      
      <a href="${link}">
        <button style="padding:0.5rem 1rem;">
          Change my Password
        </button>
      </a>
    </div>
  `;

  const transporter = nodemailer.createTransport({
    host: 'mail.veebimajutus.ee',
    port: 2525,
    secure: false,
    auth: {
      user: 'info@vra.ee',
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    to: email,
    from: 'vra@info.ee',
    subject: 'Password reset on VRA E-commerce',
    html: output,
  };

  try {
    await newToken.save();
  } catch (error) {
    res.status(500).send('Something went wrong. Please try again later');
  }

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      res.status(500).send('Something went wrong, please try again later');
    } else {
      res.status(200).send('Recovery Email sent. Please check your Email');
    }
  });
});

// @desc    Reset user password
// @route   PATCH /auth/resetpassword/:token
// @access  private
router.patch('/resetpassword/:token', async (req, res) => {
  const { userId, password, confirmPassword } = req.body;
  const token = await Token.findOne({ userId });

  // Check if token is not expired
  if (!token) return res.status(400).send('Reset password link is expired. Please request a new reset password link to email.');

  // Check if token is valid
  const isValid = await bcrypt.compare(req.params.token, token.token);
  if (!isValid) return res.status(400).send('Invalid reset password link. Please request a new reset password link to email.');

  const user = await User.findById(token.userId);

  // Check for user input
  if (password === '' || confirmPassword === '') {
    return res.status(400).send('Please fill in all fields');
  }

  if (password !== confirmPassword) {
    return res.status(400).send('Passwords do not match');
  }

  // Password validation
  const { error } = editUserValidation({ password });
  if (error) return res.status(400).send(error.details[0].message);

  // Hash password and set new password
  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(password, salt);

  user.password = hashPassword;

  // Update user password
  try {
    await user.save();
    res.status(201).send('Password changed');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

function paginatedResults(model) {
  return async (req, res, next) => {
    const page = parseInt(req.query.page);
    const limit = parseInt(req.query.limit);

    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const results = {};

    if (endIndex < await model.countDocuments().exec()) {
      results.next = {
        page: page + 1,
        limit,
      };
    }

    if (startIndex > 0) {
      results.previous = {
        page: page - 1,
        limit,
      };
    }

    try {
      results.results = await model.find();
      results.paginatedResults = await model.find().select('-password').limit(limit).skip(startIndex)
        .exec();

      res.paginatedResults = results;
      next();
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  };
}

module.exports = router;
