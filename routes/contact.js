const router = require('express').Router();
const nodemailer = require('nodemailer');

// @desc    Submit a contact form & send an email
// @route   POST /contact
// @access  public
router.post('/', async (req, res) => {
  const { name, email, message } = req.body;

  if (name === '' || email === '' || message === '') {
    return res.status(400).send('Please fill in all fields');
  }

  const re = /^(([^<>()[\].,;:\s@"]+(\.[^<>()[\].,;:\s@"]+)*)|(".+"))@(([^<>()[\].,;:\s@"]+\.)+[^<>()[\].,;:\s@"]{2,})$/i;

  if (!re.test(email)) {
    return res.status(400).send('Please enter a valid E-mail address');
  }

  const output = `
    <p>You have a new contact request</p>
    <h3>Contact Details</h3>
    <ul>
      <li>Name: ${name}</li>
      <li>Email: ${email}</li>
    </ul>
    <h3>Message</h3>
    <p>${message}</p>
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
    to: 'info@vra.ee',
    from: email,
    subject: 'VRA E-commerce contact form request',
    html: output,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      res.status(500).send('Something went wrong, please try again later');
    } else {
      res.status(200).send('Thank you. We will contact you back as soon as possible.');
    }
  });
});

module.exports = router;
