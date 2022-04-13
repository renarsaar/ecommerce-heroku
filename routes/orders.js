const jwt = require('jsonwebtoken');
const router = require('express').Router();
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const auth = require('../middleware/auth');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Order = require('../model/Order');
const User = require('../model/User');
const Product = require('../model/Product');
const Token = require('../model/Token');
const { makeOrderValidation } = require('../validation');

// @desc    Get all orders
// @route   GET /orders
// @access  admin
router.get('/', auth, paginatedResults(Order), async (req, res) => {
  const user = await User.findById(req.user._id);

  // Validate if admin
  if (!user.isAdmin) {
    return res.status(401).send('Unauthorized');
  }

  try {
    res.status(200).json(res.paginatedResults);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @desc    Get all orders made from 1 user
// @route   GET /orders/user/:userId
// @access  private
router.get('/user/:userId', auth, paginatedResults(Order), async (req, res) => {
  try {
    res.status(200).json(res.paginatedResults);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @desc    Get single order
// @route   GET /orders/:id
// @access  private
router.get('/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  const user = await User.findById(req.user._id);

  if (!order) {
    return res.status(404).json({ message: 'Order not found' });
  }

  // Validate if admin
  if (user.isAdmin) {
    return res.status(200).send(order);
  }

  // orderer & user are the same
  if (user.name !== order.name) {
    return res.status(400).send('Unauthorized');
  }

  try {
    res.status(200).send(order);
  } catch (err) {
    res.status(500).json({ message: 'Something went wrong. Please try again later.' });
  }
});

// @desc    Make a new order
// @route   POST /orders
// @access  public
router.post('/', async (req, res) => {
  // Validation
  const { error } = makeOrderValidation(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const order = new Order({
    name: req.body.name,
    userId: req.body.userId,
    email: req.body.email,
    products: req.body.products,
    totalPrice: req.body.totalPrice,
    delivery: req.body.delivery,
  });

  try {
    // Make a new order
    await order.save();

    // Map all products and remove quantity from db
    order.products.map(async (product) => {
      const collectionProduct = await Product.findById(product.id);

      // Find the index of the size in the stock array
      const index = collectionProduct.sizes.findIndex((size) => size === product.size);

      collectionProduct.stock[index] -= product.quantity;

      // Rewrite the whole stock array
      collectionProduct.updateOne({ stock: collectionProduct.stock }, (err) => {
        if (err) res.status(400).send({ message: 'Failed to create an order. Please try again later' });
      });
    });

    // Send a conformation Email
    const subject = 'VRA E-commerce order conformation';
    const output = `<div style="padding:1.5rem 1rem; background: rgba(255, 96, 10, 0.2); color: black;">
      <h3 style="margin-bottom: 2rem;">Hi, ${order.name} - thanks for your order, we hope you enjoyed shopping with us.</h3>

      <h3>Your order #${order._id}</h3>
      <p>Order was made on ${new Date(order.date).toLocaleDateString('en-GB')}</p>
      <p>Delivery method: ${order.delivery}</p>
      <p>Total price: ${order.totalPrice} €</p>

      <h3 style="margin-bottom: 0;">Products:</h3>
    ${order.products.map((product) => `<div style="display: flex; flex-direction: column; margin: 3rem, 0, 1rem, 1rem;">
      <h3>${product.name} x ${product.quantity}</h3>
      <h3>Size: ${product.size}</h3>
      <h3>${product.totalPrice} €</h3>
    </div>`)}

    <a style="text-decoration: none;" href=${`http://localhost:3000/order/${order._id}`}>
      <button style="width: 200px; height: 50px; cursor: pointer;">
        View Your Order
      </button>
    </a>

    <p>If you have any questions regarding to your order, please send us an E-mail info@vra.ee</p>
    `;

    // Create PDF document
    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream(`./orderPDF/${order._id}.pdf`));

    doc
      .fontSize(20)
      .text(`Hi, ${order.name} - thanks for your order, we hope you enjoyed shopping with us.`, {
        align: 'center',
      });

    doc
      .fontSize(14)
      .text(`
        Your order #${order._id}
        Order was made on ${new Date(order.date).toLocaleDateString('en-GB')}
        Delivery method: ${order.delivery}
        Total price: ${order.totalPrice} €
      `, {
        align: 'left',
      });

    doc
      .fontSize(18)
      .text('Products:');

    order.products.map((product) => {
      doc
        .image(`${product.image}`, {
          fit: [30, 90],
          align: 'center',
          valign: 'center',
        })
        .fontSize(16)
        .text(`
          ${product.name} x ${product.quantity}
          Size: ${product.size}
          ${product.totalPrice} €
        `);
    });

    doc.end();

    // Send PDF file as an attachment
    const attachments = [{
      filename: 'order.pdf',
      path: `./orderPDF/${order._id}.pdf`,
      contentType: 'application/pdf',
    }];

    sendMail(order.email, subject, output, attachments);

    res.status(201).send('Order created successfully');
  } catch (err) {
    res.status(400).send({ message: err.message });
  }
});

// @desc    Delete order
// @route   DELETE /orders/delete/:id
// @access  admin
router.delete('/delete/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  const user = await User.findById(req.user._id);

  // Validate if admin
  if (!user.isAdmin) {
    return res.status(401).send('Unauthorized');
  }

  try {
    await order.remove();
    res.json({ message: 'Order deleted successfully' });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

// @desc    Change order completed status
// @route   PATCH /orders/status/:id
// @access  admin
router.patch('/status/:id', auth, async (req, res) => {
  const { id } = req.params;
  const { newStatus, statusComment } = req.body;
  const order = await Order.findById(id);
  const user = await User.findById(req.user._id);
  const allowedStatuses = ['Active', 'Cancelled', 'Completed', 'Seen By Admin', 'Recieved'];

  // Validate if admin
  if (!user.isAdmin) {
    return res.status(401).send('Unauthorized');
  }

  // Check if not unknown status
  if (!allowedStatuses.includes(newStatus)) {
    return res.status(400).send('Unknown status');
  }

  order.status = newStatus;
  if (statusComment) {
    order.statusComment = req.body.statusComment;
  }

  // Reset the status comment if new status changed from "cancelled"
  if (newStatus !== 'Cancelled' && order.statusComment) {
    order.statusComment = '';
  }

  // Send an informative Email to user about cancelling
  if (newStatus === 'Cancelled') {
    const ordererAccount = await User.findById(order.userId);
    let redirectLink = '';

    const subject = 'VRA E-commerce order has been cancelled';
    let output = '';

    //
    // If orderer is registered account, send direct link to open the order
    if (ordererAccount) {
      const token = jwt.sign({ _id: ordererAccount._id }, process.env.JWT_TOKEN_SECRET);
      redirectLink = `http://localhost:3000/order/${order._id}?token=${token}`;

      output = `<div style="padding:1.5rem 1rem; background: rgba(255, 96, 10, 0.1); color: black;">
        <h2>Hi, ${order.name} - Your order ${order._id} has been cancelled.</h3>
        <h3>Reason for cancelling the order: ${order.statusComment}</h3>

        <a style="text-decoration: none;" href=${redirectLink}>
          <button style="width: 200px; height: 50px; cursor: pointer;">
            View Your Order
          </button>
        </a>

        <p>If you have any questions regarding to your order, please send us an E-mail info@vra.ee</p>
      </div>`;
    } else {
      output = `<div style="padding:1.5rem 1rem; background: rgba(255, 96, 10, 0.1); color: black;">
          <h2>Hi, ${order.name} - Your order ${order._id} has been cancelled.</h3>
          <h3>Reason for cancelling the order: ${order.statusComment}</h3>

          <p>If you have any questions regarding to your order, please send us an E-mail info@vra.ee</p>
        </div>`;
    }

    sendMail(order.email, subject, output);
  }

  try {
    await order.save();

    res.status(200).send('Status Changed');
  } catch (error) {
    res.status(500).send('Something went wrong. Please try again later.');
  }
});

function sendMail(ordererEmail, subject, output, attachments) {
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
    to: ordererEmail,
    from: 'vra@info.ee',
    subject,
    html: output,
    attachments,
  };

  transporter.sendMail(mailOptions);
}

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
      // results.results = await model.find();
      results.paginatedResults = await model.find().limit(limit).skip(startIndex).exec();

      // Filter orders by userId if userId in params
      if (req.params.userId) {
        results.paginatedResults = await model.find({ userId: req.params.userId })
          .limit(limit)
          .skip(startIndex)
          .exec();
      }

      // Filter orders by 'Recieved' status if new in params
      if (req.query.new) {
        results.paginatedResults = await model.find({ status: 'Recieved' })
          .limit(limit)
          .skip(startIndex)
          .exec();
      }

      res.paginatedResults = results;
      next();
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  };
}

module.exports = router;
