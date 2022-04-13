const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const path = require('path');
const connectDB = require('./db');

// Load config
dotenv.config({ path: './.env' });

connectDB();

const app = express();

app.use(cors());
app.use(express.json());

// Production config
app.use(express.static(path.join(__dirname, 'build')));
app.get('/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

app.use('/uploads', express.static('uploads'));

// Route Middlewares
app.use('/products', require('./routes/products'));
app.use('/orders', require('./routes/orders'));
app.use('/parcels', require('./routes/parcels'));
app.use('/auth', require('./routes/auth'));
app.use('/reviews', require('./routes/reviews'));
app.use('/contact', require('./routes/contact'));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port: ${PORT}`));
