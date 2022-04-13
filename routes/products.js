const router = require('express').Router();
const multer = require('multer');
const fs = require('fs');
const Product = require('../model/Product');
const User = require('../model/User');
const { addProductValidation } = require('../validation');
const auth = require('../middleware/auth');
const sortProducts = require('../helpers/SortProducts');

// Store files to /uploads
const storage = multer.diskStorage({
  destination: (req, file, res) => {
    res(null, './uploads/');
  },
  filename: (req, file, res) => {
    res(null, file.originalname);
  },
});

// Reject files that are not images
const fileFilter = (req, file, res) => {
  if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png' || file.mimetype === 'image/jpg') {
    res(null, true);
  } else {
    res(new Error('Only PNG, JPG & JPEG files allowed'), false);
  }
};

// Init multer
const upload = multer({
  storage,
  limits: {
    fileSize: 1024 * 1024 * 5,
  },
  fileFilter,
});

// @desc    Get all products
// @route   GET /products
// @access  Public
router.get('/', paginatedResults(Product), async (req, res) => {
  try {
    res.status(200).json(res.paginatedResults);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @desc    Get single product
// @route   GET /products/:id
// @access  Public
router.get('/:id', getProduct, async (req, res) => {
  try {
    const product = await res.product;
    res.status(200).json(product);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @desc    Add a product
// @route   POST /products
// @access  Admin
router.post('/', auth, async (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (!req.file) {
      return res.status(400).send('Please upload an image');
    }

    if (err instanceof multer.MulterError) {
      return res.status(400).send(err.message);
    }

    if (err) {
      return res.status(400).send(err.message);
    }

    const user = await User.findById(req.user._id);

    // Validate if admin
    if (!user.isAdmin) {
      return res.status(401).send('Unauthorized');
    }

    const {
      name, brand, category, subCategory, gender,
      sizes, description, stock, price, discountPrice,
    } = req.body;

    const validationValues = {
      name,
      brand,
      category,
      subCategory,
      gender,
      sizes: JSON.parse(sizes),
      description: JSON.parse(description),
      stock: JSON.parse(stock),
      price,
      discountPrice,
    };

    // Validation
    const { error } = addProductValidation(validationValues);
    if (error) return res.status(400).send(error.details[0].message);

    const product = new Product({
      name,
      brand,
      category,
      subCategory,
      gender,
      sizes: JSON.parse(sizes),
      description: JSON.parse(description),
      stock: JSON.parse(stock),
      price: +price,
      discountPrice: !+discountPrice || +discountPrice === 0 ? +price : +discountPrice,
      image: req.file.path,
    });

    // Add a product
    try {
      await product.save();
      res.status(201).send('Product added');
    } catch (addProductErr) {
      res.status(400).send(addProductErr.message);
    }
  });
});

// @desc    Edit a product
// @route   PATCH /products/:id
// @access  Admin
router.patch('/:id', auth, getProduct, async (req, res) => {
  upload.single('image')(req, res, async (err) => {
    if (err instanceof multer.MulterError) {
      return res.status(400).send(err.message);
    }

    if (err) {
      return res.status(400).send(err.message);
    }

    const user = await User.findById(req.user._id);

    // Validate if admin
    if (!user.isAdmin) {
      return res.status(401).send('Unauthorized');
    }

    const {
      name, brand, category, subCategory, gender,
      sizes, description, stock, price, discountPrice,
    } = req.body;

    const validationValues = {
      name,
      brand,
      category,
      subCategory,
      gender,
      sizes: JSON.parse(sizes),
      description: JSON.parse(description),
      stock: JSON.parse(stock),
      price,
      discountPrice,
    };

    // Validation
    const { error } = addProductValidation(validationValues);
    if (error) return res.status(400).send(error.details[0].message);

    // Check for user input
    if (name) res.product.name = name;
    if (brand) res.product.brand = brand;
    if (category) res.product.category = category;
    if (subCategory) res.product.subCategory = subCategory;
    if (gender) res.product.gender = gender;
    if (sizes) res.product.sizes = JSON.parse(sizes);
    if (description) res.product.description = JSON.parse(description);
    if (stock) res.product.stock = JSON.parse(stock);
    if (price) res.product.price = +price;
    if (discountPrice) res.product.discountPrice = +discountPrice;

    // Set original price if discount price is set as 0
    if (+discountPrice === 0) res.product.discountPrice = res.product.price;
    if (+discountPrice > res.product.price) res.product.discountPrice = res.product.price;

    if (req.file) {
      // Delete old image
      fs.unlink((res.product.image), (deleteFileErr) => {
        if (deleteFileErr) {
          return res.status(500).send('Something went wrong uploading image');
        }
      });

      // Set new image path
      res.product.image = req.file.path;
    }

    // Update product
    try {
      await res.product.save();
      res.status(201).send('Product updated');
    } catch (saveProductErr) {
      res.status(400).send(saveProductErr.message);
    }
  });
});

// @desc    Delete a product
// @route   DELETE /products/:id
// @access  Admin
router.delete('/:id', auth, getProduct, async (req, res) => {
  const user = await User.findById(req.user._id);

  // Validate if admin
  if (!user.isAdmin) {
    return res.status(401).send('Unauthorized');
  }

  // Delete image
  fs.unlink((res.product.image), (deleteFileErr) => {
    if (deleteFileErr) {
      return res.status(500).send('Something went wrong deleting image');
    }
  });

  try {
    await res.product.remove();
    res.status(200).send('Product removed successfully');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Get Product by ID Middleware
async function getProduct(req, res, next) {
  let product;

  try {
    product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
  } catch (err) {
    return res.status(500).json({ message: 'Unexpected error, please try again later' });
  }

  res.product = product;
  next();
}

function paginatedResults(model) {
  return async (req, res, next) => {
    const { sortValue } = req.query;
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
      results.paginatedResults = await model.find().limit(limit).skip(startIndex).exec();

      if (sortValue) {
        results.paginatedResults = sortProducts(results.results, sortValue)
          .slice((page - 1) * limit, page * limit);
      }

      res.paginatedResults = results;
      next();
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  };
}

module.exports = router;
