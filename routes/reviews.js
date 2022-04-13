const router = require('express').Router();
const Review = require('../model/Review');

// @desc    Get all product reviews
// @route   GET /reviews/:productId
// @access  public
router.get('/:productId', async (req, res) => {
  try {
    const reviews = await Review.find({ productId: req.params.productId });

    res.status(200).json(reviews);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @desc    Post a new review
// @route   POST /reviews
// @access  public
router.post('/', async (req, res) => {
  const { productId, rating, reviewerName, review } = req.body;

  // Empty values validation
  if (!reviewerName || !review) {
    return res.status(400).send('Please fill in all fields');
  }

  const newReview = new Review({
    productId,
    rating,
    reviewerName,
    review,
  });

  try {
    await newReview.save();
    res.status(201).send('Review published');
  } catch (err) {
    res.status(400).send(err.message);
  }
});

module.exports = router;
