const router = require('express').Router();
const axios = require('axios');

// @desc    Get Omniva parcel terminal locations
// @route   GET /parcels
// @access  public
router.get('/', async (req, res) => {
  const BASE_URL = 'https://www.omniva.ee/locations.json';

  axios.get(BASE_URL)
    .then((response) => res.send(response.data))
    .catch((error) => res.send(error.message));
});

module.exports = router;
