const {
  verifyTokenAndAuthorization,
  verifyTokenAndAdmin,
  verifyToken,
} = require('./verifyToken');
const Cart = require('../models/Cart');

const router = require('express').Router();

// CREATE

router.post('/', verifyToken, async (req, res) => {
  const newCart = new Cart(req.body);

  try {
    const savedCart = await newCart.save();
    res.status(200).json(savedCart);
  } catch (err) {
    res.status(500).json(err);
  }
});

// UPDATE

router.put('/:id', verifyTokenAndAuthorization, async (req, res) => {
  Cart.findByIdAndUpdate(
    req.params.id,
    {
      $set: {
        products: req.body.products,
      },
    },
    { returnNewDocument: true },
    (err, cart) => {
      console.log(cart);
    }
  );
  res.status(200).json('Готово');
});

// DELETE CART

router.delete('/:id', verifyTokenAndAuthorization, async (req, res) => {
  try {
    await Cart.findByIdAndDelete(req.params.id);
    return res.status(200).json('Cart has been deleted...');
  } catch (err) {
    return res.status(500).json(err);
  }
});

// GET USER CART

router.get('/find/:id', verifyTokenAndAuthorization, async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.params.id });
    res.status(200).json(cart);
  } catch (err) {
    res.status(500).json(err);
  }
});

// GET ALL PRODUCTS

router.get('/', verifyTokenAndAdmin, async (req, res) => {
  try {
    const carts = await Cart.find();
    res.status(200).json(carts);
  } catch (err) {
    res.status(500).json(err);
  }
});

module.exports = router;
