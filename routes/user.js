const {
  verifyTokenAndAuthorization,
  verifyTokenAndAdmin,
} = require('./verifyToken');
const CryptoJS = require('crypto-js');
const User = require('../models/User');

const router = require('express').Router();

// UPDATE

router.put('/:id', verifyTokenAndAuthorization, async (req, res) => {
  const user = await User.findOne({ _id: req.params.id });

  if (req.body.password) {
    const hashedPassword = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASS_SEC
    );
    const originalPassword = hashedPassword.toString(CryptoJS.enc.Utf8);

    if (originalPassword === req.body.oldPassword) {
      req.body.password = CryptoJS.AES.encrypt(
        req.body.password,
        process.env.PASS_SEC
      ).toString();
    } else {
      return res.status(500).json('Not valid password');
    }
  }

  const noOldPassword = ({ oldPassword, ...rest }) => rest;

  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        $set: noOldPassword(req.body),
      },
      { new: true }
    );
    res.status(200).json(updatedUser);
  } catch (err) {
    return res.status(500).json(err);
  }
});

// DELETE USER

router.delete('/:id', verifyTokenAndAuthorization, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    return res.status(200).json('User has been deleted...');
  } catch (err) {
    return res.status(500).json(err);
  }
});

// GET USER

router.get('/find/:id', verifyTokenAndAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    const { selectedUser, ...others } = user._doc;
    res.status(200).json(others);
  } catch (err) {
    res.status(500).json(err);
  }
});

// GET ALL USERS

router.get('/', verifyTokenAndAdmin, async (req, res) => {
  const query = req.query.new;
  try {
    const users = query
      ? await User.find().sort({ _id: -1 }).limit(5)
      : await User.find();
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json(err);
  }
});

// GET USER STATS

router.get('/stats', verifyTokenAndAdmin, async (req, res) => {
  const date = new Date();
  const lastYear = new Date(date.setFullYear(date.getFullYear() - 1));

  try {
    const data = await User.aggregate([
      { $match: { createdAt: { $gte: lastYear } } },
      {
        $project: {
          month: { $month: '$createdAt' },
        },
      },
      {
        $group: {
          _id: '$month',
          total: { $sum: 1 },
        },
      },
    ]);
    res.status(200).json(data);
  } catch (err) {
    return res.status(500).json(err);
  }
});

module.exports = router;
