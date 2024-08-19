const jwt = require("jsonwebtoken");
const catchAsync = require("./../utils/catchAsync");
const AppError = require("./../utils/appError");
const User = require("../models/User");

// Utility methods
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm || req.body.password,
    passwordChangedAt: req.body.passwordChangedAt || Date.now(),
  });

  const token = signToken(newUser._id);

  res.status(201).json({
    status: "success",
    token,
    data: {
      user: newUser,
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1. Check if user exists
  if (!email || !password) {
    return next(new AppError("Please provide the email and password", 400));
  }

  // 2. Match the credentails
  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  // 3. Send JWT
  const token = signToken(user._id);

  res.status(200).json({
    status: "success",
    token,
    data: { user },
  });
});

exports.getMe = catchAsync(async (req, res, next) => {
  // 1. Get token from headers
  const token = req.header("x-auth-token");

  if (!token) {
    return next(new AppError("No token, authorization denied", 401));
  }

  try {
    // 2. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 3. Find user from token
    const user = await User.findById(decoded.id);

    if (!user) {
      return next(new AppError("Token is not valid", 401));
    }

    // 4. Attach user to request object
    req.user = user;
    next();
  } catch (error) {
    next(new AppError("Token is not valid", 401));
  }
});
