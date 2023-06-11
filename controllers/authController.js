const User = require("../models/User");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

/**
 * @desc Login user request
 * @route Post/auth/login
 * @access PUBLIC
 */

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "All fields are required!",
    });
  }

  //   check user
  const loginUser = await User.findOne({ email });
  if (!loginUser) {
    return res.status(400).json({ message: "Login user not found!" });
  }
  //   password check
  const passwordCheck = await bcrypt.compare(password, loginUser.password);

  if (!passwordCheck) {
    return res.status(400).json({ message: "Wrong password!" });
  }

  //   access token
  const accessToken = jwt.sign(
    { email: loginUser.email, role: loginUser.role },
    process.env.ACCESS_TOKEN,
    {
      expiresIn: "30s",
    }
  );

  //   refresh token
  const refreshToken = jwt.sign(
    { email: loginUser.email },
    process.env.REFRESH_TOKEN,
    {
      expiresIn: "30d",
    }
  );

  //   now set refresh token to cookie
  res
    .cookie("rtToken", refreshToken, {
      httpOnly: true,
      secure: false,
      maxAge: 1000 * 60 * 24 * 30,
    })
    .json({ token: accessToken });

  if (passwordCheck) {
    return res.status(200).json({
      message: "Logged In successful:)",
    });
  }
});

/**
 * @desc Create Refresh Token
 * @route GET/AUTH/REFRESH
 * @access PUBLIC
 */

const refresh = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.rtToken) {
    return res.status(400).json({ message: "You are not authorized!" });
  }

  const token = cookies.rtToken;
  jwt.verify(
    token,
    process.env.REFRESH_TOKEN,
    asyncHandler(async (err, decode) => {
      if (err) {
        return res.status(400).json({ message: "Invalid token request!" });
      }

      const tokenUser = await User.findOne({ email: decode.email });

      if (!tokenUser) {
        return res.status(400).json({ message: "Invalid user request!" });
      }

      const accessToken = jwt.sign(
        { email: tokenUser.email, role: tokenUser.role },
        process.env.ACCESS_TOKEN,
        {
          expiresIn: "30s",
        }
      );

      res.json({ token: accessToken });
    })
  );
};

/**
 * @desc Create Refresh Token
 * @route GET/AUTH/REFRESH
 * @access PUBLIC
 */

const logout = (req, res) => {
  const cookies = req.cookies;
  if (!cookies.rtToken) {
    return res.status(400).json({ message: "Cookies not found" });
  }
  res.clearCookie("rtToken", { httpOnly: true, secure: false });
  res.json({ message: "User Logged Out!" });
};

// Export
module.exports = { login, refresh, logout };
