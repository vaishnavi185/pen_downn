import jwt from "jsonwebtoken";
import usermodel from "../models/user.js";

var checkAuth = async (req, res, next) => {
  let token;
  const { authorization } = req.headers;

  if (authorization && authorization.startsWith("Bearer")) {
    try {
      token = authorization.split(' ')[1];
      console.log("token",token)
      const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY); // Corrected here
      req.user = await usermodel.findById(decoded.userID).select('-password'); // Corrected here
      next();
    } catch (error) {
      console.log(error);
      res.status(401).send({ status: 'failed', message: 'Unauthorized user' });
    }
  } else {
    res.status(401).send({ status: 'failed', message: 'No token' });
  }
};
const isAdmin = (req, res, next) => {
  if (req.user?.role === 'admin') {
    next(); // Proceed to the next middleware or controller
  } else {
    res.status(403).json({ status: 'failed', message: 'Access denied: Admins only' });
  }
};

export { checkAuth, isAdmin };
