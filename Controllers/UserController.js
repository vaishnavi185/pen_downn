import usermodel from '../models/user.js';
import nodemailer from 'nodemailer';
import transporter from '../Config/emailconfig.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto, { sign } from 'crypto';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pdfmodel from '../models/files.js';
import { dirname } from 'path';
import mongoose from 'mongoose';
import express from 'express'

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Define the path to the 'uploads' directory in the root of the PEN_DOWN project
const uploadsDir = path.resolve(__dirname, '../uploads');




// Ensure 'uploads' directory exists
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir); // Use the correct directory path
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const pdfFilter = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Only PDF files are allowed!'), false);
  }
};

// Define PDF schema
const pdfSchema = new mongoose.Schema({
  pdf: String,
  title: String
}, { collection: 'pdfcollection' });

// Create PDF model
const Pdf = mongoose.model('Pdf', pdfSchema);

const upload = multer({
  storage: storage,
  fileFilter: pdfFilter
});

const uploadPdf = async (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      console.error('File upload error:', err.message);
      return res.status(400).json({ status: 'failed', message: err.message });
    }

    if (!req.file) {
      console.error('No file uploaded');
      return res.status(400).json({ status: 'failed', message: 'No file uploaded' });
    }

    try {
      const title = req.body.title;
      const file = req.file.filename;

      // Save to MongoDB
      await Pdf.create({ title, pdf: file });

      res.status(200).json({ status: 'success', message: 'PDF uploaded successfully', file: req.file });
    } catch (error) {
      console.error('Database error:', error);
      return res.status(500).json({ status: 'failed', message: 'Internal Server Error' });
    }


  });
};
// Fetch all PDF files from the database
const fetchPdfs = async (req, res) => {
  try {
    const pdfs = await Pdf.find(); // Fetch PDFs from the database
    res.status(200).json({ status: 'success', data: pdfs });
  } catch (error) {
    console.error('Database fetch error:', error);
    res.status(500).json({ status: 'failed', message: 'Error fetching data' });
  }
};



class UserController {



  static userRegistration = async (req, res) => {
    const { name, email, password, tc, role } = req.body;

    if (!email || !name || !password || !tc || !role) {
      return res.status(400).send({ status: 'failed', message: 'Incomplete user details' });
    }

    try {
      const existingUser = await usermodel.findOne({ email });
      if (existingUser) {
        return res.status(409).send({ status: 'failed', message: 'User already exists' });
      }

      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(password, salt);

      const newUser = new usermodel({
        name,
        email,
        password: hashedPassword,
        tc,
        role,
      });

      await newUser.save();

      const token = jwt.sign(
        { userID: newUser._id, role: newUser.role },
        process.env.JWT_SECRET_KEY,
        { expiresIn: '5d' }
      );

      return res.status(201).send({ status: 'success', message: 'User registered successfully', token });
    } catch (error) {
      console.error(error);
      return res.status(500).send({ status: 'failed', message: 'Registration failed' });
    }
  };

  static userlogin = async (req, res) => {
    try {
      const { email, password } = req.body;

      // Ensure both email and password are provided in the request
      if (email && password) {
        const user = await usermodel.findOne({ email });

        if (user) {
          // Ensure user.password is not undefined or null
          if (user.password) {
            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {
              const token = jwt.sign(
                { userID: user._id, role: user.role },
                process.env.JWT_SECRET_KEY,
                { expiresIn: '2m' }
              );
              res.send({
                status: 'success',
                message: 'User authenticated',
                token,
                role: user.role,
                name: user.name
              });
            } else {
              res.status(401).send({ status: 'failed', message: 'Invalid email or password' });
            }
          } else {
            // If user.password is missing
            res.status(500).send({ status: 'failed', message: 'Password hash missing from the user record' });
          }
        } else {
          res.status(404).send({ status: 'failed', message: 'User not registered' });
        }
      } else {
        res.status(400).send({ status: 'failed', message: 'Incomplete login details' });
      }
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).send({ status: 'failed', message: 'Login failed due to a server error' });
    }
  };


  // static forgotPassword = async (req, res) => {
  //   const { email } = req.body;
  //   try {
  //     const user = await usermodel.findOne({ email });
  //     if (!user) {
  //       return res.send({ status: 'failed', message: 'User not found' });
  //     }

  //     // Generate a reset token
  //     const resetToken = crypto.randomBytes(20).toString('hex');

  //     // Set token and expiration on the user object
  //     user.resetPasswordToken = resetToken;
  //     user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

  //     await user.save();

  //     // Send email with the token (using nodemailer or any email service)
  //     const transporter = nodemailer.createTransport({
  //       service: 'Gmail',
  //       auth: {
  //         user: process.env.EMAIL_USER,
  //         pass: process.env.EMAIL_PASS
  //       }
  //     });

  //     const mailOptions = {
  //       to: user.email,
  //       from: process.env.EMAIL_USER,
  //       subject: 'Password Reset',
  //       text: `You are receiving this because you (or someone else) have requested to reset your password.\n\n
  //       Please click on the following link, or paste it into your browser to complete the process:\n\n
  //       http://${req.headers.host}/reset/${resetToken}\n\n
  //       If you did not request this, please ignore this email, and your password will remain unchanged.\n`
  //     };

  //     transporter.sendMail(mailOptions, (err) => {
  //       if (err) {
  //         console.log(err);
  //         return res.send({ status: 'failed', message: 'Error sending email' });
  //       }
  //       res.send({ status: 'success', message: 'Reset link sent to your email' });
  //     });
  //   } catch (error) {
  //     console.log(error);
  //     res.send({ status: 'failed', message: 'Error processing request' });
  //   }
  // };

  static resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
      const user = await usermodel.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() }
      });

      if (!user) {
        return res.status(400).json({ status: 'failed', message: 'Password reset token is invalid or has expired' });
      }

      const salt = await bcrypt.genSalt(12);
      user.password = await bcrypt.hash(password, salt);

      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;

      await user.save();

      res.status(200).json({ status: 'success', message: 'Password has been updated' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ status: 'failed', message: 'Error resetting password' });
    }
  };

  static resetpassword = async (req, res) => {
    const { password } = req.body;
    if (password) {
      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(password, salt);
      console.log(req.user)
      res.send({ status: 'success', message: 'Password changed' });
    } else {
      return res.status(400).json({ status: 'failed', message: 'All fields are required' });
    }
  };
  static loggeduser = async (req, res) => {
    res.send = ({ "user": req.user })
  }
  static senduserpasswardemail = async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ status: 'failed', message: 'Email is required' });
      }

      const user = await usermodel.findOne({ email: email });

      if (!user) {
        return res.status(400).json({ status: 'failed', message: 'Email does not exist' });
      }

      const secret = user._id + process.env.JWT_SECRET_KEY;
      const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '15m' });

      //send email


      const link = `http://localhost:3000/api/user/reset/${user._id}/${token}`;
      console.log(link);
      let info = await transporter.sendMail({
        from: process.env.EMAIL_FROM, // Sender address (e.g., '"Pen Down" <noreply@pendown.com>')
        to: user.email, // List of receivers
        subject: "Pen Down Password Reset", // Subject line
        html: `
          <p>Dear ${user.name},</p>
          <p>You requested a password reset. Click the link below to reset your password:</p>
          <p><a href="${link}">Reset Password</a></p>
          <p>If you did not request this, please ignore this email.</p>
          <p>Best regards,</p>
          <p>The Pen Down Team</p>
        `, // HTML body
      });




      // Send email with the link here (using a mail service like nodemailer)
      res.send({ status: 'success', message: 'Email sent' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ status: 'failed', message: 'An error occurred' });
    }
  };
  static userPassword = async (req, res) => {
    const { password } = req.body;
    const { id, token } = req.params;

    try {
      const user = await usermodel.findById(id);
      if (!user) {
        return res.status(404).json({ status: 'failed', message: 'User not found' });
      }

      const secret = user._id + process.env.JWT_SECRET_KEY;
      jwt.verify(token, secret);

      if (password) {
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        await usermodel.findByIdAndUpdate(id, { $set: { password: hashedPassword } });

        return res.status(200).json({ status: 'success', message: 'Password changed successfully' });
      } else {
        return res.status(400).json({ status: 'failed', message: 'All fields are required' });
      }
    } catch (error) {
      return res.status(500).json({ status: 'failed', message: 'Invalid token or token has expired' });
    }
  };
  //send email

  // //sending pdf on  admin panel
  // const upload = multer({ dest: 'uploads/' })



}
export const deletePdf = async (req, res) => {
  const { id } = req.params;
  try {
    // Check if the id is valid
    if (!id) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    // Delete the PDF file
    const pdf = await pdfmodel.findByIdAndDelete(id);
    if (!pdf) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Check if the file was deleted successfully
    if (pdf.deletedCount === 0) {
      return res.status(500).json({ message: 'Error deleting file' });
    }

    res.status(200).json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error deleting file' });
  }
};
export default UserController;
export { uploadPdf, fetchPdfs };