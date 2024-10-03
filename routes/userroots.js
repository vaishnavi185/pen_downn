import express from 'express';
import UserController,{ uploadPdf, fetchPdfs, deletePdf }  from '../Controllers/UserController.js';
import  { checkAuth,isAdmin } from '../Middlewares/authymiddleware.js';

const router = express.Router();
router.post('/resetpassword',checkAuth);
router.get('/logineduser',checkAuth);

router.post('/register', UserController.userRegistration);
router.post('/login', UserController.userlogin);
router.post('/email-send-password', UserController.senduserpasswardemail); // Corrected route
router.post('/reset-password/:id/:token', UserController.userPassword);

router.post('/upload-pdf', checkAuth, isAdmin, uploadPdf);
router.delete('/delete-pdf/:id', deletePdf);
// router.post('/forgot-password', UserController.forgotPassword);
// router.post('/reset/:token', UserController.resetPassword);
//private route after login
router.post('/resetpassword',UserController.resetpassword);
router.post('/logineduser',UserController.loggeduser);
router.get('/pdf', fetchPdfs);

export default router;
