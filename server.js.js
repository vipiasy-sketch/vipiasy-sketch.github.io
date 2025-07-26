const express = require('express');
const twilio = require('twilio');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../')));

// Twilio configuration
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Rate limiting for OTP requests
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: "Too many OTP requests, please try again later"
});

// In-memory storage for OTPs (use database in production)
const otpStore = new Map();

// Generate a random 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP via SMS using Twilio
async function sendSMS(phone, otp) {
  try {
    await twilioClient.messages.create({
      body: `Your OTP for Noble AFFIS Consult is: ${otp}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone
    });
    console.log(`SMS sent to ${phone}`);
  } catch (error) {
    console.error('Error sending SMS:', error);
    throw error;
  }
}

// Send OTP via Email using Nodemailer
async function sendEmail(email, otp) {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OTP Verification - Noble AFFIS Consult',
      text: `Your OTP for Noble AFFIS Consult is: ${otp}`
    });
    console.log(`Email sent to ${email}`);
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
}

// Request OTP endpoint
app.post('/api/request-otp', otpLimiter, async (req, res) => {
  const { contact, method } = req.body; // contact can be phone or email
  
  if (!contact || !method) {
    return res.status(400).json({ error: 'Contact and method are required' });
  }
  
  const otp = generateOTP();
  const expirationTime = Date.now() + 10 * 60 * 1000; // 10 minutes from now
  
  // Store OTP with expiration
  otpStore.set(contact, { otp, expirationTime });
  
  try {
    if (method === 'sms') {
      await sendSMS(contact, otp);
    } else if (method === 'email') {
      await sendEmail(contact, otp);
    } else {
      return res.status(400).json({ error: 'Invalid method. Use sms or email' });
    }
    
    res.json({ success: true, message: `OTP sent to ${contact}` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP endpoint
app.post('/api/verify-otp', (req, res) => {
  const { contact, otp } = req.body;
  
  if (!contact || !otp) {
    return res.status(400).json({ error: 'Contact and OTP are required' });
  }
  
  const storedData = otpStore.get(contact);
  
  if (!storedData) {
    return res.status(400).json({ error: 'OTP not found or expired' });
  }
  
  const { otp: storedOtp, expirationTime } = storedData;
  
  if (Date.now() > expirationTime) {
    otpStore.delete(contact);
    return res.status(400).json({ error: 'OTP has expired' });
  }
  
  if (otp !== storedOtp) {
    return res.status(400).json({ error: 'Invalid OTP' });
  }
  
  // OTP is valid - delete it to prevent reuse
  otpStore.delete(contact);
  
  res.json({ 
    success: true, 
    message: 'OTP verified successfully'
  });
});

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../index.html'));
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to view your website`);
});