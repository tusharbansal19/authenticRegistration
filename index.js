const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});


userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

app.post('/api/users/register', async (req, res) => {
  const { username, email, password } = req.body;
console.log(username, email, password);

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Please provide all required fields: username, email, and password.' });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists with this email.' });
    }

    const user = await User.create({ username, email, password });
    res.status(201).json({ message: 'User registered successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.post('/api/users/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Please provide both username and password.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'Invalid username or password.' });
    }

    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    const token = generateToken(user._id);
    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// 1.3 Forgot Password
const nodemailer = require('nodemailer');

app.post('/api/users/forgot-password', async (req, res) => {
  const { email } = req.body;

  // Validate Input
  if (!email) {
    return res.status(400).json({ message: 'Please provide an email address.' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found with this email.' });
    }

    const resetToken = generateToken(user._id);

    const { APP_EMAIL, APP_PASS, HOST_NO } = process.env;

    // Create a transport object using the configuration from your new example
    const transporter = nodemailer.createTransport({
      host: HOST_NO,
      port: 465,
      secure: true, // Use true for port 465, false for other ports
      auth: {
        user: APP_EMAIL,
        pass: APP_PASS,
      },
    });

    
    const resetUrl = `https://authenticregistration.onrender.com/reset-password/${resetToken}`;

    console.log(resetUrl);
    console.log(resetUrl)

    // Send email using the transporter object
    const info = await transporter.sendMail({
      from: APP_EMAIL, // Sender's email
      to: user.email, // Recipient's email address
      subject: 'Password Reset Request', // Subject line
      html: `<p>Click the link to reset your password: <a href="${resetUrl}">${resetUrl}</a></p>`, // HTML formatted message
    });

    console.log("Message sent: %s", info.messageId);
    res.status(200).json({ message: 'Password reset email sent', resetUrl });

  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});
app.get('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  // const { password } = req.body;

  // Validate Input

  try {
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
   
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({ message: 'Password successfully reset.' });
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

const PORT = process.env.PORT ;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));