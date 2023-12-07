/* 
Filename: complexCode.js
Description: This code demonstrates an advanced video streaming platform with user authentication, content management system, and user interactions.
*/

// Import required libraries
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// Create Express server
const app = express();
app.use(bodyParser.json());

// Database Models
const User = mongoose.model('User', {
  name: String,
  email: String,
  password: String,
  role: String,
});

const Video = mongoose.model('Video', {
  title: String,
  description: String,
  url: String,
  createdBy: String,
});

// Authentication Routes
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  
  // Create user
  const user = new User({ name, email, password: hashedPassword, role: 'user' });
  await user.save();
  
  res.send('Registration successful!');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Find user
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send('User not found.');
  
  // Check password
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid password.');
  
  // Generate JWT token
  const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
  
  res.header('Authorization', `Bearer ${token}`)
    .status(200)
    .send('Login successful!');
});

// Protected Routes
app.post('/videos', authenticateToken, async (req, res) => {
  const { title, description, url } = req.body;
  
  // Save video
  const video = new Video({ title, description, url, createdBy: req.user._id });
  await video.save();
  
  res.status(201).send('Video created successfully!');
});

app.get('/videos', authenticateToken, async (req, res) => {
  const videos = await Video.find();
  
  res.send(videos);
});

// Token verification middleware
function authenticateToken(req, res, next) {
  const authHeader = req.header('Authorization');
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.sendStatus(401);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/myapp', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    // Start the server
    app.listen(3000, () => {
      console.log('Server started on port 3000');
    });
  })
  .catch((err) => {
    console.error(err);
  });