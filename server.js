const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const sharp = require("sharp");
const path = require("path");

const app = express();

//env config
dotenv.config();

// Middleware
app.use(cors());
app.use(express.json()); // Using express.json() to parse JSON bodies

// Set storage engine
const storage = multer.memoryStorage(); // Store the file in memory as a buffer

// Initiate upload
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 1024 * 1024 * 5, // Maximum file size (5MB)
  },
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/; // Allowed extensions
    const mimetype = filetypes.test(file.mimetype); // Check file mimetype
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    ); // Check file extension
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb("Error: Images only!");
    }
  },
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => console.log("Connected to MongoDB"));

// Define a schema
const userSchema = new mongoose.Schema({
  fullName: String,
  email: { type: String, unique: true },
  password: String,
  username: String,
  brief: String,
  location: String,
  image: {
    type: Buffer,
  },
});

// Define a model
const User = mongoose.model("User", userSchema);

// Set up a route for file uploads
app.post("/upload", upload.single("file"), (req, res) => {
  // Handle the uploaded file
  //  console.log("Received file from frontend:", req.file); // Log received file from frontend
  res.json({ message: "File uploaded successfully!" });
});

// Signup route with Multer middleware
app.post("/api/signup", upload.single("image"), async (req, res) => {
  // console.log("Received data from frontend:", req.body); // Log received data from frontend
  // console.log("Received file from frontend:", req.file); // Log received file from frontend
  const buffer = await sharp(req.file.buffer).png().toBuffer();
  const { mimetype } = req.file; // Extract image buffer and mimetype
  // console.log(buffer, mimetype, "Check mime and buff");
  const { fullName, email, password, username, brief, location } = req.body;

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    // Check if a file was uploaded
    const imageBuffer = req.file ? Buffer.from(req.file.buffer) : null;

    // Save user to database
    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
      username,
      brief,
      location,
      image: imageBuffer, // Save image buffer to the database
    });
    await newUser.save();

    res.status(201).json({ message: "User signed up successfully" });
  } catch (error) {
    console.error("Error signing up:", error);
    res.status(500).json({ message: "Error signing up" });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // Compare the provided password with the hashed password from the database
    //password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send({
        success: false,
        message: "Invlid username or password",
      });
    }

    // If the password matches, generate a JWT token
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET);
    res.status(200).json({ token, userId: user._id });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Error logging in!!!" });
  }
});

// Route to fetch all users' data
app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find();
    // console.log("All users data:", users); // Log all users' data
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Error fetching users" });
  }
});
// Define a route to handle user deletion
app.delete("/api/users/:userId", async (req, res) => {
  const userId = req.params.userId;
  try {
    // Find the user by userId
    const user = await User.findById(userId);

    // If user not found, return 404 status
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Delete the user
    await user.deleteOne();

    // Return success message
    return res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    // Handle errors
    console.error("Error deleting user:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
