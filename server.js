const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const sqlite3 = require("sqlite3");
const path = require("path");

dotenv.config();

const app = express();
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");

// Initialize SQLite database (in-memory)
const db = new sqlite3.Database(":memory:", (err) => {
  if (err) {
    return console.error("Error opening database: ", err.message);
  }
  console.log("Connected to the in-memory SQLite database.");

  // Create users table
  db.run(
    `CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )`,
    (err) => {
      if (err) {
        console.error("Error creating users table: ", err.message);
      }
    }
  );
});

// Route to render the login page
app.get("/LOGIN", (req, res) => {
  res.render("login");
});

// Route to render the register page
app.get("/REGISTER", (req, res) => {
  res.render("register");
});

// Route for user registration
app.post("/REGISTER", async (req, res) => {
  const { name, password } = req.body;

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Save user in the database
  const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
  db.run(query, [name, hashedPassword], (err) => {
    if (err) {
      console.error("Error inserting user:", err.message);
      return res.render("fail");
    }
    console.log("User registered successfully");
    // Redirect to login page
    res.redirect("/LOGIN");
  });
});

// Route for user login
app.post("/LOGIN", (req, res) => {
  const { name, password } = req.body;

  // Find user in the database
  const query = `SELECT * FROM users WHERE username = ?`;
  db.get(query, [name], async (err, user) => {
    if (err) {
      console.error("Error querying user:", err.message);
      return res.render("fail");
    }

    if (!user) {
      // User not found
      return res.render("fail");
    }

    // Compare the password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("fail");
    }

    // Create a JWT token
    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    console.log("JWT Token:", token);

    // Render the start page
    res.render("start");
  });
});

// Redirect to /LOGIN from /
app.get("/", (req, res) => {
  res.redirect("/LOGIN");
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
