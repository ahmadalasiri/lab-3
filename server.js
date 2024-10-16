const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const sqlite3 = require("sqlite3");

dotenv.config();

const app = express();
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");

const db = new sqlite3.Database(":memory:", (err) => {
  if (err) {
    return console.log(err.message);
  }

  db.run(
    `CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )`,
    (err) => {
      if (err) {
        console.log("Error creating users table: ", err.message);
      }
    }
  );
});

app.get("/LOGIN", (req, res) => {
  res.render("login");
});

app.get("/REGISTER", (req, res) => {
  res.render("register");
});

app.post("/REGISTER", async (req, res) => {
  const { name, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
  db.run(query, [name, hashedPassword], (err) => {
    if (err) {
      console.log(err.message);
      return res.render("fail");
    }
    res.redirect("/LOGIN");
  });
});

app.post("/LOGIN", (req, res) => {
  const { name, password } = req.body;

  const query = `SELECT * FROM users WHERE username = ?`;
  db.get(query, [name], async (err, user) => {
    if (err) {
      console.log(err.message);
      return res.render("fail");
    }

    if (!user) {
      return res.render("fail");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("fail");
    }

    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    console.log("JWT Token:", token);
    res.render("start");
  });
});

app.get("/", (req, res) => {
  res.redirect("/LOGIN");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
