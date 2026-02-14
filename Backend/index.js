// -------------------- Load environment --------------------
require("dotenv").config({
  path: require("path").join(__dirname, ".env"),
  override: true
});


const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
console.log("Environment variables loaded");
console.log("GOOGLE ID:", process.env.GOOGLE_CLIENT_ID);
console.log("ENV PATH CHECK");
console.log("DIR:", __dirname);
console.log("GOOGLE ID:", process.env.GOOGLE_CLIENT_ID);


// -------------------- Required modules --------------------
const mongoose = require("mongoose");
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const pdfParse = require("pdf-parse");
const { exec } = require("child_process");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

// 🔹 OAuth
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;

const saltRounds = 10;

const app = express();
app.use(express.json());
app.get("/", (req, res) => {
    res.send("Backend Working");
});

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "opsmind_secret",
    resave: false,
    saveUninitialized: false
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

console.log("__dirname path:", __dirname);
app.use(express.static(path.join(__dirname, "../frontend")));
const PORT = 3000;

// -------------------- MongoDB connection --------------------
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB Atlas connected");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
}
connectDB();

// -------------------- Upload folder --------------------
const uploadFolder = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder);

// -------------------- Multer --------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadFolder),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// -------------------- MongoDB Schemas --------------------
const pdfSchema = new mongoose.Schema({
  fileName: String,
  pages: Number,
  pdfPreview: String,
  uploadDate: { type: Date, default: Date.now }
});
const PdfModel = mongoose.model("Pdf", pdfSchema);

const pdfVectorSchema = new mongoose.Schema({
  fileName: String,
  chunkIndex: Number,
  textChunk: String,
  embedding: [Number],
  uploadDate: { type: Date, default: Date.now }
});
const PdfVector = mongoose.model("PdfVector", pdfVectorSchema);

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ["admin", "employee"], default: "employee" },
  isVerified: { type: Boolean, default: true }, // OAuth users auto verified
  otp: Number,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", userSchema);

// -------------------- Helpers --------------------
function chunkText(text, chunkSize = 1000, overlap = 100) {
  const chunks = [];
  let start = 0;
  while (start < text.length) {
    const end = Math.min(start + chunkSize, text.length);
    chunks.push(text.slice(start, end));
    start += chunkSize - overlap;
  }
  return chunks;
}

function cosineSimilarity(a, b) {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

// -------------------- Nodemailer --------------------
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// -------------------- OAuth Strategies --------------------

// ✅ GOOGLE
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {

  const email = profile.emails[0].value;

  let user = await User.findOne({ email });
  if (!user) {
    user = await User.create({
      name: profile.displayName,
      email,
      isVerified: true
    });
  }

  return done(null, user);
}));

// GITHUB
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "/auth/github/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value || `${profile.username}@github.com`;
      let user = await User.findOne({ email });
      if (!user) {
        user = await User.create({
          name: profile.username,
          email,
          password: "github-auth",
          role: "employee",
          isVerified: true
        });
      }
      return done(null, user);
    }
  )
);

// -------------------- OAuth Routes --------------------
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account"
  })
);
app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login.html" }),
  (req, res) => {
    res.send(`
      <script>
        window.opener.location.href = "/chat.html";
        window.close();
      </script>
    `);
  }
);

app.get("/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

app.get("/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login.html" }),
  (req, res) => res.redirect("/chat.html")
);

// -------------------- REGISTER --------------------
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Save user
    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
      role,
      isVerified: false
    });

    // Send OTP email (optional)
    const otp = Math.floor(100000 + Math.random() * 900000);
    newUser.otp = otp;
    await newUser.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "OTP Verification",
      text: `Your OTP is: ${otp}`
    });

    res.json({ message: "Registered successfully. Check your email for OTP." });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Registration failed" });
  }
});
// -------------------- LOGIN --------------------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    res.json({ message: "Login successful" });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});
// -------------------- VERIFY OTP --------------------
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    if (user.otp != otp) {
      return res.status(400).json({ error: "OTP verification failed" });
    }

    user.isVerified = true;
    user.otp = null;
    await user.save();

    res.json({ message: "OTP verified successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "OTP verification failed" });
  }
});
// -------------------- RESEND OTP --------------------
app.post("/api/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    user.otp = otp;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "OTP Resend",
      text: `Your new OTP is: ${otp}`
    });

    res.json({ message: "OTP resent successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Failed to resend OTP" });
  }
});

// -------------------- Start server --------------------
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
); 