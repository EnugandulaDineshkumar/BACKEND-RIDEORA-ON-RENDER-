const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const RegisterUser = require("./src/models/model");
const middleware = require("./src/middleware/middleware");

dotenv.config();

const app = express();

// ==========================================
// CORS
// ==========================================

const allowedOrigins = [
  "http://localhost:5173",
  "https://rideora-full-stack-web-application.vercel.app",
  process.env.FRONTEND_URL,
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests without origin such as Postman
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
  res.status(200).json({
    message: "🚀 RIDEORA Backend API is running",
  });
});

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Backend is healthy",
  });
});

// ==========================================
// REGISTER
// POST /api/auth/register
// ==========================================

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      confirmPassword,
    } = req.body;

    if (
      !username ||
      !email ||
      !password ||
      !confirmPassword
    ) {
      return res.status(400).json({
        message: "All fields are required",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        message: "Passwords do not match",
      });
    }

    const existingUser = await RegisterUser.findOne({
      email: email.toLowerCase(),
    });

    if (existingUser) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    const newUser = new RegisterUser({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
    });

    await newUser.save();

    return res.status(201).json({
      message: "User registered successfully",
    });
  } catch (error) {
    console.error("Register Error:", error);

    return res.status(500).json({
      message: "Internal Server Error",
    });
  }
});

// ==========================================
// LOGIN
// POST /api/auth/login
// ==========================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message:
          "Email and password are required",
      });
    }

    const existingUser =
      await RegisterUser.findOne({
        email: email.toLowerCase(),
      });

    if (!existingUser) {
      return res.status(400).json({
        message: "User not found",
      });
    }

    const isPasswordValid =
      await bcrypt.compare(
        password,
        existingUser.password
      );

    if (!isPasswordValid) {
      return res.status(400).json({
        message: "Invalid password",
      });
    }

    const payload = {
      user: {
        id: existingUser._id,
      },
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    return res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: existingUser._id,
        username: existingUser.username,
        email: existingUser.email,
      },
    });
  } catch (error) {
    console.error("Login Error:", error);

    return res.status(500).json({
      message: "Server Error",
    });
  }
});

// ==========================================
// GET CURRENT USER
// GET /api/auth/me
// ==========================================

app.get(
  "/api/auth/me",
  middleware,
  async (req, res) => {
    try {
      const user =
        await RegisterUser.findById(
          req.user.id
        ).select("-password");

      if (!user) {
        return res.status(404).json({
          message: "User not found",
        });
      }

      return res.status(200).json({
        id: user._id,
        username: user.username,
        email: user.email,
      });
    } catch (error) {
      console.error(
        "Get Me Error:",
        error
      );

      return res.status(500).json({
        message: "Server Error",
      });
    }
  }
);

// ==========================================
// 404 HANDLER
// ==========================================

app.use((req, res) => {
  res.status(404).json({
    message: `Route not found: ${req.originalUrl}`,
  });
});

// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 2002;

const startServer = async () => {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error(
        "MONGO_URI is missing"
      );
    }

    if (!process.env.JWT_SECRET) {
      throw new Error(
        "JWT_SECRET is missing"
      );
    }

    await mongoose.connect(
      process.env.MONGO_URI
    );

    console.log(
      "✅ Connected to MongoDB"
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `🚀 Server running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "❌ Startup Error:",
      error.message
    );

    process.exit(1);
  }
};

startServer();