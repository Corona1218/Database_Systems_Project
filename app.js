// Core setup for HealthHub backend
const express = require("express");
const mysql = require("mysql2/promise");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();

// Middleware to handle JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the 'public' folder (login, dashboards, images, etc.)
app.use(express.static(path.join(__dirname, "public")));

// Session config so we can remember who is logged in
app.use(
  session({
    secret: "healthhub_super_secret",
    resave: false,
    saveUninitialized: true,
  })
);

// Database connection pool
const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "Lionelmessi10!", // <- same as in DBeaver
  database: "HealthHUB",
});

// Small helpers for routes that need login / role
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }
  next();
}

function requireRole(expectedRole) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== expectedRole) {
      return res
        .status(403)
        .json({ success: false, message: "Not authorized for this page" });
    }
    next();
  };
}

// ---------------- LOGIN ----------------
app.post("/login", async (req, res) => {
  const { email, password, role } = req.body; // role from toggle (patient / doctor) but we trust DB

  try {
    // Look up the user by email
    const [rows] = await db.query(
      "SELECT * FROM UserAccount WHERE Email = ?",
      [email]
    );

    if (rows.length === 0) {
      // Email not found
      return res.json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const user = rows[0];

    // Compare entered password with bcrypt hash in PasswordHash column
    const isValid = await bcrypt.compare(password, user.PasswordHash);

    if (!isValid) {
      return res.json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Save useful stuff in the session in case we want it later
    req.session.user = {
      id: user.UserID,            // primary key from UserAccount
      role: user.Role,            // "PATIENT" or "DOCTOR"
      patientId: user.PatientID,  // may be null for doctors
      doctorId: user.DoctorID,    // may be null for patients
    };

    // Send JSON back to login.html
    return res.json({
      success: true,
      role: user.Role,
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
});

/// ---------------- PATIENT DASHBOARD DATA ----------------
// Returns patient info + upcoming appointments + allergy info
app.get(
  "/api/patient/dashboard",
  requireLogin,
  requireRole("PATIENT"),
  async (req, res) => {
    const patientId = req.session.user.patientId;

    if (!patientId) {
      return res
        .status(400)
        .json({ success: false, message: "No patient linked to this user" });
    }

    try {
      // 1) Basic patient info
      const [patientRows] = await db.query(
        `SELECT PatientName, Age, Gender, Insurance 
         FROM Patient 
         WHERE PatientID = ?`,
        [patientId]
      );

      // 2) Recent / upcoming appointments
      const [apptRows] = await db.query(
        `SELECT 
           a.AppointmentID,
           a.AppointmentDate,
           a.StartTime,
           a.ApptStatus,
           a.ReasonForVisit,
           d.Name AS DoctorName
         FROM Appointment a
         JOIN Doctor d ON a.DoctorID = d.DoctorID
         WHERE a.PatientID = ?
         ORDER BY a.AppointmentDate DESC, a.StartTime DESC
         LIMIT 5`,
        [patientId]
      );

      // 3) Allergy warning info
      const [allergyRows] = await db.query(
        `SELECT AllergyName, ReactionType, Severity, AllergyFlag, AllergyNotes
         FROM Allergy_Warning_System
         WHERE PatientID = ?`,
        [patientId]
      );

      return res.json({
        success: true,
        patient: patientRows[0] || null,
        appointments: apptRows,
        allergies: allergyRows,
      });
    } catch (err) {
      console.error("Patient dashboard error:", err);
      return res.status(500).json({
        success: false,
        message: "Could not load patient dashboard",
      });
    }
  }
);

// ---------------- DOCTOR DASHBOARD DATA ----------------
// Returns doctor's upcoming schedule + patient list
app.get(
  "/api/doctor/dashboard",
  requireLogin,
  requireRole("DOCTOR"),
  async (req, res) => {
    const doctorId = req.session.user.doctorId;

    if (!doctorId) {
      return res
        .status(400)
        .json({ success: false, message: "No doctor linked to this user" });
    }

    try {
      // Upcoming appointments for this doctor
      const [apptRows] = await db.query(
        `SELECT 
           a.AppointmentID,
           a.AppointmentDate,
           a.StartTime,
           a.ApptStatus,
           a.ReasonForVisit,
           p.PatientName
         FROM Appointment a
         JOIN Patient p ON a.PatientID = p.PatientID
         WHERE a.DoctorID = ?
         ORDER BY a.AppointmentDate, a.StartTime
         LIMIT 10`,
        [doctorId]
      );

      // Distinct patients this doctor has seen
      const [patientRows] = await db.query(
        `SELECT DISTINCT 
           p.PatientID, 
           p.PatientName, 
           p.Age, 
           p.Gender
         FROM Appointment a
         JOIN Patient p ON a.PatientID = p.PatientID
         WHERE a.DoctorID = ?
         ORDER BY p.PatientName`,
        [doctorId]
      );

      return res.json({
        success: true,
        appointments: apptRows,
        patients: patientRows,
      });
    } catch (err) {
      console.error("Doctor dashboard error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Could not load doctor dashboard" });
    }
  }
);

// ---------------- LOGOUT ----------------
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Start the server
app.listen(3000, () => {
  console.log("HealthHub server running at http://localhost:3000");
});
