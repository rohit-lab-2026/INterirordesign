require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const session = require("express-session");

const app = express();

// Render (and most hosts) terminate HTTPS in front of the app; trust the
// proxy so secure cookies work correctly.
app.set("trust proxy", 1);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Holds the pending OTP for the visitor currently verifying their email,
// used by the register/login/verify-otp routes below.
app.use(session({
    secret: process.env.SESSION_SECRET || process.env.JWT_SECRET || "fallback-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: "auto", sameSite: "lax", maxAge: 10 * 60 * 1000 }
}));

// Serve static files (your HTML, CSS, JS)
app.use(express.static("public"));

// MongoDB connection (uses MONGODB_URI from environment / .env file)
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/contactDB";

mongoose.connect(MONGODB_URI, {
    dbName: process.env.DB_NAME || "nordic_designs",
    serverSelectionTimeoutMS: 8000   // fail fast instead of hanging the request
})
.then(() => console.log("MongoDB connected 🐳"))
.catch(err => console.error("Mongo connection error:", err.message));

// Return a clear JSON error if the DB is not connected (readyState 1 = connected)
function requireDb(req, res, next) {
    if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({
            message: "Database is not connected right now. Please try again shortly."
        });
    }
    next();
}

// Schema
const contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    subject: String,
    message: String,
    budget: Boolean,
    timeline: Boolean,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Contact = mongoose.model("Contact", contactSchema);

// Route: Serve homepage
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Route: Handle contact form
app.post(["/contact", "/api/contact"], requireDb, async (req, res) => {
    try {
        const { name, email, phone, subject, message, budget, timeline } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({ message: "Name, email and message are required." });
        }
        if (!NAME_RE.test(String(name).trim())) {
            return res.status(400).json({ message: "Name must contain letters only (no numbers or symbols)." });
        }

        const newContact = new Contact({
            name,
            email,
            phone,
            subject,
            message,
            budget,
            timeline
        });

        await newContact.save();

        res.status(200).json({ message: "Data saved successfully 🚀" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error saving data" });
    }
});

// Schema: quote requests (modal on index.html)
const quoteSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    service: String,
    budget: String,
    description: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Quote = mongoose.model("Quote", quoteSchema);

// ─── User accounts (login / register) ──────────────────────────────────────
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    verified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);

const JWT_SECRET = process.env.JWT_SECRET || "fallback-secret-key";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Letters, spaces, hyphens and apostrophes only - no digits or symbols.
const NAME_RE = /^[A-Za-z\s'-]+$/;

// ─── Email (OTP verification) via Brevo's transactional email REST API ────
// Uses HTTPS (port 443) rather than SMTP, since Render's free tier blocks
// outbound SMTP ports. Requires BREVO_API_KEY and MAIL_FROM_EMAIL (a sender
// verified in your Brevo account) to be set as environment variables.
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const MAIL_FROM_EMAIL = process.env.MAIL_FROM_EMAIL;
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || "Nordic Designs";

async function sendMail({ to, subject, html }) {
    if (!BREVO_API_KEY || !MAIL_FROM_EMAIL) {
        throw new Error("BREVO_API_KEY and MAIL_FROM_EMAIL must be set.");
    }
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
            "api-key": BREVO_API_KEY,
            "content-type": "application/json",
            accept: "application/json"
        },
        body: JSON.stringify({
            sender: { name: MAIL_FROM_NAME, email: MAIL_FROM_EMAIL },
            to: [{ email: to }],
            subject,
            htmlContent: html
        }),
        signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) {
        const detail = await response.text().catch(() => "");
        throw new Error(`Brevo responded ${response.status}: ${detail}`);
    }
}

if (BREVO_API_KEY && MAIL_FROM_EMAIL) {
    console.log("[mail] Brevo configured, sending as", MAIL_FROM_EMAIL);
} else {
    console.error("[mail] not configured: set BREVO_API_KEY and MAIL_FROM_EMAIL");
}

// Generates a 6-digit OTP, remembers it in the visitor's session, and emails
// it. Shared by register (new account verification) and login (resend for
// a not-yet-verified account).
async function issueOtp(req, email, purpose) {
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    req.session.otp = otp;
    req.session.otpEmail = email.toLowerCase();
    req.session.otpPurpose = purpose || "verify";
    req.session.otpExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    const subject = "Verify your Nordic Designs email";
    const html = `
      <div style="font-family: sans-serif; max-width: 420px; margin: auto;">
        <h2>${subject}</h2>
        <p style="font-size: 28px; font-weight: bold; letter-spacing: 6px;">${otp}</p>
        <p style="color:#666; font-size: 13px;">This code expires in 10 minutes.</p>
      </div>
    `;

    await sendMail({ to: email, subject, html });
    return { message: "OTP sent." };
}

// Server-side validation, mirrors the client-side checks in login.html
function validateRegisterInput({ name, email, password }) {
    const errors = [];
    if (!name || name.trim().length < 2) errors.push("Name must be at least 2 characters.");
    else if (!NAME_RE.test(name.trim())) errors.push("Name must contain letters only (no numbers or symbols).");
    if (!email || !EMAIL_RE.test(email)) errors.push("A valid email address is required.");
    if (!password || password.length < 6) errors.push("Password must be at least 6 characters.");
    return errors;
}

// Verifies a Bearer JWT and attaches { id, email } to req.auth
function requireAuth(req, res, next) {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) {
        return res.status(401).json({ message: "Missing or invalid Authorization header." });
    }
    try {
        req.auth = jwt.verify(token, JWT_SECRET); // { id, email, iat, exp }
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token. Please log in again." });
    }
}

// Allows a request through if EITHER a valid x-admin-key header is present
// (full access to any account), OR a valid Bearer token belonging to the
// same user as req.params.id (self access only). This is what lets you test
// "access a different account" in Postman via the admin key, while a normal
// logged-in user's own token only ever works on their own record.
function requireAdminOrSelf(req, res, next) {
    const configuredKey = process.env.ADMIN_KEY;
    const providedKey = req.headers["x-admin-key"];
    if (configuredKey && providedKey === configuredKey) {
        return next();
    }

    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) {
        return res.status(401).json({
            message: "Provide a valid x-admin-key header, or a Bearer token for this account."
        });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.id !== req.params.id) {
            return res.status(403).json({ message: "You can only access your own account." });
        }
        req.auth = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token." });
    }
}

// Admin-only: lists every registered account (never returns password hashes)
function requireAdmin(req, res, next) {
    const configuredKey = process.env.ADMIN_KEY;
    if (!configuredKey) {
        return res.status(503).json({ message: "Admin access is not configured on this server." });
    }
    if (req.headers["x-admin-key"] !== configuredKey) {
        return res.status(403).json({ message: "Invalid admin key." });
    }
    next();
}

// Route: Register a new account. Account is created unverified; a 6-digit
// OTP is emailed via Brevo, and no JWT is issued until /api/auth/verify-otp
// confirms it. If the account save fails, that's a genuine "could not
// create the account" error. If the account saves but the OTP email fails,
// the account is rolled back (deleted) instead of being left as an
// unverified, unrecoverable account that would block future signups with
// "already exists" while never being able to receive its code.
app.post("/api/auth/register", requireDb, async (req, res) => {
    const { name, email, password } = req.body || {};
    const errors = validateRegisterInput({ name, email, password });
    if (errors.length) {
        return res.status(400).json({ message: errors[0], errors });
    }

    const key = email.toLowerCase();
    let user;
    try {
        const existing = await User.findOne({ email: key });
        if (existing) {
            return res.status(409).json({ message: "An account with this email already exists." });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        user = await User.create({ name, email: key, passwordHash, verified: false });
    } catch (err) {
        console.error("[register] could not save account:", err.message);
        return res.status(500).json({ message: "Could not create the account." });
    }

    try {
        const result = await issueOtp(req, key, "verify");
        res.status(201).json({ message: result.message || `We sent a verification code to ${key}.`, requiresOtp: true });
    } catch (err) {
        console.error("[register] account created but OTP email failed, rolling back:", err.message);
        await User.deleteOne({ _id: user._id }).catch((cleanupErr) => {
            console.error("[register] rollback delete failed:", cleanupErr.message);
        });
        res.status(502).json({
            message: "We could not send the verification email. Please check the mail configuration and try again."
        });
    }
});

// Route: Log in with email + password. Unverified accounts are blocked and
// sent a fresh OTP instead of a token, so they finish verifying first.
app.post("/api/auth/login", requireDb, async (req, res) => {
    try {
        const { email, password } = req.body || {};
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required." });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        const matches = await bcrypt.compare(password, user.passwordHash);
        if (!matches) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        if (!user.verified) {
            try {
                const result = await issueOtp(req, user.email, "verify");
                return res.status(200).json({
                    message: result.message || "Please verify your email before signing in. We sent a new code.",
                    requiresOtp: true
                });
            } catch (otpErr) {
                console.error("[login] credentials ok but OTP email failed:", otpErr.message);
                return res.status(502).json({
                    message: "Your password is correct, but your account is still unverified and we could not send a new code. Please try again shortly."
                });
            }
        }

        const token = jwt.sign({ id: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: "7d" });
        res.status(200).json({
            message: "Login successful ✅",
            token,
            user: { id: user._id, name: user.name, email: user.email, createdAt: user.createdAt }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Login failed" });
    }
});

// Route: (Re)send an OTP without logging in — used by the "Resend code" link.
app.post("/api/auth/send-otp", async (req, res) => {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: "email is required." });
    try {
        const result = await issueOtp(req, email, "verify");
        res.status(200).json(result);
    } catch (err) {
        console.error("[send-otp] failed:", err.message);
        res.status(502).json({ message: "Failed to send email." });
    }
});

// Route: Confirm the code the visitor typed against the one stored in their
// session. On success, marks the account verified and returns a JWT so the
// frontend can log them straight in.
app.post("/api/auth/verify-otp", requireDb, async (req, res) => {
    const { email, otp } = req.body || {};
    if (!email || !otp) {
        return res.status(400).json({ message: "email and otp are required." });
    }
    if (!req.session.otp) {
        return res.status(400).json({ message: "No code was requested." });
    }
    if (Date.now() > req.session.otpExpiresAt) {
        return res.status(400).json({ message: "Code expired. Request a new one." });
    }
    if (req.session.otpEmail !== email.toLowerCase() || req.session.otp !== otp) {
        return res.status(400).json({ message: "Incorrect code." });
    }

    delete req.session.otp;
    delete req.session.otpEmail;
    delete req.session.otpExpiresAt;

    try {
        const user = await User.findOneAndUpdate(
            { email: email.toLowerCase() },
            { verified: true },
            { new: true }
        );
        if (!user) {
            return res.status(404).json({ message: "Account not found." });
        }
        const token = jwt.sign({ id: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: "7d" });
        res.status(200).json({
            message: "Email verified 🎉",
            token,
            user: { id: user._id, name: user.name, email: user.email, createdAt: user.createdAt }
        });
    } catch (err) {
        console.error("[verify-otp] could not mark user verified:", err.message);
        res.status(500).json({ message: "Verified, but could not finish logging you in. Please sign in." });
    }
});

// GET: Return every registered account (admin only, no password hashes)
app.get("/api/users", requireAdmin, requireDb, async (req, res) => {
    try {
        const users = await User.find({}, { passwordHash: 0 }).sort({ createdAt: -1 });
        res.status(200).json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error fetching users" });
    }
});

// GET: Return a single user by id (admin key, or that user's own token)
app.get("/api/users/:id", requireAdminOrSelf, requireDb, async (req, res) => {
    try {
        const user = await User.findById(req.params.id, { passwordHash: 0 });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json(user);
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Invalid user id" });
    }
});

// PUT: Update a user's name/email/password (admin key, or that user's own token)
app.put("/api/users/:id", requireAdminOrSelf, requireDb, async (req, res) => {
    try {
        const { name, email, password } = req.body || {};
        const update = {};

        if (name !== undefined) {
            if (name.trim().length < 2) {
                return res.status(400).json({ message: "Name must be at least 2 characters." });
            }
            update.name = name;
        }
        if (email !== undefined) {
            if (!EMAIL_RE.test(email)) {
                return res.status(400).json({ message: "A valid email address is required." });
            }
            update.email = email.toLowerCase();
        }
        if (password !== undefined) {
            if (password.length < 6) {
                return res.status(400).json({ message: "Password must be at least 6 characters." });
            }
            update.passwordHash = await bcrypt.hash(password, 10);
        }

        const updated = await User.findByIdAndUpdate(req.params.id, update, {
            new: true,
            runValidators: true
        }).select("-passwordHash");

        if (!updated) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ message: "User updated successfully ✅", user: updated });
    } catch (err) {
        console.error(err);
        if (err.code === 11000) {
            return res.status(409).json({ message: "That email is already in use." });
        }
        res.status(400).json({ message: "Error updating user" });
    }
});

// DELETE: Remove a user account (admin key, or that user's own token)
app.delete("/api/users/:id", requireAdminOrSelf, requireDb, async (req, res) => {
    try {
        const deleted = await User.findByIdAndDelete(req.params.id);
        if (!deleted) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json({ message: "User deleted successfully 🗑️" });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Invalid user id" });
    }
});

// Route: Handle quote requests
app.post("/api/quote", requireDb, async (req, res) => {
    try {
        const { name, email, phone, service, budget, description } = req.body;

        if (!name || !email) {
            return res.status(400).json({ message: "Name and email are required." });
        }
        if (!NAME_RE.test(String(name).trim())) {
            return res.status(400).json({ message: "Name must contain letters only (no numbers or symbols)." });
        }

        await new Quote({ name, email, phone, service, budget, description }).save();

        res.status(201).json({ message: "Quote request received! We'll contact you shortly. 🎉" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error saving quote request" });
    }
});

// GET: Return all contact form records (requires database connection)
// Optional ?email=... filters to records matching that email (case-insensitive).
// An email isn't a unique key on this collection - the same person can submit
// the form more than once - so this returns an array, not a single record.
app.get("/api/contacts", requireDb, async (req, res) => {
    try {
        const filter = {};
        if (req.query.email) {
            filter.email = new RegExp(`^${String(req.query.email).trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i");
        }
        const contacts = await Contact.find(filter).sort({ createdAt: -1 });
        res.status(200).json(contacts);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error fetching contacts" });
    }
});

// GET: Return all quote request records (requires database connection).
// Same optional ?email=... filter as /api/contacts, same reasoning.
app.get("/api/quotes", requireDb, async (req, res) => {
    try {
        const filter = {};
        if (req.query.email) {
            filter.email = new RegExp(`^${String(req.query.email).trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i");
        }
        const quotes = await Quote.find(filter).sort({ createdAt: -1 });
        res.status(200).json(quotes);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error fetching quote requests" });
    }
});

// GET: Return a single contact record by id
app.get("/api/contacts/:id", requireDb, async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({ message: "Contact not found" });
        }
        res.status(200).json(contact);
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Invalid contact id" });
    }
});

// PUT: Update a contact record by id
app.put("/api/contacts/:id", requireDb, async (req, res) => {
    try {
        const { name, email, phone, subject, message, budget, timeline } = req.body;

        const updated = await Contact.findByIdAndUpdate(
            req.params.id,
            { name, email, phone, subject, message, budget, timeline },
            { new: true, runValidators: true }
        );

        if (!updated) {
            return res.status(404).json({ message: "Contact not found" });
        }

        res.status(200).json({ message: "Contact updated successfully ✅", contact: updated });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Error updating contact" });
    }
});

// DELETE: Remove a contact record by id
app.delete("/api/contacts/:id", requireDb, async (req, res) => {
    try {
        const deleted = await Contact.findByIdAndDelete(req.params.id);

        if (!deleted) {
            return res.status(404).json({ message: "Contact not found" });
        }

        res.status(200).json({ message: "Contact deleted successfully 🗑️" });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Invalid contact id" });
    }
});

// DELETE: Remove every contact record matching ?email=... (required - this
// route refuses to run with no filter, so it can never wipe the whole
// collection by accident). Since email isn't unique here, this can delete
// more than one record; the response reports how many were removed.
app.delete("/api/contacts", requireDb, async (req, res) => {
    const email = req.query.email ? String(req.query.email).trim() : "";
    if (!email) {
        return res.status(400).json({ message: "A ?email=... query parameter is required." });
    }
    try {
        const escaped = email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const result = await Contact.deleteMany({ email: new RegExp(`^${escaped}$`, "i") });
        res.status(200).json({ message: `Deleted ${result.deletedCount} contact record(s) for ${email}.`, deletedCount: result.deletedCount });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error deleting contacts" });
    }
});

// GET: Return a single quote request by id
app.get("/api/quotes/:id", requireDb, async (req, res) => {
    try {
        const quote = await Quote.findById(req.params.id);
        if (!quote) {
            return res.status(404).json({ message: "Quote request not found" });
        }
        res.status(200).json(quote);
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Invalid quote id" });
    }
});

// PUT: Update a quote request by id
app.put("/api/quotes/:id", requireDb, async (req, res) => {
    try {
        const { name, email, phone, service, budget, description } = req.body;

        const updated = await Quote.findByIdAndUpdate(
            req.params.id,
            { name, email, phone, service, budget, description },
            { new: true, runValidators: true }
        );

        if (!updated) {
            return res.status(404).json({ message: "Quote request not found" });
        }

        res.status(200).json({ message: "Quote request updated successfully ✅", quote: updated });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Error updating quote request" });
    }
});

// DELETE: Remove a quote request by id
app.delete("/api/quotes/:id", requireDb, async (req, res) => {
    try {
        const deleted = await Quote.findByIdAndDelete(req.params.id);

        if (!deleted) {
            return res.status(404).json({ message: "Quote request not found" });
        }

        res.status(200).json({ message: "Quote request deleted successfully 🗑️" });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Invalid quote id" });
    }
});

// DELETE: Remove every quote record matching ?email=... (required - see the
// matching /api/contacts route for why).
app.delete("/api/quotes", requireDb, async (req, res) => {
    const email = req.query.email ? String(req.query.email).trim() : "";
    if (!email) {
        return res.status(400).json({ message: "A ?email=... query parameter is required." });
    }
    try {
        const escaped = email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const result = await Quote.deleteMany({ email: new RegExp(`^${escaped}$`, "i") });
        res.status(200).json({ message: `Deleted ${result.deletedCount} quote record(s) for ${email}.`, deletedCount: result.deletedCount });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Error deleting quote requests" });
    }
});

// Health check (open /health in a browser to see if the server + DB are up)
app.get("/health", (req, res) => {
    res.json({ server: "ok", database: mongoose.connection.readyState === 1 ? "connected" : "disconnected" });
});

// Always answer unknown POST/API routes with JSON (never HTML)
app.use((req, res, next) => {
    if (req.method !== "GET") return res.status(404).json({ message: "Route not found" });
    next();
});
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: "Server error" });
});

// Start server (Render provides PORT; falls back to 5050 locally)
const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} 🔥`);
});
