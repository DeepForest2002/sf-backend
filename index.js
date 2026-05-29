const express = require("express");
const axios = require("axios");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(
  cors({
    origin: "https://sf-frontend-seven.vercel.app/",
    credentials: true,
  }),
);
app.use(express.json());

let tokenStore = {};
let codeVerifier = ""; // store verifier temporarily

// Helper: generate code verifier and challenge
function generatePKCE() {
  // Step 1: Random string (code verifier)
  const verifier = crypto.randomBytes(32).toString("base64url");

  // Step 2: SHA256 hash of verifier (code challenge)
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  return { verifier, challenge };
}

// Login route - now includes PKCE
app.get("/auth/login", (req, res) => {
  const { verifier, challenge } = generatePKCE();

  codeVerifier = verifier; // save for later use in callback

  const url =
    `${process.env.SF_LOGIN_URL}/services/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=${process.env.SF_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.SF_REDIRECT_URI)}` +
    `&code_challenge=${challenge}` + // 👈 added
    `&code_challenge_method=S256`; // 👈 added

  res.redirect(url);
});

// Callback route - now sends code_verifier
app.get("/oauth/callback", async (req, res) => {
  const { code } = req.query;
  try {
    const response = await axios.post(
      `${process.env.SF_LOGIN_URL}/services/oauth2/token`,
      null,
      {
        params: {
          grant_type: "authorization_code",
          client_id: process.env.SF_CLIENT_ID,
          client_secret: process.env.SF_CLIENT_SECRET,
          redirect_uri: process.env.SF_REDIRECT_URI,
          code,
          code_verifier: codeVerifier, // 👈 added
        },
      },
    );

    tokenStore = response.data;
    res.redirect(`${process.env.FRONTEND_URL}?loggedIn=true`);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Get validation rules
app.get("/api/validation-rules", async (req, res) => {
  try {
    const { access_token, instance_url } = tokenStore;
    const query = `SELECT Id, ValidationName, Active, Description 
                   FROM ValidationRule 
                   WHERE EntityDefinition.QualifiedApiName = 'Account'`;
    const response = await axios.get(
      `${instance_url}/services/data/v59.0/tooling/query?q=${encodeURIComponent(query)}`,
      { headers: { Authorization: `Bearer ${access_token}` } },
    );
    res.json(response.data.records);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Toggle a validation rule
app.patch("/api/validation-rules/:id", async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;
  try {
    const { access_token, instance_url } = tokenStore;
    await axios.patch(
      `${instance_url}/services/data/v59.0/tooling/sobjects/ValidationRule/${id}`,
      { Metadata: { active } },
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          "Content-Type": "application/json",
        },
      },
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(5000, () => console.log("Backend running on port 5000"));
