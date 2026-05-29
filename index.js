const express = require("express");
const axios = require("axios");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

app.use(
  cors({
    origin: "https://sf-frontend-seven.vercel.app",
    credentials: true,
  }),
);

app.use(express.json());

// Store PKCE verifiers temporarily
const pkceStore = new Map();

function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
  return { verifier, challenge };
}

// Login
app.get("/auth/login", (req, res) => {
  const { verifier, challenge } = generatePKCE();
  const state = crypto.randomBytes(16).toString("hex"); // unique key

  pkceStore.set(state, verifier); // store verifier with state key

  const url =
    `${process.env.SF_LOGIN_URL}/services/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=${process.env.SF_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.SF_REDIRECT_URI)}` +
    `&code_challenge=${challenge}` +
    `&code_challenge_method=S256` +
    `&state=${state}`; // 👈 pass state to Salesforce

  res.redirect(url);
});

// Callback
app.get("/oauth/callback", async (req, res) => {
  const { code, state } = req.query;
  const codeVerifier = pkceStore.get(state); // 👈 retrieve using state

  if (!codeVerifier) {
    return res.redirect(`${process.env.FRONTEND_URL}?error=missing_verifier`);
  }

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
          code_verifier: codeVerifier,
        },
      },
    );

    pkceStore.delete(state); // cleanup

    const { access_token, instance_url } = response.data;

    // 👇 Send tokens directly to frontend in URL
    res.redirect(
      `${process.env.FRONTEND_URL}?` +
        `access_token=${access_token}&` +
        `instance_url=${encodeURIComponent(instance_url)}`,
    );
  } catch (err) {
    console.error("OAuth error:", err.response?.data || err.message);
    res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed`);
  }
});

// Get validation rules — now receives token from frontend
app.get("/api/validation-rules", async (req, res) => {
  const { access_token, instance_url } = req.headers;

  if (!access_token || !instance_url) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const query = `SELECT Id, ValidationName, Active, Description 
                   FROM ValidationRule 
                   WHERE EntityDefinition.QualifiedApiName = 'Account'`;

    const response = await axios.get(
      `${decodeURIComponent(instance_url)}/services/data/v59.0/tooling/query?q=${encodeURIComponent(query)}`,
      { headers: { Authorization: `Bearer ${access_token}` } },
    );

    res.json(response.data.records);
  } catch (err) {
    console.error("Rules error:", err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// Toggle validation rule
app.patch("/api/validation-rules/:id", async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;
  const { access_token, instance_url } = req.headers;

  try {
    await axios.patch(
      `${decodeURIComponent(instance_url)}/services/data/v59.0/tooling/sobjects/ValidationRule/${id}`,
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
    console.error("Toggle error:", err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

app.listen(5000, () => console.log("Backend running on port 5000"));
