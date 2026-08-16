import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import "./Signup.css";

export default function Signup() {
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSignup = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setError("");
    setSuccess("");

    if (!name || !email || !password || !confirmPassword) {
      setError("Please fill in all fields.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    try {
      setLoading(true);

      const response = await api.post("/auth/register", {
        name,
        email,
        password,
      });

      setSuccess(
        response.data.message || "Account created successfully."
      );

      setName("");
      setEmail("");
      setPassword("");
      setConfirmPassword("");

      setTimeout(() => {
        navigate("/");
      }, 1200);
    } catch (err: unknown) {
      const message =
        getErrorMessage(err) ||
        "Registration failed. Please try again.";

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="signup-page">
      <div className="signup-card">
        <div className="signup-logo">
          🛡️
        </div>

        <h1 className="signup-title">
          Create Account
        </h1>

        <p className="signup-subtitle">
          Register for AI Network IDS
        </p>

        <form onSubmit={handleSignup}>
          <label className="signup-label">Name</label>

          <input
            type="text"
            placeholder="Enter your name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="signup-input"
            disabled={loading}
          />

          <label className="signup-label signup-label-spaced">
            Email
          </label>

          <input
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="signup-input"
            disabled={loading}
          />

          <label className="signup-label signup-label-spaced">
            Password
          </label>

          <input
            type="password"
            placeholder="Create a password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="signup-input"
            disabled={loading}
          />

          <label className="signup-label signup-label-spaced">
            Confirm Password
          </label>

          <input
            type="password"
            placeholder="Confirm your password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="signup-input"
            disabled={loading}
          />

          {error && (
            <div className="signup-error">
              {error}
            </div>
          )}

          {success && (
            <div className="signup-success">
              {success}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="signup-button"
          >
            {loading ? "CREATING ACCOUNT..." : "SIGN UP"}
          </button>
        </form>

        <p className="signup-login-text">
          Already have an account?{" "}
          <span onClick={() => navigate("/")} className="signup-login-link">
            Login
          </span>
        </p>
      </div>
    </div>
  );
}

function getErrorMessage(err: unknown) {
  if (typeof err !== "object" || err === null || !("response" in err)) {
    return "";
  }

  const response = (err as { response?: { data?: { message?: unknown } } }).response;
  return typeof response?.data?.message === "string"
    ? response.data.message
    : "";
}
