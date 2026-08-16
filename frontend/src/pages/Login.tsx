import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../services/api";
import { useAuth } from "../context/AuthContext";
import "./Login.css";

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleLogin = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setError("");

    if (!email || !password) {
      setError("Please enter your email and password.");
      return;
    }

    try {
      setLoading(true);

      const response = await api.post("/auth/login", {
        email,
        password,
      });

      const { token, user } = response.data;

      if (!token || !user) {
        throw new Error("Invalid login response from server.");
      }

      login(token, user);

      navigate("/dashboard");
    } catch (err: unknown) {
      const message =
        getErrorMessage(err) ||
        "Login failed. Please check your email and password.";

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">🛡️</div>

        <h1 className="login-title">AI Network IDS</h1>

        <p className="login-subtitle">
          AI-Based Network Intrusion Detection System
        </p>

        <form onSubmit={handleLogin}>
          <label className="login-label">Email</label>

          <input
            type="email"
            placeholder="Enter email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="login-input"
            disabled={loading}
          />

          <label className="login-label login-label-spaced">Password</label>

          <input
            type="password"
            placeholder="Enter password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="login-input"
            disabled={loading}
          />

          {error && <div className="login-error">{error}</div>}

          <div className="login-options">
            <label className="login-checkbox-label">
              <input
                type="checkbox"
                className="login-checkbox"
                disabled={loading}
              />
              Remember Me
            </label>

            <span className="login-forgot">Forgot Password?</span>
          </div>

          <Link to="/signup" className="login-signup-link">
            Don&apos;t have an account? Sign up
          </Link>

          <button
            type="submit"
            disabled={loading}
            className="login-button"
          >
            {loading ? "LOGGING IN..." : "LOGIN"}
          </button>
        </form>

        <p className="login-footer">
          AI-Based Network Intrusion Detection System
          <br />
          Version 1.0
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
