import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import { useAuth } from "../context/AuthContext";

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
    } catch (err: any) {
      const message =
        err.response?.data?.message ||
        "Login failed. Please check your email and password.";

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0f172a",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        padding: "20px",
      }}
    >
      <div
        style={{
          width: "420px",
          maxWidth: "100%",
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: "15px",
          padding: "40px",
          boxShadow: "0 10px 30px rgba(0,0,0,0.4)",
        }}
      >
        {/* Logo */}
        <div
          style={{
            width: "70px",
            height: "70px",
            borderRadius: "50%",
            background: "#3b82f6",
            color: "white",
            fontSize: "30px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            margin: "0 auto 20px",
          }}
        >
          🛡️
        </div>

        <h1
          style={{
            color: "white",
            textAlign: "center",
            marginBottom: "8px",
          }}
        >
          AI Network IDS
        </h1>

        <p
          style={{
            color: "#94a3b8",
            textAlign: "center",
            marginBottom: "35px",
          }}
        >
          AI-Based Network Intrusion Detection System
        </p>

        <form onSubmit={handleLogin}>
          {/* Email */}
          <label style={labelStyle}>Email</label>

          <input
            type="email"
            placeholder="Enter email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={inputStyle}
            disabled={loading}
          />

          {/* Password */}
          <label
            style={{
              ...labelStyle,
              marginTop: "20px",
            }}
          >
            Password
          </label>

          <input
            type="password"
            placeholder="Enter password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={inputStyle}
            disabled={loading}
          />

          {/* Error */}
          {error && (
            <div
              style={{
                marginTop: "15px",
                padding: "10px 12px",
                background: "rgba(239, 68, 68, 0.12)",
                border: "1px solid #ef4444",
                borderRadius: "8px",
                color: "#fca5a5",
                fontSize: "14px",
              }}
            >
              {error}
            </div>
          )}

          {/* Remember Me / Forgot Password */}
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginTop: "20px",
            }}
          >
            <label
              style={{
                color: "#94a3b8",
                fontSize: "14px",
              }}
            >
              <input
                type="checkbox"
                style={{ marginRight: "8px" }}
                disabled={loading}
              />
              Remember Me
            </label>

            <span
              style={{
                color: "#3b82f6",
                fontSize: "14px",
                cursor: "pointer",
              }}
            >
              Forgot Password?
            </span>
          </div>
<a href="/signup">Don't have an account? Sign up</a>
          {/* Login */}
          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              marginTop: "30px",
              padding: "14px",
              background: loading ? "#64748b" : "#3b82f6",
              color: "white",
              border: "none",
              borderRadius: "8px",
              fontSize: "16px",
              fontWeight: "bold",
              cursor: loading ? "not-allowed" : "pointer",
            }}
          >
            {loading ? "LOGGING IN..." : "LOGIN"}
          </button>
        </form>

        <p
          style={{
            color: "#64748b",
            textAlign: "center",
            marginTop: "30px",
            fontSize: "13px",
          }}
        >
          AI-Based Network Intrusion Detection System
          <br />
          Version 1.0
        </p>
      </div>
    </div>
  );
}

const labelStyle = {
  color: "#cbd5e1",
  display: "block",
  marginBottom: "8px",
};

const inputStyle = {
  width: "100%",
  padding: "12px",
  background: "#0f172a",
  border: "1px solid #334155",
  borderRadius: "8px",
  color: "white",
  outline: "none",
  fontSize: "15px",
  boxSizing: "border-box" as const,
};

