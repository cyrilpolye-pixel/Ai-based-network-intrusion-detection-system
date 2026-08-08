import { FormEvent, useState } from "react";
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
    } catch (err: any) {
      const message =
        err.response?.data?.message ||
        "Registration failed. Please try again.";

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
          Create Account
        </h1>

        <p
          style={{
            color: "#94a3b8",
            textAlign: "center",
            marginBottom: "30px",
          }}
        >
          Register for AI Network IDS
        </p>

        <form onSubmit={handleSignup}>
          <label style={labelStyle}>Name</label>

          <input
            type="text"
            placeholder="Enter your name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={inputStyle}
            disabled={loading}
          />

          <label
            style={{
              ...labelStyle,
              marginTop: "18px",
            }}
          >
            Email
          </label>

          <input
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={inputStyle}
            disabled={loading}
          />

          <label
            style={{
              ...labelStyle,
              marginTop: "18px",
            }}
          >
            Password
          </label>

          <input
            type="password"
            placeholder="Create a password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={inputStyle}
            disabled={loading}
          />

          <label
            style={{
              ...labelStyle,
              marginTop: "18px",
            }}
          >
            Confirm Password
          </label>

          <input
            type="password"
            placeholder="Confirm your password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            style={inputStyle}
            disabled={loading}
          />

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

          {success && (
            <div
              style={{
                marginTop: "15px",
                padding: "10px 12px",
                background: "rgba(34, 197, 94, 0.12)",
                border: "1px solid #22c55e",
                borderRadius: "8px",
                color: "#86efac",
                fontSize: "14px",
              }}
            >
              {success}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              marginTop: "25px",
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
            {loading ? "CREATING ACCOUNT..." : "SIGN UP"}
          </button>
        </form>

        <p
          style={{
            color: "#94a3b8",
            textAlign: "center",
            marginTop: "25px",
            fontSize: "14px",
          }}
        >
          Already have an account?{" "}
          <span
            onClick={() => navigate("/")}
            style={{
              color: "#3b82f6",
              cursor: "pointer",
              fontWeight: "bold",
            }}
          >
            Login
          </span>
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

