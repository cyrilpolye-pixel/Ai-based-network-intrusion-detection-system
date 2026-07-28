import { useNavigate } from "react-router-dom";

export default function Login() {
  const navigate = useNavigate();

  return (
    <div
      style={{
        height: "100vh",
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

        <label
          style={{
            color: "#cbd5e1",
            display: "block",
            marginBottom: "8px",
          }}
        >
          Username
        </label>

        <input
          type="text"
          placeholder="Enter username"
          style={inputStyle}
        />

        <label
          style={{
            color: "#cbd5e1",
            display: "block",
            marginTop: "20px",
            marginBottom: "8px",
          }}
        >
          Password
        </label>

        <input
          type="password"
          placeholder="Enter password"
          style={inputStyle}
        />

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

        <button
          onClick={() => navigate("/dashboard")}
          style={{
            width: "100%",
            marginTop: "30px",
            padding: "14px",
            background: "#3b82f6",
            color: "white",
            border: "none",
            borderRadius: "8px",
            fontSize: "16px",
            fontWeight: "bold",
            cursor: "pointer",
          }}
        >
          LOGIN
        </button>

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

const inputStyle = {
  width: "100%",
  padding: "12px",
  background: "#0f172a",
  border: "1px solid #334155",
  borderRadius: "8px",
  color: "white",
  outline: "none",
  fontSize: "15px",
} as const;