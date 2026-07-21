import { useNavigate } from "react-router-dom";

export default function Login() {
  const navigate = useNavigate();

  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        background: "#0f172a",
      }}
    >
      <div
        style={{
          width: 350,
          background: "#1e293b",
          padding: 30,
          borderRadius: 10,
        }}
      >
        <h2 style={{ color: "white", textAlign: "center" }}>
          AI Network IDS
        </h2>

        <input
          type="text"
          placeholder="Username"
          style={{ width: "100%", padding: 10, marginTop: 20 }}
        />

        <input
          type="password"
          placeholder="Password"
          style={{ width: "100%", padding: 10, marginTop: 15 }}
        />

        <button
          style={{
            width: "100%",
            padding: 12,
            marginTop: 20,
            cursor: "pointer",
          }}
          onClick={() => navigate("/dashboard")}
        >
          Login
        </button>
      </div>
    </div>
  );
}