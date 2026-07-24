export default function Topbar() {
  return (
    <div
      style={{
        height: "70px",
        background: "#1e293b",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 25px",
        color: "white",
        borderBottom: "1px solid #334155",
      }}
    >
      <input
        type="text"
        placeholder="Search..."
        style={{
          width: "300px",
          padding: "10px",
          borderRadius: "8px",
          border: "none",
        }}
      />

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "20px",
        }}
      >
        <span style={{ cursor: "pointer" }}>🔔</span>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
          }}
        >
          <div
            style={{
              width: "40px",
              height: "40px",
              borderRadius: "50%",
              background: "#3b82f6",
            }}
          />
          <span>Admin</span>
        </div>
      </div>
    </div>
  );
}