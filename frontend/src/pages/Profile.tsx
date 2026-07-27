import { useState } from "react";

const Profile = () => {
  const [profile, setProfile] = useState({
    name: "Admin User",
    email: "admin@example.com",
    role: "Administrator",
    phone: "9876543210",
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;

    setProfile((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSave = () => {
    console.log("Profile updated:", profile);
    alert("Profile updated successfully!");
  };

  return (
    <div style={{ padding: "20px", color: "white" }}>
      <h2>Profile</h2>

      <div style={{ maxWidth: "400px" }}>
        {/* Name */}
        <div style={{ marginBottom: "15px" }}>
          <label>Name</label>
          <input
            type="text"
            name="name"
            value={profile.name}
            onChange={handleChange}
            style={{
              width: "100%",
              padding: "8px",
              marginTop: "5px",
              background: "#1e293b",
              border: "1px solid #334155",
              color: "white",
            }}
          />
        </div>

        {/* Email */}
        <div style={{ marginBottom: "15px" }}>
          <label>Email</label>
          <input
            type="email"
            name="email"
            value={profile.email}
            onChange={handleChange}
            style={{
              width: "100%",
              padding: "8px",
              marginTop: "5px",
              background: "#1e293b",
              border: "1px solid #334155",
              color: "white",
            }}
          />
        </div>

        {/* Phone */}
        <div style={{ marginBottom: "15px" }}>
          <label>Phone</label>
          <input
            type="text"
            name="phone"
            value={profile.phone}
            onChange={handleChange}
            style={{
              width: "100%",
              padding: "8px",
              marginTop: "5px",
              background: "#1e293b",
              border: "1px solid #334155",
              color: "white",
            }}
          />
        </div>

        {/* Role (readonly) */}
        <div style={{ marginBottom: "15px" }}>
          <label>Role</label>
          <input
            type="text"
            value={profile.role}
            disabled
            style={{
              width: "100%",
              padding: "8px",
              marginTop: "5px",
              background: "#111827",
              border: "1px solid #334155",
              color: "#9ca3af",
            }}
          />
        </div>

        {/* Save Button */}
        <button
          onClick={handleSave}
          style={{
            padding: "10px",
            background: "#3b82f6",
            border: "none",
            color: "white",
            cursor: "pointer",
            width: "100%",
          }}
        >
          Save Profile
        </button>
      </div>
    </div>
  );
};

export default Profile;