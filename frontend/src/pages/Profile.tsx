import { useState } from "react";

export default function Profile() {
  const [profile, setProfile] = useState({
    name: "Admin User",
    email: "admin@example.com",
    phone: "+91 9876543210",
    role: "System Administrator",
    department: "Cyber Security",
    lastLogin: "28 Jul 2026, 09:15 AM",
    status: "Active",
  });

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const { name, value } = e.target;

    setProfile((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSave = () => {
    console.log(profile);
    alert("Profile updated successfully!");
  };

  return (
    <div style={{ color: "white" }}>
      <h1 style={{ marginBottom: "25px" }}>Profile</h1>

      <div
        style={{
          display: "flex",
          gap: "25px",
          flexWrap: "wrap",
        }}
      >
        {/* Left Card */}

        <div
          style={{
            width: "280px",
            background: "#1e293b",
            border: "1px solid #334155",
            borderRadius: "12px",
            padding: "25px",
            textAlign: "center",
          }}
        >
          <div
            style={{
              width: "90px",
              height: "90px",
              borderRadius: "50%",
              background: "#3b82f6",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              fontSize: "42px",
              margin: "0 auto 20px",
            }}
          >
            👤
          </div>

          <h2>{profile.name}</h2>

          <p
            style={{
              color: "#94a3b8",
              marginTop: "5px",
            }}
          >
            {profile.role}
          </p>

          <hr
            style={{
              borderColor: "#334155",
              margin: "20px 0",
            }}
          />

          <InfoRow title="Department" value={profile.department} />

          <InfoRow title="Status" value={profile.status} />

          <InfoRow title="Last Login" value={profile.lastLogin} />
        </div>

        {/* Right Card */}

        <div
          style={{
            flex: 1,
            minWidth: "350px",
            background: "#1e293b",
            border: "1px solid #334155",
            borderRadius: "12px",
            padding: "25px",
          }}
        >
          <InputField
            label="Full Name"
            name="name"
            value={profile.name}
            onChange={handleChange}
          />

          <InputField
            label="Email Address"
            name="email"
            value={profile.email}
            onChange={handleChange}
          />

          <InputField
            label="Phone Number"
            name="phone"
            value={profile.phone}
            onChange={handleChange}
          />

          <div style={{ marginBottom: "20px" }}>
            <label style={labelStyle}>Role</label>

            <input
              value={profile.role}
              disabled
              style={{
                ...inputStyle,
                background: "#111827",
                color: "#94a3b8",
                cursor: "not-allowed",
              }}
            />
          </div>

          <button
            onClick={handleSave}
            style={{
              background: "#3b82f6",
              color: "white",
              border: "none",
              padding: "12px 20px",
              borderRadius: "8px",
              cursor: "pointer",
              fontWeight: "bold",
            }}
          >
            Save Profile
          </button>
        </div>
      </div>
    </div>
  );
}

type InputProps = {
  label: string;
  name: string;
  value: string;
  onChange: (
    e: React.ChangeEvent<HTMLInputElement>
  ) => void;
};

function InputField({
  label,
  name,
  value,
  onChange,
}: InputProps) {
  return (
    <div style={{ marginBottom: "20px" }}>
      <label style={labelStyle}>{label}</label>

      <input
        type="text"
        name={name}
        value={value}
        onChange={onChange}
        style={inputStyle}
      />
    </div>
  );
}

type InfoProps = {
  title: string;
  value: string;
};

function InfoRow({ title, value }: InfoProps) {
  return (
    <div
      style={{
        marginBottom: "15px",
      }}
    >
      <div
        style={{
          color: "#94a3b8",
          fontSize: "13px",
        }}
      >
        {title}
      </div>

      <div
        style={{
          marginTop: "4px",
          fontWeight: "bold",
        }}
      >
        {value}
      </div>
    </div>
  );
}

const labelStyle = {
  display: "block" as const,
  marginBottom: "8px",
  color: "#cbd5e1",
};

const inputStyle = {
  width: "100%",
  padding: "10px",
  background: "#0f172a",
  border: "1px solid #334155",
  borderRadius: "8px",
  color: "white",
  fontSize: "15px",
};