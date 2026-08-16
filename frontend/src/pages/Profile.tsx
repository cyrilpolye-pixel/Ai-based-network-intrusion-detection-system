import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import { useAuth } from "../context/AuthContext";
import "./Profile.css";

type ProfileUser = {
  _id?: string;
  id?: string;
  name: string;
  email: string;
  role: string;
};

export default function Profile() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [profile, setProfile] = useState<ProfileUser | null>(user);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let isMounted = true;

    const loadProfile = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await api.get("/auth/profile");
        const currentUser = response.data?.user;

        if (!currentUser) {
          throw new Error("Profile response did not include user data.");
        }

        if (isMounted) {
          setProfile(currentUser);
        }
      } catch (err: any) {
        const message =
          err.response?.data?.message ||
          "Unable to load your profile. Please try again.";

        if (isMounted) {
          setError(message);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    loadProfile();

    return () => {
      isMounted = false;
    };
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/", { replace: true });
  };

  if (loading) {
    return (
      <ProfileShell>
        <StatusMessage>Loading your profile...</StatusMessage>
      </ProfileShell>
    );
  }

  if (error) {
    return (
      <ProfileShell>
        <StatusMessage tone="error">{error}</StatusMessage>
        <button onClick={handleLogout} className="profile-button">
          Logout
        </button>
      </ProfileShell>
    );
  }

  if (!profile) {
    return (
      <ProfileShell>
        <StatusMessage tone="error">No profile data is available.</StatusMessage>
        <button onClick={handleLogout} className="profile-button">
          Logout
        </button>
      </ProfileShell>
    );
  }

  return (
    <ProfileShell>
      <div className="profile-grid">
        <div className="profile-card profile-summary-card">
          <div className="profile-avatar">👤</div>

          <h2>{profile.name}</h2>
          <p className="profile-role-text">{profile.role}</p>

          <hr className="profile-divider" />

          <InfoRow title="Email" value={profile.email} />
          <InfoRow title="Role" value={profile.role} />
        </div>

        <div className="profile-card profile-details-card">
          <ReadOnlyField label="Full Name" value={profile.name} />
          <ReadOnlyField label="Email Address" value={profile.email} />
          <ReadOnlyField label="Role" value={profile.role} />

          <button onClick={handleLogout} className="profile-button">
            Logout
          </button>
        </div>
      </div>
    </ProfileShell>
  );
}

type ProfileShellProps = {
  children: React.ReactNode;
};

function ProfileShell({ children }: ProfileShellProps) {
  return (
    <div className="profile-page">
      <h1 className="profile-title">Profile</h1>
      {children}
    </div>
  );
}

type ReadOnlyFieldProps = {
  label: string;
  value: string;
};

function ReadOnlyField({ label, value }: ReadOnlyFieldProps) {
  return (
    <div className="profile-field">
      <label className="profile-label">{label}</label>
      <input value={value} readOnly className="profile-input" />
    </div>
  );
}

type InfoProps = {
  title: string;
  value: string;
};

function InfoRow({ title, value }: InfoProps) {
  return (
    <div className="profile-info-row">
      <div className="profile-info-title">{title}</div>
      <div className="profile-info-value">{value}</div>
    </div>
  );
}

type StatusMessageProps = {
  children: React.ReactNode;
  tone?: "info" | "error";
};

function StatusMessage({ children, tone = "info" }: StatusMessageProps) {
  return <div className={`profile-status profile-status-${tone}`}>{children}</div>;
}
