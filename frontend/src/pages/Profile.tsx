import { useEffect, useState, useCallback } from "react";
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
  createdAt?: string;
};

export default function Profile() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [profile, setProfile] = useState<ProfileUser | null>(user);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  // Edit Profile Form
  const [isEditing, setIsEditing] = useState(false);
  const [editName, setEditName] = useState("");
  const [editRole, setEditRole] = useState("admin");
  const [savingProfile, setSavingProfile] = useState(false);

  // Change Password Form
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);

  const showToast = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => {
      setSuccessMsg("");
    }, 4000);
  };

  const loadProfile = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const response = await api.get("/auth/profile");
      const currentUser = response.data?.user;

      if (!currentUser) {
        throw new Error("Profile response did not include user data.");
      }

      setProfile(currentUser);
      setEditName(currentUser.name || "");
      setEditRole(currentUser.role || "admin");
    } catch (err: any) {
      const message =
        err.response?.data?.message ||
        "Unable to load your profile. Please check backend connection.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProfile();
  }, [loadProfile]);

  const handleUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editName.trim()) return;

    try {
      setSavingProfile(true);
      setError("");

      const res = await api.put("/auth/profile", {
        name: editName.trim(),
        role: editRole,
      });

      if (res.data?.user) {
        setProfile(res.data.user);
      }
      setIsEditing(false);
      showToast("Profile information updated successfully.");
    } catch (err: any) {
      setError(err.response?.data?.message || "Failed to update profile.");
    } finally {
      setSavingProfile(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!currentPassword || !newPassword) {
      setError("Please fill out all password fields.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("New password and confirmation do not match.");
      return;
    }

    if (newPassword.length < 6) {
      setError("New password must be at least 6 characters long.");
      return;
    }

    try {
      setChangingPassword(true);
      const res = await api.put("/auth/change-password", {
        currentPassword,
        newPassword,
      });

      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setShowPasswordForm(false);
      showToast(res.data?.message || "Password updated successfully.");
    } catch (err: any) {
      setError(err.response?.data?.message || "Failed to change password.");
    } finally {
      setChangingPassword(false);
    }
  };

  const handleLogout = () => {
    logout();
    navigate("/", { replace: true });
  };

  const formatDate = (val?: string) => {
    if (!val) return "Active User";
    const d = new Date(val);
    return Number.isNaN(d.getTime()) ? "Active User" : d.toLocaleDateString();
  };

  // Initials for avatar
  const getInitials = (name?: string) => {
    if (!name) return "U";
    const parts = name.trim().split(" ");
    if (parts.length === 1) return parts[0].charAt(0).toUpperCase();
    return (parts[0].charAt(0) + parts[1].charAt(0)).toUpperCase();
  };

  if (loading) {
    return (
      <div className="profile-page">
        <div className="profile-loading-card">
          <div className="profile-spinner" />
          <p>Loading security analyst profile...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="profile-page">
      {/* Header */}
      <div className="profile-header">
        <div>
          <h1 className="profile-title">Security Analyst Profile</h1>
          <p className="profile-subtitle">
            Manage your account credentials, security privileges, and session authentication.
          </p>
        </div>

        <button onClick={handleLogout} className="profile-logout-top-btn">
          🚪 Logout
        </button>
      </div>

      {/* Alerts */}
      {successMsg && (
        <div className="profile-banner banner-success">
          <span>✓</span>
          <span>{successMsg}</span>
        </div>
      )}

      {error && (
        <div className="profile-banner banner-error">
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}

      <div className="profile-grid">
        {/* Left Column: Avatar & Role Summary Card */}
        <div className="profile-card profile-summary-card">
          <div className="profile-avatar-circle">
            {getInitials(profile?.name)}
          </div>

          <h2 className="profile-user-name">{profile?.name || "Analyst"}</h2>
          <span className="profile-role-badge">
            {profile?.role === "admin" ? "🛡️ Security Admin" : "🔍 Security Analyst"}
          </span>
          <span className="profile-email-text">{profile?.email}</span>

          <hr className="profile-divider" />

          <div className="profile-summary-items">
            <div className="summary-item">
              <span className="summary-lbl">Member Since</span>
              <strong className="summary-val">{formatDate(profile?.createdAt)}</strong>
            </div>

            <div className="summary-item">
              <span className="summary-lbl">Auth Provider</span>
              <span className="summary-val">JWT Bearer (7 Days)</span>
            </div>

            <div className="summary-item">
              <span className="summary-lbl">Access Scope</span>
              <span className="summary-val text-green">Full SOC Access</span>
            </div>
          </div>

          <button onClick={handleLogout} className="profile-logout-btn">
            Sign Out of SOC
          </button>
        </div>

        {/* Right Column: Account Management & Security */}
        <div className="profile-details-column">
          {/* Account Details & Edit Profile */}
          <div className="profile-card">
            <div className="card-header-flex">
              <div>
                <h3 className="card-heading">Account Information</h3>
                <span className="card-subheading">Personal credentials and access role</span>
              </div>

              {!isEditing && (
                <button
                  className="profile-edit-btn"
                  onClick={() => setIsEditing(true)}
                >
                  ✏️ Edit Profile
                </button>
              )}
            </div>

            {isEditing ? (
              <form onSubmit={handleUpdateProfile} className="profile-edit-form">
                <div className="form-group">
                  <label>Full Name</label>
                  <input
                    type="text"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="profile-input"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>Email Address (Immutable)</label>
                  <input
                    type="email"
                    value={profile?.email || ""}
                    disabled
                    className="profile-input input-disabled"
                  />
                </div>

                <div className="form-group">
                  <label>Security Role</label>
                  <select
                    value={editRole}
                    onChange={(e) => setEditRole(e.target.value)}
                    className="profile-select"
                  >
                    <option value="admin">Security Administrator</option>
                    <option value="analyst">Security Analyst</option>
                  </select>
                </div>

                <div className="form-actions">
                  <button
                    type="submit"
                    className="profile-btn-primary"
                    disabled={savingProfile}
                  >
                    {savingProfile ? "Saving..." : "Save Changes"}
                  </button>
                  <button
                    type="button"
                    className="profile-btn-secondary"
                    onClick={() => setIsEditing(false)}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <div className="profile-fields-list">
                <div className="profile-field-row">
                  <span className="field-lbl">Full Name</span>
                  <strong className="field-val">{profile?.name}</strong>
                </div>

                <div className="profile-field-row">
                  <span className="field-lbl">Email Address</span>
                  <span className="field-val mono">{profile?.email}</span>
                </div>

                <div className="profile-field-row">
                  <span className="field-lbl">Assigned Role</span>
                  <span className="field-val capitalize">{profile?.role}</span>
                </div>
              </div>
            )}
          </div>

          {/* Change Password Card */}
          <div className="profile-card">
            <div className="card-header-flex">
              <div>
                <h3 className="card-heading">Security & Password</h3>
                <span className="card-subheading">Update login credentials and hashing</span>
              </div>

              {!showPasswordForm && (
                <button
                  className="profile-edit-btn"
                  onClick={() => setShowPasswordForm(true)}
                >
                  🔒 Change Password
                </button>
              )}
            </div>

            {showPasswordForm ? (
              <form onSubmit={handleChangePassword} className="password-form">
                <div className="form-group">
                  <label>Current Password</label>
                  <input
                    type="password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    className="profile-input"
                    placeholder="Enter existing password"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>New Password (min 6 characters)</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="profile-input"
                    placeholder="Enter new strong password"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>Confirm New Password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="profile-input"
                    placeholder="Re-type new password"
                    required
                  />
                </div>

                <div className="form-actions">
                  <button
                    type="submit"
                    className="profile-btn-primary"
                    disabled={changingPassword}
                  >
                    {changingPassword ? "Updating..." : "Update Password"}
                  </button>
                  <button
                    type="button"
                    className="profile-btn-secondary"
                    onClick={() => {
                      setShowPasswordForm(false);
                      setCurrentPassword("");
                      setNewPassword("");
                      setConfirmPassword("");
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <p className="password-info-text">
                Password is encrypted using standard bcrypt salt (10 rounds). Recommended rotation every 90 days.
              </p>
            )}
          </div>

          {/* Active Session & SOC Metadata */}
          <div className="profile-card session-card">
            <h3 className="card-heading">Active SOC Session Diagnostics</h3>
            <div className="session-grid">
              <div className="session-metric">
                <span className="metric-lbl">Session Status</span>
                <span className="metric-val text-green">● Authenticated</span>
              </div>

              <div className="session-metric">
                <span className="metric-lbl">Token Expiry</span>
                <span className="metric-val">7 Days</span>
              </div>

              <div className="session-metric">
                <span className="metric-lbl">User ID</span>
                <code className="metric-val mono">
                  {profile?._id || profile?.id || "soc-user"}
                </code>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
