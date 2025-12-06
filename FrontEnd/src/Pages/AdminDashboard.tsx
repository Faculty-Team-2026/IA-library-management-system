import { useState, useEffect, lazy, Suspense } from "react";
import { useNavigate } from "react-router-dom";
import {
  faUser,
  faBook,
  faCrown,
  faSignIn,
  faMapMarkerAlt,
} from "@fortawesome/free-solid-svg-icons";
import Sidebar from "../components/admin/Sidebar";
import SearchBar from "../components/admin/SearchBar";
import api from "../Services/api";
import User from "../types/user";
import AddUserDialog from "../components/admin/AddUserDialog";
import UserList from "../components/admin/UserList";
import BookManagement from "../components/Book/BookManagement";
import ManageMemberShip from "../components/MemberShip/ManageMemberShip";
import JoinUS from "../components/admin/JoinUS";
import AddLocationDialog from "../components/maps/AddLocationDialog";
import locationService, { Location } from "../Services/locationService";
import SystemLogger from "../components/admin/SystemLogger";
import { faClipboard } from "@fortawesome/free-solid-svg-icons";

// Lazy load MapView component
const MapView = lazy(() => import("../components/maps/MapView"));

const sidebarItems = [
  { key: "users", icon: faUser, label: "Manage Users" },
  { key: "books", icon: faBook, label: "Manage Books" },
  { key: "req", icon: faSignIn, label: "Registration Requests" },
  { key: "memberships", icon: faCrown, label: "Manage Membership plans" },
  { key: "map", icon: faMapMarkerAlt, label: "Map" },
  { key: "logs", icon: faClipboard, label: "System Logs" },
];

const defaultNewUser = {
  id: 0,
  username: "",
  role: "",
  email: "",
  firstName: "",
  lastName: "",
  phoneNumber: "",
  password: "",
  ssn: "",
  createdAt: new Date().toISOString(),
};

const AdminDashboard = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState("users");
  const [users, setUsers] = useState<User[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [originalUser, setOriginalUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const token = localStorage.getItem("token");

  // States for the map
  const [locations, setLocations] = useState<Location[]>([]);
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [selectedLocationId, setSelectedLocationId] = useState<number | null>(
    null
  );
  const [isMapReady, setIsMapReady] = useState(false);
  const [mapError, setMapError] = useState<string | null>(null);

  const [isAddUserOpen, setIsAddUserOpen] = useState(false);
  const [newUser, setNewUser] = useState<typeof defaultNewUser>({
    ...defaultNewUser,
  });
  const [addUserError, setAddUserError] = useState<string | null>(null);

  const [locationPermission, setLocationPermission] =
    useState<PermissionState>("prompt");

  useEffect(() => {
    const loadData = async () => {
      if (!token) {
        navigate("/auth/login");
        return;
      }
      try {
        setLoading(true);
        setError(null);
        if (activeTab === "users") {
          const response = await api.get("/Users", {
            headers: { Authorization: `Bearer ${token}` },
          });
          setUsers(response.data);
          setFilteredUsers(response.data);
        }
      } catch (err) {
        setError("Failed to load data. Please try again.");
        console.error("Error loading data:", err);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [activeTab, navigate, token]);

  // Load locations
  useEffect(() => {
    const loadLocations = async () => {
      try {
        const data = await locationService.getLocations();
        setLocations(data);
      } catch (error) {
        console.error("Error loading locations:", error);
        setMapError("Failed to load locations");
      }
    };

    if (activeTab === "map") {
      loadLocations();
    }
  }, [activeTab]);

  // Check location permission status
  useEffect(() => {
    if (navigator.permissions && navigator.permissions.query) {
      navigator.permissions.query({ name: "geolocation" }).then((result) => {
        setLocationPermission(result.state);
        result.onchange = () => {
          setLocationPermission(result.state);
        };
      });
    }
  }, []);

  const handleSearch = (searchTerm: string) => {
    if (activeTab === "users") {
      const filtered = users.filter((user) =>
        [user.username, user.firstName, user.lastName, user.email].some(
          (field) => field.toLowerCase().includes(searchTerm.toLowerCase())
        )
      );
      setFilteredUsers(filtered);
    }
  };

  const handleAddClick = () => {
    if (activeTab === "users") setIsAddUserOpen(true);
  };

  const handleEditUser = (user: User) => {
    setEditingUser({ ...user });
    setOriginalUser({ ...user });
  };

  const handleCancelEdit = () => {
    setEditingUser(null);
    setOriginalUser(null);
  };

  const handleSaveUser = () => {
    if (!editingUser || !originalUser) return;
    const payload = {
      id: editingUser.id,
      username: editingUser.username,
      email: editingUser.email,
      firstName: editingUser.firstName,
      lastName: editingUser.lastName,
      phoneNumber: editingUser.phoneNumber?.trim() || null,
      role: editingUser.role,
      ssn: editingUser.ssn,
      createdAt: editingUser.createdAt,
    };

    api
      .put(`/Users/${editingUser.id}`, payload, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((response) => {
        const updated = response.data;
        const updatedUsers = users.map((u) =>
          u.id === editingUser.id ? { ...u, ...updated } : u
        );
        setUsers(updatedUsers);
        setFilteredUsers(updatedUsers);
        handleCancelEdit();
      })
      .catch((error) => {
        console.error("Error updating user:", error);
        setError(
          error.response?.data?.message ||
            error.response?.data?.title ||
            JSON.stringify(error.response?.data) ||
            "Error updating user."
        );
      });
  };

  const handleDeleteUser = (id: number) => {
    api
      .delete(`/Users/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then(() => {
        const updatedUsers = users.filter((u) => u.id !== id);
        setUsers(updatedUsers);
        setFilteredUsers(updatedUsers);
      })
      .catch((error) => {
        setError(error.response?.data?.message || "Error deleting user.");
      });
  };

  const handleAddUser = () => {
    setAddUserError(null);
    const payload = {
      Username: newUser.username,
      Password: newUser.password,
      Role: newUser.role,
      Email: newUser.email,
      FirstName: newUser.firstName,
      LastName: newUser.lastName,
      SSN: newUser.ssn,
      PhoneNumber: newUser.phoneNumber,
    };

    api
      .post("/Users", payload, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((response) => {
        const updated = [...users, response.data];
        setUsers(updated);
        setFilteredUsers(updated);
        setNewUser({ ...defaultNewUser });
        setIsAddUserOpen(false);
      })
      .catch((error) => {
        setAddUserError(
          error.response?.data?.message ||
            error.response?.data?.title ||
            JSON.stringify(error.response?.data) ||
            "Failed to add user"
        );
      });
  };

  const handleCloseAddUser = () => {
    setNewUser({ ...defaultNewUser });
    setIsAddUserOpen(false);
    setAddUserError(null);
  };

  const handleAddLocation = async (location: {
    name: string;
    lat: number;
    lng: number;
  }) => {
    try {
      const newLocation = await locationService.createLocation({
        name: location.name,
        latitude: location.lat,
        longitude: location.lng,
      });
      setLocations((prev) => [...prev, newLocation]);
      setIsAddDialogOpen(false);
    } catch (error) {
      console.error("Error adding location:", error);
      setMapError("Failed to add location");
    }
  };

  const handleDeleteLocation = async (id: number) => {
    try {
      await locationService.deleteLocation(id);
      setLocations((prev) => prev.filter((loc) => loc.id !== id));
      setSelectedLocationId(null);
    } catch (error) {
      console.error("Error deleting location:", error);
      setMapError("Failed to delete location");
    }
  };

  const renderTabContent = () => {
    if (loading) {
      return (
        <div className="flex justify-center items-center py-8">
          <span className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mr-2"></span>
          <span className="text-gray-800">Loading...</span>
        </div>
      );
    }

    switch (activeTab) {
      case "users":
        return (
          <UserList
            users={filteredUsers}
            editingUser={editingUser}
            setEditingUser={setEditingUser}
            setOriginalUser={setOriginalUser}
            handleSaveUser={handleSaveUser}
            handleCancelEdit={handleCancelEdit}
            handleEditUser={handleEditUser}
            handleDeleteUser={handleDeleteUser}
          />
        );
      case "books":
        return <BookManagement containerClassName="w-full" />;
      case "req":
        return <JoinUS containerClassName="w-full" />;
      case "memberships":
        return <ManageMemberShip containerClassName="w-full" />;
      case "map":
        return (
          <div className="space-y-4">
            <div className="flex gap-4">
              <button
                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition-colors"
                onClick={() => setIsAddDialogOpen(true)}
              >
                Add Location
              </button>
              <button
                className="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                disabled={selectedLocationId === null}
                onClick={() => {
                  if (selectedLocationId !== null) {
                    handleDeleteLocation(selectedLocationId);
                  }
                }}
              >
                {selectedLocationId
                  ? `Delete Selected Location`
                  : "Select a Location to Delete"}
              </button>
            </div>
            {selectedLocationId && (
              <div className="p-4 bg-blue-100 text-blue-700 rounded-lg">
                Click on the map to deselect the current location
              </div>
            )}
            {locationPermission === "denied" && (
              <div className="p-4 bg-yellow-100 text-yellow-700 rounded-lg">
                Location access is denied. Please enable location access in your
                browser settings to see your current location on the map.
              </div>
            )}
            {mapError && (
              <div className="p-4 bg-red-100 text-red-700 rounded-lg">
                {mapError}
              </div>
            )}
            <div className="relative">
              {!isMapReady && (
                <div className="absolute inset-0 flex items-center justify-center bg-gray-100 bg-opacity-75 z-10">
                  <div className="text-gray-500">Loading map...</div>
                </div>
              )}
              <Suspense
                fallback={
                  <div className="w-full h-[70vh] rounded-lg shadow border flex items-center justify-center bg-gray-100">
                    <div className="text-gray-500">Loading map...</div>
                  </div>
                }
              >
                <MapView
                  locations={locations.map((loc) => ({
                    id: loc.id,
                    lat: loc.latitude,
                    lng: loc.longitude,
                    name: loc.name,
                  }))}
                  onMarkerClick={setSelectedLocationId}
                  selectedLocationId={selectedLocationId}
                  onMapReady={() => setIsMapReady(true)}
                />
              </Suspense>
            </div>
            <AddLocationDialog
              open={isAddDialogOpen}
              onClose={() => setIsAddDialogOpen(false)}
              onAdd={handleAddLocation}
            />
          </div>
        );
      case "logs":
        return <SystemLogger containerClassName="w-full" />;
      default:
        return null;
    }
  };

  // State for mobile sidebar
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  
  const toggleSidebar = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      {activeTab === "users" && (
        <AddUserDialog
          open={isAddUserOpen}
          newUser={newUser}
          setNewUser={setNewUser}
          onClose={handleCloseAddUser}
          onSubmit={handleAddUser}
          addUserError={addUserError}
        />
      )}
      <div className="flex flex-1 relative">
        <Sidebar
          items={sidebarItems}
          activeKey={activeTab}
          onSelect={setActiveTab}
          isMobileOpen={isSidebarOpen}
          onMobileClose={() => setIsSidebarOpen(false)}
        />
        <main className="flex-1 px-4 sm:px-6 md:px-8 lg:px-10 py-4 sm:py-6 md:py-8 w-full">
          {/* Search bar and mobile menu button */}
          <div className="w-full">
            {activeTab === "users" ? (
              <SearchBar
                onAdd={handleAddClick}
                onSearch={handleSearch}
                placeholder="Search users..."
                onToggleSidebar={toggleSidebar}
              />
            ) : (
              <div className="flex items-center mb-6 gap-2">
                <button
                  className="md:hidden w-10 h-10 flex items-center justify-center rounded-full border bg-white shadow"
                  onClick={toggleSidebar}
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-500" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M3 5a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM3 10a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM3 15a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
                  </svg>
                </button>
              </div>
            )}
          </div>

          {error && (
            <div className="mb-4 p-4 bg-red-100 text-red-700 rounded-lg text-sm">
              {error}
            </div>
          )}

          <div className="bg-white rounded-xl shadow-md border p-3 sm:p-4 md:p-6 overflow-hidden">
            <div className="flex flex-col gap-4 max-h-full overflow-y-auto">
              {renderTabContent()}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default AdminDashboard;
