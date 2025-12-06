import { useState, useEffect } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faEdit } from "@fortawesome/free-solid-svg-icons";
import { Membership } from "../../types/membership";
import api from "../../Services/api";
import MemberShipDialog from "./AddMemberShipDialog";
import EditMemberShipDialog from "./EditMemberShipDialog";
import DeleteMemberShip from "./DeleteMemberShip";

interface ManageMemberShipProps {
  containerClassName?: string;
}

const ManageMemberShip: React.FC<ManageMemberShipProps> = ({
  containerClassName = "",
}) => {
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [memberships, setMemberships] = useState<Membership[]>([]);
  const [editingMembership, setEditingMembership] = useState<Membership | null>(
    null
  );
  const [membershipError, setMembershipError] = useState<string | null>(null);

  // Fetch memberships
  useEffect(() => {
    const fetchMemberships = async () => {
      try {
        const response = await api.get("/Membership");
        setMemberships(response.data);
      } catch (err) {
        setMembershipError("Failed to load memberships");
        console.error("Error fetching memberships:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchMemberships();
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center items-center py-8">
        <span className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mr-2"></span>
        <span className="text-gray-800">Loading...</span>
      </div>
    );
  }

  return (
    <div className={containerClassName}>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-gray-800">Membership Plans</h2>
        <button
          onClick={() => setIsDialogOpen(true)}
          className="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors"
        >
          Add New Plan
        </button>
      </div>
      {membershipError && (
        <div className="text-red-600 text-center text-sm mb-4">
          {membershipError}
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {memberships.map((membership) => (
          <div
            key={membership.membershipId}
            className="bg-white p-6 rounded-lg shadow-md relative"
          >
            <div className="absolute top-4 right-4 flex gap-2">
              <button
                onClick={() => {
                  setEditingMembership(membership);
                  setIsEditDialogOpen(true);
                }}
                className="text-green-500 bg-transparent hover:text-green-600"
              >
                <FontAwesomeIcon icon={faEdit} />
              </button>
              <DeleteMemberShip
                membership={membership}
                onDelete={async () => {
                  try {
                    await api.delete(
                      `/Membership/${membership.membershipId}`
                    );
                    setMemberships(
                      memberships.filter(
                        (m) => m.membershipId !== membership.membershipId
                      )
                    );
                  } catch (err) {
                    setMembershipError("Failed to delete membership");
                    console.error("Error deleting membership:", err);
                  }
                }}
                className="text-red-600 bg-transparent hover:text-red-800"
              />
            </div>
            <h3 className="text-xl font-semibold text-gray-800 mb-2 pr-16">
              {membership.membershipType}
            </h3>
            <div className="space-y-2 text-gray-600">
              <p>Borrow Limit: {membership.borrowLimit}</p>
              <p>Duration: {membership.durationInDays} days</p>
              {membership.price && <p>Price: {membership.price} EGP</p>}
              {membership.description && (
                <p>Description: {membership.description}</p>
              )}
              <p>Family Plan: {membership.isFamilyPlan ? "Yes" : "No"}</p>
              {membership.isFamilyPlan && membership.maxFamilyMembers && (
                <p>Max Family Members: {membership.maxFamilyMembers}</p>
              )}
              <p>
                Requires Approval: {membership.requiresApproval ? "Yes" : "No"}
              </p>
            </div>
          </div>
        ))}
      </div>
      <MemberShipDialog
        open={isDialogOpen}
        onClose={() => setIsDialogOpen(false)}
        onAdd={async (newMembership: Membership) => {
          try {
            const response = await api.post("/Membership", newMembership);
            setMemberships([...memberships, response.data]);
            setIsDialogOpen(false);
          } catch (err) {
            setMembershipError("Failed to add membership");
            console.error("Error adding membership:", err);
          }
        }}
        addMembershipError={membershipError}
      />
      {editingMembership && (
        <EditMemberShipDialog
          open={isEditDialogOpen}
          membership={editingMembership}
          onClose={() => {
            setIsEditDialogOpen(false);
            setEditingMembership(null);
          }}
          onEdit={async (updatedMembership: Membership) => {
            try {
              const response = await api.put(
                `/Membership/${updatedMembership.membershipId}`,
                updatedMembership
              );
              setMemberships(
                memberships.map((m) =>
                  m.membershipId === updatedMembership.membershipId
                    ? response.data
                    : m
                )
              );
              setIsEditDialogOpen(false);
              setEditingMembership(null);
            } catch (err) {
              setMembershipError("Failed to update membership");
              console.error("Error updating membership:", err);
            }
          }}
          editError={membershipError}
        />
      )}
    </div>
  );
};

export default ManageMemberShip;
