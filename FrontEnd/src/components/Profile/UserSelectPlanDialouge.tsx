import React, { useEffect, useState } from 'react';
import api from '../../Services/api';

interface UserMembership {
  userMembershipId: number;
  userId: number;
  membershipId: number;
  startDate: string;
  endDate: string | null;
  isCanceled: boolean;
  isActive: boolean;
  parentUserId: number | null;
  status: string;
  membership: Membership;
}

interface Membership {
  membershipId: number;
  membershipType: string;
  borrowLimit: number;
  durationInDays: number;
  price: number | null;
  description?: string;
  isFamilyPlan: boolean;
  maxFamilyMembers?: number;
  createdAt: string;
}

interface ApiError {
  response?: {
    status?: number;
    data: {
      message?: string;
    };
  };
}

const UserSelectPlanDialouge: React.FC<{ onRequestSent?: () => void }> = ({ onRequestSent }) => {
  const [plans, setPlans] = useState<Membership[]>([]);
  const [selectedPlan, setSelectedPlan] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [currentMembership, setCurrentMembership] = useState<UserMembership | null>(null);
  const [showPlanSelection, setShowPlanSelection] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        // Fetch plans first
        const plansRes = await api.get<Membership[]>('/Membership');
        console.log('Available plans:', plansRes.data);
        setPlans(plansRes.data);

        // Then try to fetch current membership
        const userId = localStorage.getItem('userId');
        if (userId) {
          try {
            const membershipRes = await api.get<UserMembership>(`/Membership/user/${userId}`);
            console.log('Current membership:', membershipRes.data);
            if (membershipRes.data) {
              setCurrentMembership(membershipRes.data);
              setShowPlanSelection(false);
            } else {
              setCurrentMembership(null);
              setShowPlanSelection(true);
            }
          } catch (membershipErr: unknown) {
            const apiError = membershipErr as ApiError;
            if (apiError.response?.status === 404) {
              // User doesn't have a membership yet - show plan selection
              setCurrentMembership(null);
              setShowPlanSelection(true);
            } else {
              console.error('Error fetching membership:', membershipErr);
              setError('Failed to fetch current membership');
            }
          }
        } else {
          setError('User not logged in');
        }
      } catch (err: unknown) {
        const apiError = err as ApiError;
        console.error('Error in fetchData:', err);
        setError(apiError.response?.data?.message || 'Failed to load data');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleSubmit = async () => {
    if (!selectedPlan) {
      setError('Please select a plan');
      return;
    }
    setSubmitting(true);
    setError(null);
    setSuccess(null);
    try {
      // Get userId from localStorage
      const userId = localStorage.getItem('userId');

      if (!userId) {
        setError('User not logged in');
        setSubmitting(false);
        return;
      }

      const selectedPlanData = plans.find(p => p.membershipId === selectedPlan);
      if (!selectedPlanData) {
        setError('Selected plan not found');
        setSubmitting(false);
        return;
      }

      // Only send the required data for the request
      const requestData = {
        userId: parseInt(userId),
        membershipId: selectedPlan,
        membershipType: selectedPlanData.membershipType,
        borrowLimit: selectedPlanData.borrowLimit,
        durationInDays: selectedPlanData.durationInDays,
        price: selectedPlanData.price,
        description: selectedPlanData.description,
        isFamilyPlan: selectedPlanData.isFamilyPlan,
        maxFamilyMembers: selectedPlanData.maxFamilyMembers,
        parentUserId: selectedPlanData.isFamilyPlan ? parseInt(userId) : null
      };

      await api.post('/Membership/request', requestData);
      setSuccess('Request sent to librarian for approval. Your current plan will remain active until the new plan is approved.');
      if (onRequestSent) onRequestSent();
    } catch (err: unknown) {
      const apiError = err as ApiError;
      setError(apiError.response?.data?.message || 'Failed to send request');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-white p-6 rounded-xl shadow-lg max-w-lg mx-auto">
        <div className="flex justify-center items-center h-24">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-white p-6 rounded-xl shadow-lg max-w-lg mx-auto">
        <div className="text-red-600 mb-2">{error}</div>
      </div>
    );
  }

  if (!showPlanSelection && currentMembership) {
    console.log('Rendering current membership:', currentMembership);
    return (
      <div className="bg-white p-4 sm:p-6 rounded-xl shadow-lg max-w-lg mx-auto">
        <h2 className="text-xl font-semibold mb-4 text-gray-900">Current Membership Plan</h2>
        <div className="border rounded-lg p-4 mb-4 hover:shadow-md transition-shadow">
          <div className="flex justify-between items-start mb-2">
            <div className="font-bold text-xl text-gray-900">{currentMembership.membership.membershipType}</div>
            <div className="text-lg font-semibold text-blue-600">
              {currentMembership.membership.price ? `$${currentMembership.membership.price}` : 'Free'}
            </div>
          </div>
          {currentMembership.membership.description && (
            <div className="text-gray-800 text-sm mt-2">{currentMembership.membership.description}</div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
            <div className="text-gray-800">
              <span className="font-semibold">Borrow Limit:</span> {currentMembership.membership.borrowLimit}
            </div>
            <div className="text-gray-800">
              <span className="font-semibold">Duration:</span> {currentMembership.membership.durationInDays} days
            </div>
            <div className="text-gray-800">
              <span className="font-semibold">Status:</span> <span className={
                currentMembership.status === 'Approved' ? 'text-green-600' : 
                currentMembership.status === 'Pending' ? 'text-amber-600' : 
                'text-red-600'
              }>{currentMembership.status}</span>
            </div>
            {currentMembership.startDate && (
              <div className="text-gray-800">
                <span className="font-semibold">Start Date:</span> {new Date(currentMembership.startDate).toLocaleDateString()}
              </div>
            )}
            {currentMembership.endDate && (
              <div className="text-gray-800">
                <span className="font-semibold">End Date:</span> {new Date(currentMembership.endDate).toLocaleDateString()}
              </div>
            )}            {currentMembership.membership.isFamilyPlan && (
              <div className="text-gray-800 col-span-full">
                <span className="font-semibold">Family Plan:</span> Up to {currentMembership.membership.maxFamilyMembers} members
              </div>
            )}
          </div>
        </div>
        {currentMembership.status !== 'Pending' && (
          <button
            onClick={() => setShowPlanSelection(true)}
            className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Change Plan
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="bg-white p-4 sm:p-6 rounded-xl shadow-lg max-w-lg mx-auto">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold text-gray-900">Select a Membership Plan</h2>
        {currentMembership && (
          <button
            onClick={() => setShowPlanSelection(false)}
            className="text-blue-600 hover:text-blue-800 font-medium"
          >
            Back to Current Plan
          </button>
        )}
      </div>
      {loading ? (
        <div className="flex justify-center items-center h-24">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : error ? (
        <div className="text-red-600 mb-2">{error}</div>
      ) : (
        <>
          <ul className="space-y-3 mb-4">
            {plans.map(plan => (
              <li 
                key={plan.membershipId} 
                className={`border rounded-lg p-4 cursor-pointer hover:shadow-md transition-all ${
                  selectedPlan === plan.membershipId ? 'border-blue-500 bg-blue-50' : 'border-gray-200'
                }`} 
                onClick={() => setSelectedPlan(plan.membershipId)}
              >
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center">
                  <div className="w-full">
                    <div className="flex justify-between items-center mb-2">
                      <div className="font-bold text-lg text-gray-900">{plan.membershipType}</div>
                      <div className="text-blue-600 font-bold text-lg">
                        {plan.price ? `$${plan.price}` : 'Free'}
                      </div>
                    </div>
                    <div className="text-gray-800 text-sm mb-2">{plan.description}</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                      <div className="text-gray-800">
                        <span className="font-semibold">Borrow Limit:</span> {plan.borrowLimit}
                      </div>
                      <div className="text-gray-800">
                        <span className="font-semibold">Duration:</span> {plan.durationInDays} days
                      </div>
                      {plan.isFamilyPlan && (
                        <div className="text-gray-800 col-span-full">
                          <span className="font-semibold">Family Plan:</span> Up to {plan.maxFamilyMembers} members
                        </div>
                      )}
                    </div>
                  </div>
                  {selectedPlan === plan.membershipId && (
                    <div className="mt-2 sm:mt-0 sm:ml-4">
                      <span className="text-blue-600 font-bold whitespace-nowrap">✓ Selected</span>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
          >
            {submitting ? 'Sending Request...' : 'Send Request'}
          </button>
          {success && <div className="text-green-600 mt-2 font-medium">{success}</div>}
          {error && <div className="text-red-600 mt-2 font-medium">{error}</div>}
        </>
      )}
    </div>
  );
};

export default UserSelectPlanDialouge;
