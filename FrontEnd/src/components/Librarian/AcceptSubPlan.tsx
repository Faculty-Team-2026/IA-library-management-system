import React, { useEffect, useState } from 'react';
import api from '../../Services/api';

interface UserMembership {
  userMembershipId: number;
  userId: number;
  membershipId: number;
  status: string;
  startDate: string;
  endDate?: string;
  isActive: boolean;
  isCanceled: boolean;
  membership: {
    membershipType: string;
    borrowLimit: number;
    durationInDays: number;
    price: number | null;
    isFamilyPlan: boolean;
  };
  user: {
    username: string;
    email: string;
    firstName: string;
    lastName: string;
  };
}

interface ApiError {
  response?: {
    data: {
      message?: string;
    };
  };
}

const AcceptSubPlan: React.FC = () => {
  const [requests, setRequests] = useState<UserMembership[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [processing, setProcessing] = useState<number | null>(null);

  useEffect(() => {
    fetchRequests();
  }, []);

  const fetchRequests = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get('/Membership/requests');
      setRequests(res.data);
    } catch (err: unknown) {
      const apiError = err as ApiError;
      setError(apiError.response?.data?.message || 'Failed to load requests. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const getUserId = (): number | null => {
    const userId = sessionStorage.getItem('userId') || localStorage.getItem('userId');
    if (!userId) return null;
    const parsedId = parseInt(userId);
    return isNaN(parsedId) ? null : parsedId;
  };

  const handleApprove = async (userMembershipId: number) => {
    const userId = getUserId();
    if (!userId) {
      setError('Authentication required. Please log in again.');
      return;
    }

    setProcessing(userMembershipId);
    setError(null);
    setSuccess(null);

    try {
      await api.put(`/Membership/approve/${userMembershipId}`, null, {
        params: { approverId: userId }
      });
      setSuccess('Subscription approved successfully. The user\'s previous plan has been canceled and the new plan is now active.');
      await fetchRequests();
    } catch (err: unknown) {
      const apiError = err as ApiError;
      setError(apiError.response?.data?.message || 'Failed to approve request. Please try again.');
    } finally {
      setProcessing(null);
    }
  };

  const handleReject = async (userMembershipId: number) => {
    const userId = getUserId();
    if (!userId) {
      setError('Authentication required. Please log in again.');
      return;
    }

    setProcessing(userMembershipId);
    setError(null);
    setSuccess(null);

    try {
      await api.put(`/Membership/reject/${userMembershipId}`, null, {
        params: { approverId: userId }
      });
      setSuccess('Subscription request rejected. The user\'s current plan remains active.');
      await fetchRequests();
    } catch (err: unknown) {
      const apiError = err as ApiError;
      setError(apiError.response?.data?.message || 'Failed to reject request. Please try again.');
    } finally {
      setProcessing(null);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  return (
    <div className="bg-white p-6 rounded-xl shadow-lg">
      <h2 className="text-2xl font-bold mb-6 text-gray-900">Membership Requests</h2>
      {error && (
        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-600">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg text-green-600">
          {success}
        </div>
      )}
      {loading ? (
        <div className="flex justify-center items-center h-24">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : requests.length === 0 ? (
        <div className="text-center text-gray-500 py-8">No pending requests</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-2 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                <th className="hidden sm:table-cell px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Plan</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                <th className="hidden sm:table-cell px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Request Date</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {requests.map(req => (
                <tr key={req.userMembershipId} className="hover:bg-gray-50 transition-colors duration-150">
                  <td className="px-2 sm:px-6 py-4">
                    <div className="text-sm font-medium text-gray-900">{req.user.firstName} {req.user.lastName}</div>
                    <div className="text-xs sm:text-sm text-gray-500">{req.user.email}</div>
                    <div className="sm:hidden text-xs text-gray-500 mt-1">
                      {req.membership.membershipType} - {formatDate(req.startDate)}
                    </div>
                  </td>
                  <td className="hidden sm:table-cell px-6 py-4">
                    <div className="text-sm text-gray-900">{req.membership.membershipType}</div>
                    <div className="text-sm text-gray-500">
                      {req.membership.isFamilyPlan ? 'Family Plan' : 'Individual Plan'}
                    </div>
                  </td>
                  <td className="hidden md:table-cell px-6 py-4">
                    <div className="text-sm text-gray-900">
                      Borrow Limit: {req.membership.borrowLimit}
                    </div>
                    <div className="text-sm text-gray-500">
                      Duration: {req.membership.durationInDays} days
                      {req.membership.price && ` • $${req.membership.price}`}
                    </div>
                  </td>
                  <td className="hidden sm:table-cell px-6 py-4">
                    <div className="text-sm text-gray-500">
                      {formatDate(req.startDate)}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex flex-col sm:flex-row gap-2 justify-end">
                      <button
                        onClick={() => handleApprove(req.userMembershipId)}
                        disabled={processing === req.userMembershipId || req.status !== 'Pending'}
                        className="inline-flex items-center justify-center px-4 py-2 text-sm font-medium text-white bg-green-600 rounded-lg hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                      >
                        {processing === req.userMembershipId ? (
                          <>
                            <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Processing...
                          </>
                        ) : 'Approve'}
                      </button>
                      <button
                        onClick={() => handleReject(req.userMembershipId)}
                        disabled={processing === req.userMembershipId || req.status !== 'Pending'}
                        className="inline-flex items-center justify-center px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                      >
                        {processing === req.userMembershipId ? (
                          <>
                            <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Processing...
                          </>
                        ) : 'Reject'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default AcceptSubPlan;
