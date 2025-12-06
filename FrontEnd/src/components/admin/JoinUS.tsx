import { useEffect, useState } from 'react';
import api from '../../Services/api';

interface LibrarianRequest {
    id: number;
    userId: number;
    username: string;
    requestDate: string;
    requestMessage: string;
    status: string;
}

interface JoinUSProps {
  containerClassName?: string;
}
interface ApiError {
    response?: {
        data: {
            message?: string;
        };
    };
}

const JoinUS = ({ containerClassName = "" }: JoinUSProps) => {
    const [requests, setRequests] = useState<LibrarianRequest[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [success, setSuccess] = useState<string | null>(null);
    const [processingId, setProcessingId] = useState<number | null>(null);

    useEffect(() => {
        fetchRequests();
    }, []);

    const fetchRequests = async () => {
        try {
            setLoading(true);
            setError(null);
            const res = await api.get('/Librarian/requests?status=Pending');
            setRequests(res.data);
            console.log(res.data);
        } catch (err: unknown) {
            const apiError = err as ApiError;
            setError(apiError.response?.data?.message || 'Failed to fetch librarian requests');
        } finally {
            setLoading(false);
        }
    };

    const handleApprove = async (requestId: number) => {
        try {
            setProcessingId(requestId);
            setError(null);
            await api.post(`/Librarian/approve/${requestId}`);
            setRequests(prev => prev.filter(r => r.id !== requestId));
            setSuccess('Request approved successfully');
            setTimeout(() => setSuccess(null), 3000);
        } catch (err: unknown) {
            const apiError = err as ApiError;
            setError(apiError.response?.data?.message || 'Failed to approve request');
        } finally {
            setProcessingId(null);
        }
    };

    const handleReject = async (requestId: number) => {
        try {
            setProcessingId(requestId);
            setError(null);
            await api.post(`/Librarian/reject/${requestId}`);
            setRequests(prev => prev.filter(r => r.id !== requestId));
            setSuccess('Request rejected successfully');
            setTimeout(() => setSuccess(null), 3000);
        } catch (err: unknown) {
            const apiError = err as ApiError;
            setError(apiError.response?.data?.message || 'Failed to reject request');
        } finally {
            setProcessingId(null);
        }
    };    return (
        <div className={`w-full h-full ${containerClassName}`}>
            <div className="flex flex-col w-full h-full overflow-hidden">
                {/* Title and refresh button */}
                <div className="flex justify-between items-center mb-2">
                    <h2 className="text-xl font-semibold text-gray-800">Librarian Registration Requests</h2>
                    <button 
                        onClick={fetchRequests}
                        className="text-sm text-blue-600 bg-white hover:bg-blue-50 flex items-center px-3 py-1.5 rounded-lg border border-gray-200 shadow-sm transition-all duration-200"
                    >
                        <svg className="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                        Refresh List
                    </button>
                </div>

                {/* Notifications */}
                <div className="space-y-2">
                    {error && (
                        <div className="p-2 bg-red-50 border border-red-200 rounded-lg text-red-800 flex items-center shadow-sm animate-fadeIn text-sm">
                            <svg className="w-4 h-4 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" 
                                    d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            {error}
                        </div>
                    )}

                    {success && (
                        <div className="p-2 bg-green-50 border border-green-200 rounded-lg text-green-800 flex items-center shadow-sm animate-fadeIn text-sm">
                            <svg className="w-4 h-4 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                            </svg>
                            {success}
                        </div>
                    )}
                </div>

                {/* Content */}
                <div className="flex-grow bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden mt-2 h-[calc(100%-60px)]">
                    <div className="h-full overflow-hidden">
                    {loading ? (
                        <div className="flex flex-col items-center justify-center min-h-[400px]">
                            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                            <p className="mt-4 text-gray-500 text-sm">Loading requests...</p>
                        </div>
                    ) : requests.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-12">
                            <div className="text-center">
                                <svg className="w-14 h-14 text-gray-300 mx-auto mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                                </svg>
                                <h3 className="text-xl font-semibold text-gray-800">No pending requests</h3>
                                <p className="mt-1 text-gray-500 text-center">
                                    There are currently no pending librarian registration<br />requests to review.
                                </p>
                            </div>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead>
                                    <tr className="bg-gray-50">
                                        <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                                            Username
                                        </th>
                                        <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                                            Request Date
                                        </th>
                                        <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                                            Message
                                        </th>
                                        <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                                            Actions
                                        </th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {requests.map((request) => (
                                        <tr key={request.id} className="hover:bg-gray-50 transition-colors duration-150">
                                            <td className="px-6 py-4">
                                                <div className="flex items-center">
                                                    <div className="h-10 w-10 rounded-xl bg-blue-100 flex items-center justify-center">
                                                        <span className="text-sm font-semibold text-blue-600">
                                                            {request.username[0].toUpperCase()}
                                                        </span>
                                                    </div>
                                                    <div className="ml-4">
                                                        <div className="text-sm font-medium text-gray-900">{request.username}</div>
                                                        <div className="text-xs text-gray-500">ID: {request.userId}</div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="text-sm text-gray-900">
                                                    {new Date(request.requestDate).toLocaleDateString(undefined, {
                                                        year: 'numeric',
                                                        month: 'long',
                                                        day: 'numeric'
                                                    })}
                                                </div>
                                                <div className="text-xs text-gray-500">
                                                    {new Date(request.requestDate).toLocaleTimeString()}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="max-w-lg">
                                                    <div className="group relative">
                                                        <p className="text-sm text-gray-900 line-clamp-2 cursor-pointer hover:text-blue-600 transition-colors">
                                                            {request.requestMessage}
                                                        </p>
                                                        <div className="absolute left-0 top-full mt-2 w-96 p-4 bg-white rounded-lg shadow-lg border border-gray-200 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                                                            <div className="flex flex-col">
                                                                <h4 className="text-sm font-semibold text-gray-700 mb-2">Request Message:</h4>
                                                                <p className="text-sm text-black whitespace-pre-wrap bg-gray-50 p-3 rounded border border-gray-100">
                                                                    {request.requestMessage}
                                                                </p>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex gap-3">
                                                    <button
                                                        onClick={() => handleApprove(request.id)}
                                                        disabled={processingId === request.id}
                                                        className={`inline-flex items-center px-4 py-2 rounded-lg text-sm font-medium shadow-sm transition-all duration-200
                                                            ${processingId === request.id
                                                                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                                                                : 'bg-green-50 text-green-700 hover:bg-green-100 hover:text-green-800 hover:shadow'
                                                            }`}
                                                    >
                                                        {processingId === request.id ? (
                                                            <span className="flex items-center">
                                                                <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                                </svg>
                                                                Processing...
                                                            </span>
                                                        ) : (
                                                            <>
                                                                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                                                                </svg>
                                                                Approve
                                                            </>
                                                        )}
                                                    </button>
                                                    <button
                                                        onClick={() => handleReject(request.id)}
                                                        disabled={processingId === request.id}
                                                        className={`inline-flex items-center px-4 py-2 rounded-lg text-sm font-medium shadow-sm transition-all duration-200
                                                            ${processingId === request.id
                                                                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                                                                : 'bg-red-50 text-red-700 hover:bg-red-100 hover:text-red-800 hover:shadow'
                                                            }`}
                                                    >
                                                        {processingId === request.id ? (
                                                            <span className="flex items-center">
                                                                <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                                </svg>
                                                                Processing...
                                                            </span>
                                                        ) : (
                                                            <>
                                                                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                                                                </svg>
                                                                Reject
                                                            </>
                                                        )}
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
                </div>
            </div>
        </div>
    );
};

export default JoinUS;
