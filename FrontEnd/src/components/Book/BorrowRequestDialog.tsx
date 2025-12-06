import React, { useState } from 'react';
import api from '../../Services/api';

interface BorrowRequestDialogProps {
    bookId: number;
    bookTitle: string;
    isOpen: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

interface ApiError {
    response?: {
        data: {
            message?: string;
        };
    };
}

const BorrowRequestDialog: React.FC<BorrowRequestDialogProps> = ({
    bookId,
    bookTitle,
    isOpen,
    onClose,
    onSuccess
}) => {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleRequest = async () => {
        try {
            setLoading(true);
            setError(null);
            await api.post(`/Borrow/request/${bookId}`);
            onSuccess();
            onClose();
        } catch (err: unknown) {
            const apiError = err as ApiError;
            setError(apiError.response?.data?.message || 'Failed to submit borrow request. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded-xl shadow-xl max-w-md w-full p-6 transform transition-all">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-xl font-semibold text-gray-900">Borrow Request</h3>
                    <button
                        onClick={onClose}
                        className="text-gray-400 hover:text-gray-500 focus:outline-none"
                    >
                        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <div className="mb-6">
                    <p className="text-gray-600 mb-2">
                        You are requesting to borrow:
                    </p>
                    <p className="text-lg font-medium text-gray-900">
                        {bookTitle}
                    </p>
                </div>

                {error && (
                    <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-800 flex items-center">
                        <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        {error}
                    </div>
                )}

                <div className="flex justify-end space-x-3">
                    <button
                        onClick={onClose}
                        disabled={loading}
                        className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-all duration-200 transform hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleRequest}
                        disabled={loading}
                        className="px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-700 hover:to-blue-800 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-all duration-200 transform hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {loading ? (
                            <div className="flex items-center">
                                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                                Submitting...
                            </div>
                        ) : (
                            'Request to Borrow'
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default BorrowRequestDialog;
