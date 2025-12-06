import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../Services/api';
import ProfileForm from '../components/Profile/ProfileForm';
import BorrowHistorySection from '../components/Profile/BorrowHistorySection';
import LibrarianRequestSection from '../components/Profile/LibrarianRequestSection';
import UserAvatar from '../components/Profile/UserAvatar';
import UserSelectPlanDialouge from '../components/Profile/UserSelectPlanDialouge';

interface User {
    id: number;
    username: string;
    email: string;
    role: string;
    firstName: string;
    lastName: string;
    phoneNumber: string;
    ssn: string;
    createdAt: string;
}

interface BorrowHistory {
    id: number;
    bookTitle: string;
    bookAuthor: string;
    borrowDate: string;
    dueDate: string;
    status: string;
    returnDate: string | null;
}

interface ApiError {
    response?: {
        data: {
            message?: string;
            errors?: Record<string, string[]>;
        };
        status: number;
    };
    message?: string;
}

const UserProfile: React.FC = () => {
    const navigate = useNavigate();
    const [user, setUser] = useState<User | null>(null);
    const [isEditing, setIsEditing] = useState(false);
    const [editedUser, setEditedUser] = useState<Partial<User>>({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [borrowHistory, setBorrowHistory] = useState<BorrowHistory[]>([]);
    

    useEffect(() => {
        const fetchUserData = async () => {
            try {
                const token = localStorage.getItem('token');
                if (!token) {
                    navigate('/auth/login');
                    return;
                }
                

                const response = await api.get('/Users/profile');
                if (!response.data) {
                    throw new Error('No user data received');
                }

                setUser(response.data);
                setEditedUser(response.data);
                
                
                try {
                    const historyResponse = await api.get('/Borrow/my-records');
                    console.log('Borrow history response:', historyResponse.data);
                    setBorrowHistory(historyResponse.data);
                } catch (err) {
                    console.error('Error fetching borrow history:', err);
                    setBorrowHistory([]);
                }
            } catch (err: unknown) {
                console.error('Error fetching user data:', err);
                const apiError = err as ApiError;
                if (apiError.response) {
                    setError(apiError.response.data.message || 'Failed to load user data. Please try again later.');
                } else {
                    setError('Failed to load user data. Please try again later.');
                }
            } finally {
                setLoading(false);
            }
        };

        fetchUserData();
    }, [navigate]);

    const handleEdit = () => {
        setEditedUser({
            firstName: user?.firstName || '',
            lastName: user?.lastName || '',
            username: user?.username || '',
            email: user?.email || '',
            phoneNumber: user?.phoneNumber || ''
        });
        setIsEditing(true);
    };

    const handleSave = async () => {
        try {
            if (!user) {
                setError('User data not found');
                return;
            }
            

            const updateData = {
                Username: editedUser.username?.trim(),
                Email: editedUser.email?.trim(),
                FirstName: editedUser.firstName?.trim(),
                LastName: editedUser.lastName?.trim(),
                PhoneNumber: editedUser.phoneNumber?.trim() || null,
                Role: user.role
            };

            console.log('Update data being sent:', updateData);

            if (!updateData.Username || !updateData.Email || !updateData.FirstName || !updateData.LastName) {
                setError('Please fill in all required fields');
                return;
            }

            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(updateData.Email)) {
                setError('Please enter a valid email address');
                return;
            }

            const response = await api.put(`/Users/${user.id}`, updateData);
            setUser(response.data);
            setIsEditing(false);
            setError(null);
        } catch (error: unknown) {
            console.error('Error updating user:', error);
            const apiError = error as ApiError;
            console.log('API Error Response:', apiError.response?.data);
            if (apiError.response?.data.errors) {
                const errorMessages = Object.values(apiError.response.data.errors).flat();
                setError(errorMessages.join(', '));
            } else {
                setError(apiError.response?.data.message || 'Failed to update user data. Please try again later.');
            }
        }
    };

    const handleCancel = () => {
        setEditedUser({});
        setIsEditing(false);
    };

    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        setEditedUser(prev => ({
            ...prev,
            [name]: value
        }));
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
            </div>
        );
    }

    if (error || !user) {
        return (
            <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <div className="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
                    <div className="text-red-500 text-center">{error || 'User not found'}</div>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-gray-50 flex flex-col w-full">
            <div className="flex-1 w-full flex flex-col px-4 md:px-12 xl:px-32 py-8">
                <div className="flex-1 flex flex-col xl:flex-row gap-8 min-h-0 w-full">
                    {/* Left Column - Profile Info */}
                    <div className="w-full xl:w-2/5 animate-fadeIn flex flex-col">
                        <div className="bg-white rounded-2xl shadow-lg hover:shadow-2xl transition-all duration-300 overflow-hidden flex-1 flex flex-col">
                            {/* Top gradient banner */}
                            <div className="h-32 bg-gradient-to-r from-blue-600 to-blue-400"></div>
                            <div className="-mt-16 px-8 pb-8 flex-1 flex flex-col">
                                <UserAvatar 
                                    firstName={user.firstName}
                                    lastName={user.lastName}
                                    role={user.role}
                                />
                                <div className="mt-6 flex-1 flex flex-col">
                                    <ProfileForm
                                        user={user}
                                        isEditing={isEditing}
                                        editedUser={editedUser}
                                        onInputChange={handleInputChange}
                                        onSave={handleSave}
                                        onCancel={handleCancel}
                                        onEdit={handleEdit}
                                    />
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Right Column - Borrow History and Plan Selection */}
                    <div className="w-full xl:w-3/5 animate-fadeIn animation-delay-150 flex flex-col gap-8">
                        {/* Borrow History only for users */}
                        {user.role === 'User' && (
                            <div className="h-full bg-white rounded-2xl shadow-lg hover:shadow-blue-300 transition-all duration-300 p-6 flex-1 flex flex-col border border-blue-200">
                                <h2 className="text-xl font-bold text-blue-800 mb-4">Borrow History</h2>
                                <BorrowHistorySection 
                                    borrowHistory={borrowHistory}
                                    isLoading={loading}
                                />
                            </div>
                        )}
                        {/* Membership Plan Selection under Borrow History - Only for users */}
                        {user.role === 'User' && (
                            <div className="bg-gradient-to-r from-blue-100 via-white to-blue-50 rounded-2xl shadow-lg hover:shadow-blue-300 transition-all duration-300 p-6 flex flex-col border border-blue-200">
                                <h2 className="text-xl font-bold text-blue-800 mb-4">Select Membership Plan</h2>
                                <UserSelectPlanDialouge />
                            </div>
                        )}
                    </div>
                </div>
                {/* Bottom Section - Librarian Request */}
                <div className="mt-8 animate-fadeIn animation-delay-300 w-full">
                    <div className="bg-white rounded-2xl shadow-lg hover:shadow-2xl transition-all duration-300 p-6 w-full">
                        <LibrarianRequestSection userRole={user.role} />
                    </div>
                </div>
            </div>

            {/* Loading State */}
            {loading && (
                <div className="fixed inset-0 bg-white bg-opacity-75 flex items-center justify-center z-50">
                    <div className="text-center">
                        <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-600"></div>
                        <p className="mt-4 text-gray-600 font-medium">Loading your profile...</p>
                    </div>
                </div>
            )}

            {/* Error State */}                    {error && (
                <div className="fixed bottom-4 right-4 bg-white rounded-lg shadow-xl p-4 animate-slideIn max-w-md">
                    <div className="flex items-center text-red-600">
                        <svg className="w-5 h-5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <p className="text-sm">{error}</p>
                    </div>
                </div>
            )}
        </div>
    );
};

export default UserProfile;