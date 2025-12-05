import { Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import api from '../Services/api';
import { Membership } from '../types/membership';

// Types
interface PlanStyle {
    gradient: string;
    text: string;
}

// Constants
const PLAN_STYLES: PlanStyle[] = [
    { gradient: 'from-slate-800 to-blue-600', text: 'text-blue-600' },
    { gradient: 'from-slate-800 to-purple-600', text: 'text-purple-600' },
    { gradient: 'from-slate-800 to-emerald-600', text: 'text-emerald-600' },
    { gradient: 'from-slate-800 to-rose-600', text: 'text-rose-600' },
    { gradient: 'from-slate-800 to-amber-600', text: 'text-amber-600' },
    { gradient: 'from-slate-800 to-indigo-600', text: 'text-indigo-600' },
    { gradient: 'from-slate-800 to-cyan-600', text: 'text-cyan-600' },
    { gradient: 'from-slate-800 to-fuchsia-600', text: 'text-fuchsia-600' },
    { gradient: 'from-slate-800 to-violet-600', text: 'text-violet-600' },
    { gradient: 'from-slate-800 to-teal-600', text: 'text-teal-600' }
];

// Components
const LoadingSpinner = () => (
    <div className="w-full min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
    </div>
);

const ErrorMessage = ({ message }: { message: string }) => (
    <div className="w-full min-h-screen flex items-center justify-center">
        <div className="text-red-600 text-xl">{message}</div>
    </div>
);

const PlanCard = ({ plan, style }: { plan: Membership; style: PlanStyle }) => {
    const annualPrice = plan.price ? Math.round(plan.price * 12) : 'Contact';
    const monthlyPrice = plan.price ?? 'Contact';

    return (
        <div className={`bg-gradient-to-br ${style.gradient} rounded-2xl shadow-lg overflow-hidden text-white transform hover:scale-105 transition-all flex flex-col min-h-[700px]`}>
            <div className="p-8 flex-grow">
                <div>
                    <h3 className="text-2xl font-bold mb-2">{plan.membershipType}</h3>
                    <p className="text-gray-100 mb-6 h-12">
                        {plan.isFamilyPlan ? 'Read Together, Grow Together!' : 'For Passionate Readers!'}
                    </p>
                    <div className="flex items-baseline mb-8">
                        <span className="text-5xl font-bold">{monthlyPrice}</span>
                        {plan.price && <span className="ml-2">EGP</span>}
                    </div>
                </div>
                <div className="border-t border-white/20 pt-6">
                    <div className="text-gray-100 mb-4">
                        <p className="mb-4">
                            {plan.isFamilyPlan 
                                ? `This plan includes all Premium benefits for up to ${plan.maxFamilyMembers} family members`
                                : `You can borrow up to ${plan.borrowLimit} books per month`}
                        </p>
                    </div>
                    <ul className="space-y-2 mb-6">
                        <li>• {plan.borrowLimit} books per month</li>
                        <li>• {plan.durationInDays} days duration</li>
                        {plan.isFamilyPlan && (
                            <>
                                <li>• access to kids programs</li>
                                <li>• early access to children's events</li>
                                <li>• enjoy the library experience as a family</li>
                            </>
                        )}
                        {plan.description && <li>• {plan.description}</li>}
                    </ul>
                </div>
                <div className="mt-4">
                    {plan.price !== 0 && (
                        <div className="flex items-baseline mb-4">
                            <span className="text-2xl font-bold">{annualPrice}</span>
                            {plan.price && (
                                <>
                                    <span className="ml-2">EGP</span>
                                    <span className="ml-2">Annual</span>
                                </>
                            )}
                        </div>
                    )}
                </div>
            </div>
            <div className="p-8 pt-0">
                <Link
                    to="/auth/user/:id"
                    className={`block w-full text-center px-6 py-3 bg-white ${style.text} rounded-lg hover:bg-gray-100 transition-colors font-medium`}
                >
                    Select Plan
                </Link>
            </div>
        </div>
    );
};

export const Services = () => {
    const [plans, setPlans] = useState<Membership[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchPlans = async () => {
            try {
                const response = await api.get('/Membership');
                // Sort plans: free trial (price = 0) first, then by price, undefined prices last
                const sortedPlans = response.data.sort((a: Membership, b: Membership) => {
                    // Handle free trial (price = 0)
                    if (a.price === 0) return -1;
                    if (b.price === 0) return 1;
                    // Handle undefined prices
                    if (!a.price) return 1;
                    if (!b.price) return -1;
                    // Sort by price
                    return a.price - b.price;
                });
                setPlans(sortedPlans);
            } catch (err) {
                setError('Failed to load membership plans');
                console.error('Error fetching plans:', err);
            } finally {
                setLoading(false);
            }
        };

        fetchPlans();
    }, []);

    if (loading) return <LoadingSpinner />;
    if (error) return <ErrorMessage message={error} />;

    return (
        <div className="w-full min-h-screen px-4 sm:px-6 lg:px-8 py-20 bg-gray-50">
            <div className="max-w-7xl mx-auto">
                <div className="text-center mb-16">
                    <h1 className="text-4xl md:text-5xl font-bold text-slate-800 mb-4">
                        Unlock Your Reading Journey!
                    </h1>
                    <h2 className="text-3xl md:text-4xl text-slate-700">
                        Membership Plans
                    </h2>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                    {plans.map((plan, index) => (
                        <PlanCard
                            key={plan.membershipType}
                            plan={plan}
                            style={PLAN_STYLES[index % PLAN_STYLES.length]}
                        />
                    ))}
                </div>
            </div>
        </div>
    );
}; 