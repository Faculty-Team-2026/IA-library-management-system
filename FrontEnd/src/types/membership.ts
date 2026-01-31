export interface Membership {
  membershipId: number;
  membershipType: string;
  borrowLimit: number;
  durationInDays: number;
  price?: number | undefined;
  description?: string;
  maxFamilyMembers?: number | undefined;
  requiresApproval: boolean;
  isFamilyPlan?: boolean;
}
