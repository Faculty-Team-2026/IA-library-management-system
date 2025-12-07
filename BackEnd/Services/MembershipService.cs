using BackEnd.Data;
using BackEnd.DTOs;
using BackEnd.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace BackEnd.Services
{
    public class MembershipService : IMembershipService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly ILogger<MembershipService> _logger;

        public MembershipService(
            ApplicationDbContext dbContext,
            ILogger<MembershipService> logger)
        {
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<List<Membership>> GetAllMembershipsAsync() =>
            await _dbContext.Memberships
                .Include(m => m.UserMemberships)
                .ToListAsync();

        public async Task<Membership?> GetMembershipByIdAsync(int id) =>
            await _dbContext.Memberships
                .Include(m => m.UserMemberships)
                .FirstOrDefaultAsync(m => m.MembershipId == id);

        public async Task<Membership> AddMembershipAsync(MembershipDTO dto)
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                var membership = new Membership
                {
                    MembershipType = dto.MembershipType,
                    BorrowLimit = dto.BorrowLimit,
                    DurationInDays = dto.DurationInDays,
                    Price = dto.Price,
                    Description = dto.Description,
                    IsFamilyPlan = dto.IsFamilyPlan,
                    MaxFamilyMembers = dto.MaxFamilyMembers,
                    RequiresApproval = dto.RequiresApproval,
                    CreatedAt = DateTime.UtcNow
                };

                _dbContext.Memberships.Add(membership);
                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
                return membership;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, "Membership error: Failed to add new membership");
                throw;
            }
        }

        public async Task<Membership?> EditMembershipAsync(int id, MembershipDTO dto)
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                var membership = await _dbContext.Memberships.FindAsync(id);
                if (membership == null) return null;

                membership.MembershipType = dto.MembershipType;
                membership.BorrowLimit = dto.BorrowLimit;
                membership.DurationInDays = dto.DurationInDays;
                membership.Price = dto.Price;
                membership.Description = dto.Description;
                membership.IsFamilyPlan = dto.IsFamilyPlan;
                membership.MaxFamilyMembers = dto.MaxFamilyMembers;
                membership.RequiresApproval = dto.RequiresApproval;

                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
                return membership;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Membership error: Failed to edit membership | ID: {id}");
                throw;
            }
        }

        public async Task<bool> DeleteMembershipAsync(int id)
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                var membership = await _dbContext.Memberships.FindAsync(id);
                if (membership == null) return false;

                _dbContext.Memberships.Remove(membership);
                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
                return true;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Membership error: Failed to delete membership | ID: {id}");
                throw;
            }
        }

        public async Task<UserMembership> RequestMembershipAsync(long userId, int membershipId, long? parentUserId = null)
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                var membership = await _dbContext.Memberships.FindAsync(membershipId);
                if (membership == null)
                    throw new Exception("Membership not found");

                // Check if user already has an active membership
                var existingMembership = await _dbContext.UserMemberships
                    .FirstOrDefaultAsync(um => um.UserId == userId && um.IsActive && !um.IsCanceled);

                // Validate family plan
                if (membership.IsFamilyPlan)
                {
                    if (parentUserId == null)
                        throw new Exception("Parent user ID is required for family plan membership");

                    // Check if parent user exists and has an active family plan
                    var parentMembership = await _dbContext.UserMemberships
                        .Include(um => um.Membership)
                        .FirstOrDefaultAsync(um => 
                            um.UserId == parentUserId && 
                            um.IsActive && 
                            !um.IsCanceled && 
                            um.Membership.IsFamilyPlan);

                    if (parentMembership == null)
                        throw new Exception("Parent user does not have an active family plan membership");

                    // Check if family plan has reached maximum members
                    var familyMembersCount = await _dbContext.UserMemberships
                        .CountAsync(um => 
                            um.ParentUserId == parentUserId && 
                            um.IsActive && 
                            !um.IsCanceled);

                    if (familyMembersCount >= parentMembership.Membership.MaxFamilyMembers)
                        throw new Exception("Family plan has reached maximum number of members");
                }

                var request = new UserMembership
                {
                    UserId = userId,
                    MembershipId = membershipId,
                    ParentUserId = parentUserId,
                    Status = "Pending",
                    IsActive = false, // Always start as inactive until approved
                    StartDate = DateTime.UtcNow,
                    EndDate = DateTime.UtcNow.AddDays(membership.DurationInDays)
                };

                _dbContext.UserMemberships.Add(request);
                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
                return request;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Membership error: Failed to request membership | User ID: {userId}");
                throw;
            }
        }

        public async Task<UserMembership?> ApproveMembershipAsync(int userMembershipId, long approverId)
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                var request = await _dbContext.UserMemberships
                    .Include(um => um.Membership)
                    .FirstOrDefaultAsync(um => um.UserMembershipId == userMembershipId);

                if (request == null || request.Status != "Pending")
                    return null;

                // Find and cancel the existing active membership if any
                var existingMembership = await _dbContext.UserMemberships
                    .FirstOrDefaultAsync(um => 
                        um.UserId == request.UserId && 
                        um.IsActive && 
                        !um.IsCanceled && 
                        um.UserMembershipId != userMembershipId);

                if (existingMembership != null)
                {
                    existingMembership.IsCanceled = true;
                    existingMembership.IsActive = false;
                    existingMembership.EndDate = DateTime.UtcNow;
                    _dbContext.UserMemberships.Update(existingMembership);
                }

                // Activate the new membership
                request.Status = "Approved";
                request.IsActive = true;
                request.StartDate = DateTime.UtcNow;
                request.EndDate = DateTime.UtcNow.AddDays(request.Membership.DurationInDays);

                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
                return request;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Membership error: Failed to approve request | Request ID: {userMembershipId}");
                throw;
            }
        }

        public async Task<UserMembership?> RejectMembershipAsync(int userMembershipId, long approverId)
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                // First check if the approver is a librarian
                var approver = await _dbContext.Users
                    .FirstOrDefaultAsync(u => u.Id == approverId);

                if (approver == null)
                    throw new UnauthorizedAccessException("Approver not found");

                if (approver.Role != "Librarian" && approver.Role != "Admin")
                    throw new UnauthorizedAccessException("Only librarians and admins can reject membership requests");

                var request = await _dbContext.UserMemberships
                    .Include(um => um.Membership)
                    .FirstOrDefaultAsync(um => um.UserMembershipId == userMembershipId);

                if (request == null)
                    throw new Exception("Membership request not found");

                if (request.Status != "Pending")
                    throw new Exception("Can only reject pending membership requests");

                // Only mark the rejected request as inactive and canceled
                request.Status = "Rejected";
                request.IsActive = false;
                request.IsCanceled = true;

                // Ensure any existing active membership remains active
                var existingMembership = await _dbContext.UserMemberships
                    .FirstOrDefaultAsync(um => 
                        um.UserId == request.UserId && 
                        um.IsActive && 
                        !um.IsCanceled && 
                        um.UserMembershipId != userMembershipId);

                if (existingMembership != null)
                {
                    existingMembership.IsActive = true;
                    existingMembership.IsCanceled = false;
                    _dbContext.UserMemberships.Update(existingMembership);
                }

                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
                return request;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Membership error: Failed to reject request | Request ID: {userMembershipId}");
                throw;
            }
        }

        public async Task<bool> CancelMembershipAsync(int userMembershipId, long userId)
        {
            using var transaction = await _dbContext.Database.BeginTransactionAsync();
            try
            {
                var request = await _dbContext.UserMemberships
                    .FirstOrDefaultAsync(um => um.UserMembershipId == userMembershipId);

                if (request == null || request.UserId != userId || request.IsCanceled)
                    return false;

                request.IsCanceled = true;
                request.IsActive = false;
                request.EndDate = DateTime.UtcNow;
                

                await _dbContext.SaveChangesAsync();
                await transaction.CommitAsync();
                return true;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                _logger.LogError(ex, $"Membership error: Failed to cancel request | Request ID: {userMembershipId}");
                throw;
            }
        }

        public async Task<List<UserMembership>> GetPendingRequestsAsync()
        {
            try
            {
                return await _dbContext.UserMemberships
                    .Include(um => um.Membership)
                    .Include(um => um.User)
                    .Where(um => um.Status == "Pending" && !um.IsCanceled)
                    .OrderByDescending(um => um.StartDate)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Membership error: Failed to get pending membership requests");
                throw;
            }
        }

        public async Task<UserMembership?> GetUserMembershipAsync(long userId)
        {
            try
            {
                return await _dbContext.UserMemberships
                    .Include(um => um.Membership)
                    .Include(um => um.User)
                    .Include(um => um.ParentUser)
                    .Where(um => um.UserId == userId && !um.IsCanceled)
                    .OrderByDescending(um => um.StartDate)
                    .FirstOrDefaultAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Membership error: Failed to get membership | User ID: {userId}");
                throw;
            }
        }
    }
}
