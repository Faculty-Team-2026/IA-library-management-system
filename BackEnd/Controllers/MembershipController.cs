using BackEnd.DTOs;
using BackEnd.Models;
using BackEnd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BackEnd.Controllers
{
    /// <summary>
    /// Controller for managing memberships and membership requests
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class MembershipController : ControllerBase
    {
        private readonly IMembershipService _membershipService;
        private readonly ILogger<MembershipController> _logger;

        public MembershipController(
            IMembershipService membershipService,
            ILogger<MembershipController> logger)
        {
            _membershipService = membershipService ?? throw new ArgumentNullException(nameof(membershipService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Get all available memberships
        /// </summary>
        /// <returns>List of memberships</returns>
        [HttpGet]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IEnumerable<Membership>))]
        public async Task<ActionResult<IEnumerable<Membership>>> GetAllMemberships()
        {
            try
            {
                var memberships = await _membershipService.GetAllMembershipsAsync();
                return Ok(memberships);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting all memberships");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while retrieving memberships");
            }
        }

        /// <summary>
        /// Get a specific membership by ID
        /// </summary>
        /// <param name="id">Membership ID</param>
        /// <returns>Membership details</returns>
        [HttpGet("{id}")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Membership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<Membership>> GetMembershipById(int id)
        {
            try
            {
                var membership = await _membershipService.GetMembershipByIdAsync(id);
                if (membership == null)
                {
                    return NotFound($"Membership with ID {id} not found");
                }
                return Ok(membership);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting membership with ID {id}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while retrieving the membership");
            }
        }

        /// <summary>
        /// Create a new membership type
        /// </summary>
        /// <param name="dto">Membership details</param>
        /// <returns>Created membership</returns>
        [HttpPost]
        [Authorize(Roles = "Admin,Librarian")]
        [ProducesResponseType(StatusCodes.Status201Created, Type = typeof(Membership))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<Membership>> AddMembership([FromBody] MembershipDTO dto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var membership = await _membershipService.AddMembershipAsync(dto);
                return CreatedAtAction(nameof(GetMembershipById), new { id = membership.MembershipId }, membership);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating new membership");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while creating the membership");
            }
        }

        /// <summary>
        /// Update an existing membership
        /// </summary>
        /// <param name="id">Membership ID</param>
        /// <param name="dto">Updated membership details</param>
        /// <returns>Updated membership</returns>
        [HttpPut("{id}")]
        [Authorize(Roles = "Admin,Librarian")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Membership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<Membership>> EditMembership(int id, [FromBody] MembershipDTO dto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var membership = await _membershipService.EditMembershipAsync(id, dto);
                if (membership == null)
                {
                    return NotFound($"Membership with ID {id} not found");
                }
                return Ok(membership);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating membership with ID {id}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while updating the membership");
            }
        }

        /// <summary>
        /// Delete a membership
        /// </summary>
        /// <param name="id">Membership ID</param>
        /// <returns>No content if successful</returns>
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin,Librarian")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> DeleteMembership(int id)
        {
            try
            {
                var deleted = await _membershipService.DeleteMembershipAsync(id);
                if (!deleted)
                {
                    return NotFound($"Membership with ID {id} not found");
                }
                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting membership with ID {id}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while deleting the membership");
            }
        }

        /// <summary>
        /// Request a new membership for a user
        /// </summary>
        /// <param name="request">Request details</param>
        /// <returns>Membership request record</returns>
        [HttpPost("request")]
        [Authorize(Roles = "User,Admin")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UserMembership))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<UserMembership>> RequestMembership([FromBody] MembershipRequestDTO request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Verify the requesting user matches the authenticated user
                var userId = long.Parse(User.FindFirst("userId").Value);
                Console.WriteLine("userId: " + userId);
                if (userId != request.UserId && !User.IsInRole("Admin"))
                {
                    return Forbid();
                }

                var userMembership = await _membershipService.RequestMembershipAsync(
                    request.UserId,
                    request.MembershipId,
                    request.ParentUserId);

                return Ok(userMembership);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error requesting membership for user {request.UserId}");
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Approve a pending membership request
        /// </summary>
        /// <param name="userMembershipId">User membership ID</param>
        /// <param name="approverId">Approver user ID</param>
        /// <returns>Approved membership record</returns>
        [HttpPut("approve/{userMembershipId}")]
        [Authorize(Roles = "Admin,Librarian")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UserMembership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<UserMembership>> ApproveMembership(
            int userMembershipId,
            [FromQuery] long approverId)
        {
            try
            {
                var approved = await _membershipService.ApproveMembershipAsync(userMembershipId, approverId);
                if (approved == null)
                {
                    return NotFound($"Membership request with ID {userMembershipId} not found or already processed");
                }
                return Ok(approved);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error approving membership request {userMembershipId}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while approving the membership");
            }
        }

        /// <summary>
        /// Reject a pending membership request
        /// </summary>
        /// <param name="userMembershipId">User membership ID</param>
        /// <param name="approverId">Approver user ID</param>
        /// <returns>Rejected membership record</returns>
        [HttpPut("reject/{userMembershipId}")]
        [Authorize(Roles = "Admin,Librarian")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UserMembership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<UserMembership>> RejectMembership(
            int userMembershipId,
            [FromQuery] long approverId)
        {
            try
            {
                var rejected = await _membershipService.RejectMembershipAsync(userMembershipId, approverId);
                if (rejected == null)
                {
                    return NotFound($"Membership request with ID {userMembershipId} not found or already processed");
                }
                return Ok(rejected);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error rejecting membership request {userMembershipId}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while rejecting the membership");
            }
        }

        /// <summary>
        /// Cancel a membership (either pending or active)
        /// </summary>
        /// <param name="userMembershipId">User membership ID</param>
        /// <param name="userId">User ID</param>
        /// <returns>Success status</returns>
        [HttpPut("cancel/{userMembershipId}")]
        [Authorize(Roles = "User,Admin")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> CancelMembership(
            int userMembershipId,
            [FromQuery] long userId)
        {
            try
            {
                // Verify the requesting user matches the authenticated user
                var authenticatedUserId = long.Parse(User.FindFirst("sub")?.Value ?? "0");
                if (authenticatedUserId != userId && !User.IsInRole("Admin"))
                {
                    return Forbid();
                }

                var canceled = await _membershipService.CancelMembershipAsync(userMembershipId, userId);
                if (!canceled)
                {
                    return NotFound($"Membership request with ID {userMembershipId} not found or not authorized to cancel");
                }
                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error canceling membership request {userMembershipId}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while canceling the membership");
            }
        }

        /// <summary>
        /// Get all pending membership requests
        /// </summary>
        /// <returns>List of pending membership requests</returns>
        [HttpGet("requests")]
        [Authorize(Roles = "Admin,Librarian")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IEnumerable<UserMembership>))]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<IEnumerable<UserMembership>>> GetPendingRequests()
        {
            try
            {
                var requests = await _membershipService.GetPendingRequestsAsync();
                return Ok(requests);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting pending membership requests");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while retrieving pending requests");
            }
        }

        /// <summary>
        /// Get membership details for a specific user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <returns>User's membership details</returns>
        [HttpGet("user/{userId}")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UserMembership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<ActionResult<UserMembership>> GetUserMembership(long userId)
        {
            try
            {
                // Verify the requesting user matches the authenticated user or is an admin
                var authenticatedUserId = long.Parse(User.FindFirst("userId").Value);
                if (authenticatedUserId != userId && !User.IsInRole("Admin"))
                {
                    return Forbid();
                }

                var userMembership = await _membershipService.GetUserMembershipAsync(userId);
                if (userMembership == null)
                {
                    return NotFound($"No membership found for user {userId}");
                }
                return Ok(userMembership);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting membership for user {userId}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while retrieving the user's membership");
            }
        }
    }
}