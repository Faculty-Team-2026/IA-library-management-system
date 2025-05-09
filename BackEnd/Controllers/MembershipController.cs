﻿using BackEnd.DTOs;
using BackEnd.Models;
using BackEnd.Services;
using Microsoft.AspNetCore.Mvc;

namespace BackEnd.Controllers
{
    /// <summary>
    /// Controller for managing memberships and membership requests
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class MembershipController : ControllerBase
    {
        private readonly IMembershipService _membershipService;
        private readonly ILogger<MembershipController> _logger;

        public MembershipController(
            IMembershipService membershipService,
            ILogger<MembershipController> logger)
        {
            _membershipService = membershipService;
            _logger = logger;
        }

        /// <summary>
        /// Get all available memberships
        /// </summary>
        /// <returns>List of memberships</returns>
        [HttpGet]
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
        [ProducesResponseType(StatusCodes.Status201Created, Type = typeof(Membership))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
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
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Membership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
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
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
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
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UserMembership))]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<UserMembership>> RequestMembership([FromBody] MembershipRequestDTO request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
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
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UserMembership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
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
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(UserMembership))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
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
        /// <param name="userId">User ID who is canceling</param>
        /// <returns>Success message</returns>
        [HttpPut("cancel/{userMembershipId}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> CancelMembership(
            int userMembershipId,
            [FromQuery] long userId)
        {
            try
            {
                var cancelled = await _membershipService.CancelMembershipAsync(userMembershipId, userId);
                if (!cancelled)
                {
                    return NotFound($"Membership with ID {userMembershipId} not found or cannot be canceled");
                }
                return Ok(new { message = "Membership cancelled successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error canceling membership {userMembershipId}");
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred while canceling the membership");
            }
        }
    }
}