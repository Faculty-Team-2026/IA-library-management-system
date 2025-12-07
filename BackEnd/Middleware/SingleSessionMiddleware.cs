using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using BackEnd.Data;
using BackEnd.Models;

namespace BackEnd.Middleware
{
    public class SingleSessionMiddleware
    {
        private readonly RequestDelegate _next;

        public SingleSessionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ApplicationDbContext dbContext)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Replace("Bearer ", "");
            if (!string.IsNullOrEmpty(token))
            {
                var handler = new JwtSecurityTokenHandler();
                JwtSecurityToken? jwtToken = null;
                try
                {
                    jwtToken = handler.ReadJwtToken(token);
                }
                catch
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("Invalid token format.");
                    return;
                }
                var userIdClaim = jwtToken?.Claims.FirstOrDefault(c => c.Type == "userId");
                if (userIdClaim != null && long.TryParse(userIdClaim.Value, out var userId))
                {
                    var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
                    if (user == null || user.LastActiveToken != token)
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        await context.Response.WriteAsync("Session expired or logged in elsewhere.");
                        return;
                    }
                }
            }
            await _next(context);
        }
    }
}
