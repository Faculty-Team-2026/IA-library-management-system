using BackEnd.Data;
using BackEnd.Hubs;
using BackEnd.Models;
using BackEnd.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;
using System.Text.Json.Serialization;

internal class Program
{
    private static async Task Main(string[] args)
    {
        //start project
        var builder = WebApplication.CreateBuilder(args);

        // Add DbContext
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

        // Register Services
        builder.Services.AddScoped<IAuthService, AuthService>();
        builder.Services.AddScoped<IBookService, BookService>();
        builder.Services.AddScoped<IBorrowService, BorrowService>();
        builder.Services.AddScoped<ILibrarianService, LibrarianService>();
        builder.Services.AddScoped<IUserService, UserService>();
        builder.Services.AddScoped<IMembershipService, MembershipService>();
        builder.Services.AddScoped<IValidationService, ValidationService>();
        builder.Services.AddScoped<IEncryptionService, EncryptionService>();
        builder.Services.AddScoped<ILoggerService, LoggerService>();
        builder.Services.AddScoped<IAccountLockoutService, AccountLockoutService>();
        builder.Services.AddScoped<IAnomalyDetectionService, AnomalyDetectionService>();
        builder.Services.AddSingleton<IRateLimitingService, RateLimitingService>();

        builder.Services.Configure<FormOptions>(options =>
        {
            options.MultipartBodyLengthLimit = 10 * 1024 * 1024; // 10MB
        });

        // Add Controllers with JSON configuration
        builder.Services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
                options.JsonSerializerOptions.WriteIndented = true;
            });
        builder.Services.AddOpenApi();
        builder.Services.AddSignalR();

        // CORS for chat
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy
                      .AllowAnyOrigin()  // Allow any origin for mobile/ngrok testing
                      .AllowAnyHeader()
                      .AllowAnyMethod();
                      // Note: Cannot use AllowCredentials() with AllowAnyOrigin()
            });
        });

        // Configure SignalR
        builder.Services.AddSignalR(options =>
        {
            options.EnableDetailedErrors = true;
            options.MaximumReceiveMessageSize = 102400; // 100 KB
            options.HandshakeTimeout = TimeSpan.FromSeconds(15);
            options.KeepAliveInterval = TimeSpan.FromSeconds(10);
        });

        // JWT Authentication
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key is not configured")))
                };
            });

        // Authorization Policies
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"))
            .AddPolicy("LibrarianOnly", policy => policy.RequireRole("Librarian"))
            .AddPolicy("UserOnly", policy => policy.RequireRole("User"));

        var app = builder.Build();

        // Enable static files for testing page
        app.UseStaticFiles();

        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();
            app.MapScalarApiReference();
        }

        // app.UseHttpsRedirection();

        // Add security headers middleware
        app.Use(async (context, next) =>
        {
            // Log all incoming requests
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {context.Request.Method} {context.Request.Path} from {context.Connection.RemoteIpAddress}");
            Console.WriteLine($"  Origin: {context.Request.Headers["Origin"]}");
            Console.WriteLine($"  User-Agent: {context.Request.Headers["User-Agent"]}");
            
            // Bypass ngrok browser warning for mobile devices
            context.Response.Headers["ngrok-skip-browser-warning"] = "true";
            
            // Handle OPTIONS preflight requests explicitly
            if (context.Request.Method == "OPTIONS")
            {
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
                context.Response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, ngrok-skip-browser-warning";
                context.Response.StatusCode = 200;
                await context.Response.CompleteAsync();
                return;
            }
            
            // Prevent MIME type sniffing
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            
            // Prevent clickjacking attacks (relaxed for mobile)
            context.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
            
            // Enable XSS protection
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
            
            // Referrer policy
            context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            
            // Content Security Policy
            context.Response.Headers["Content-Security-Policy"] = "default-src 'self'";
            
            await next();
        });

        // Enable CORS before other middleware
        app.UseCors();

        app.UseAuthentication();
        
        // Enforce single active session per user (after authentication but before authorization)
        app.UseMiddleware<BackEnd.Middleware.SingleSessionMiddleware>();
        
        app.UseAuthorization();

        app.MapControllers();

        using (var scope = app.Services.CreateScope())
        {
            var services = scope.ServiceProvider;
            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var encryptionService = services.GetService<IEncryptionService>();
                
                // Ensure encryption service is available
                if (encryptionService == null)
                {
                    throw new InvalidOperationException("IEncryptionService is not registered in dependency injection container.");
                }

                await context.Database.MigrateAsync();

                // Seed admin user
                if (!await context.Users.AnyAsync(u => u.Username == "admin"))
                {
                    context.Users.Add(new User
                    {
                        Username = "admin",
                        Password = BCrypt.Net.BCrypt.HashPassword("admin123"),
                        Role = "Admin",
                        Email = "admin@library.com",
                        CreatedAt = DateTime.UtcNow,
                        FirstName = "Admin",
                        LastName = "User",
                        SSN = encryptionService.Encrypt("123-45-6789"),
                        PhoneNumber = encryptionService.Encrypt("123-456-7890")
                    });
                }

                // Seed additional users
                //var users = new List<User>
                //{
                //    new User
                //    {
                //        Username = "salma",
                //        Password = BCrypt.Net.BCrypt.HashPassword("password1"),
                //        Role = "Librarian",
                //        CreatedAt = DateTime.UtcNow,
                //        Email = "salma@example.com",
                //        FirstName = "Salma",
                //        LastName = "Mostafa",
                //        PhoneNumber = "1234567890",
                //        SSN = "323-45-6789"
                //    },
                //    new User
                //    {
                //        Username = "sagheer",
                //        Password = BCrypt.Net.BCrypt.HashPassword("password2"),
                //        Role = "User",
                //        CreatedAt = DateTime.UtcNow,
                //        Email = "sagheer@example.com",
                //        FirstName = "Mohammad",
                //        LastName = "El-Sagheer",
                //        PhoneNumber = "0987654821",
                //        SSN = "213-65-4321"
                //    },
                //    new User
                //    {
                //        Username = "reda",
                //        Password = BCrypt.Net.BCrypt.HashPassword("password3"),
                //        Role = "User",
                //        CreatedAt = DateTime.UtcNow,
                //        Email = "reda@example.com",
                //        FirstName = "Mhmd",
                //        LastName = "Reda",
                //        PhoneNumber = "0987654321",
                //        SSN = "432-65-4321"
                //    },
                //    new User
                //    {
                //        Username = "ahmed",
                //        Password = BCrypt.Net.BCrypt.HashPassword("password4"),
                //        Role = "User",
                //        CreatedAt = DateTime.UtcNow,
                //        Email = "ahmed@example.com",
                //        FirstName = "Ahmed",
                //        LastName = "Hazem",
                //        PhoneNumber = "0987659321",
                //        SSN = "987-65-4321"
                //    },
                //    new User
                //    {
                //        Username = "nehal",
                //        Password = BCrypt.Net.BCrypt.HashPassword("password5"),
                //        Role = "User",
                //        CreatedAt = DateTime.UtcNow,
                //        Email = "nehal@example.com",
                //        FirstName = "Nehal",
                //        LastName = "Nady",
                //        PhoneNumber = "0989654321",
                //        SSN = "737-65-4321"
                //    },
                //    new User
                //    {
                //        Username = "tarek",
                //        Password = BCrypt.Net.BCrypt.HashPassword("password6"),
                //        Role = "User",
                //        CreatedAt = DateTime.UtcNow,
                //        Email = "tarek@example.com",
                //        FirstName = "Mohammed",
                //        LastName = "Tarek",
                //        PhoneNumber = "0887654321",
                //        SSN = "987-65-4321"
                //    }
                //};

                //foreach (var user in users)
                //{
                //    if (!await context.Users.AnyAsync(u => u.Username == user.Username))
                //    {
                //        context.Users.Add(user);
                //    }
                //}

                

                await context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                var logger = services.GetService<ILogger<Program>>();
                if (logger != null)
                {
                    logger.LogError(ex, "An error occurred during migration and seeding.");
                }
                else
                {
                    Console.WriteLine($"An error occurred during migration and seeding: {ex.Message}");
                }
                
                // Re-throw to prevent app from starting with corrupted state
                throw;
            }
        }


        // Map SignalR hubs
        app.MapHub<ChatHub>("/chathub");
        app.MapHub<BackEnd.Hubs.SessionHub>("/sessionhub");

        await app.RunAsync();
    }
}
