using FastEndpoints;
using System.Security.Claims;

public class SecureApiEndpoint : Endpoint<NoRequest, ApiResponse>
{
    public override void Configure()
    {
        Get("/api/secure-data"); // Or Post, etc.
        RequireAuthorization(); // Enforces auth; throws 401 if no valid token
        // Optional: Declarative checks
        // Permissions("moneyIn:Read"); // Assumes "permissions" claim type; checks if ANY match
        // Claims("subscriberId"); // Ensures claim exists (value ignored)
    }

    public override async Task HandleAsync(NoRequest req, CancellationToken ct)
    {
        // Access claims via this.User (ClaimsPrincipal)
        var subscriberId = this.User.FindFirst("subscriberId")?.Value; // string? or throw if null
        var sponsorId = this.User.FindFirst("sponsorId")?.Value;
        var businessUserId = this.User.FindFirst("businessUserId")?.Value;

        if (string.IsNullOrEmpty(subscriberId))
        {
            ThrowError(400, "Missing subscriberId claim");
            return;
        }

        // Check permissions (e.g., array or comma-separated)
        var hasMoneyInRead = this.User.HasClaim("permissions", "moneyIn:Read"); // For array/single value
        // Or for comma-separated: 
        // var perms = this.User.FindFirst("permissions")?.Value?.Split(',') ?? [];
        // var hasMoneyInRead = perms.Contains("moneyIn:Read");

        if (!hasMoneyInRead)
        {
            ThrowError(403, "Insufficient permissions: moneyIn:Read required");
            return;
        }

        // Business logic using claims
        var response = new ApiResponse
        {
            Data = $"Hello {this.User.Identity?.Name ?? "User"}! Subscriber: {subscriberId}, Sponsor: {sponsorId}",
            BusinessUserId = businessUserId
        };

        // Optional: Pull from cache if needed (e.g., for performance)
        var cache = HttpContext.RequestServices.GetRequiredService<IMemoryCache>();
        var cachedPrincipal = cache.Get<ClaimsPrincipal>($"auth:{subscriberId}");
        if (cachedPrincipal != null)
        {
            // Use cached for extra checks
            var cachedPerms = cachedPrincipal.Claims.Where(c => c.Type == "permissions").Select(c => c.Value);
        }

        await SendOkAsync(response);
    }
}

public record ApiResponse
{
    public string? Data { get; init; }
    public string? BusinessUserId { get; init; }
}