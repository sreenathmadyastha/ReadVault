// dotnet add package StackExchange.Redis  # For Redis client
// dotnet add package Microsoft.AspNetCore.Authentication  # Already have, but ensure
// dotnet add package FastEndpoints.Security  # For endpoint auth

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using StackExchange.Redis;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis"); // e.g., "your-enterprise-redis:6379,password=..."
    options.InstanceName = "TokenCache:";
});

// Proxy config (optional, from appsettings/AKV)
var useProxy = builder.Configuration.GetValue<bool>("Auth:UseCorporateProxy");
var proxyUri = builder.Configuration["Auth:CorporateProxyUri"]; // e.g., "http://proxy.corp.com:8080"

// Register HttpClient for introspect (with proxy handler if enabled)
builder.Services.AddHttpClient("IntrospectClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["Ping:IntrospectEndpoint"] ?? "https://your-ping-domain.com/as/introspect.oauth2"); // Ping introspect URL
    client.DefaultRequestHeaders.Add("Authorization", $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes("clientId:clientSecret"))}"); // Client creds from AKV
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    if (useProxy && !string.IsNullOrEmpty(proxyUri))
    {
        return new HttpClientHandler { Proxy = new WebProxy(proxyUri), UseProxy = true };
    }
    return new HttpClientHandler(); // No proxy
});

// Custom handler registration (see below)
builder.Services.AddAuthentication("CustomTokenScheme")
    .AddScheme<AuthenticationSchemeOptions, CustomTokenHandler>("CustomTokenScheme", _ => { });

// Authorization and FastEndpoints
builder.Services.AddAuthorization()
    .AddFastEndpoints();

var app = builder.Build();

app.UseAuthentication()
   .UseAuthorization()
   .UseFastEndpoints();

app.Run();

// {
//   "ConnectionStrings": { "Redis": "your-redis-connection-string" },
//   "Ping": {
//     "IntrospectEndpoint": "https://your-ping-domain.com/as/introspect.oauth2"
//   },
//   "Auth": {
//     "UseCorporateProxy": true,
//     "CorporateProxyUri": "http://proxy.corp.com:8080"
//   }
// }Temp AKV Bypass: Load clientSecret from env/local instead of AKV.

// using Microsoft.AspNetCore.Authentication;
// using Microsoft.Extensions.Caching.Distributed;
// using Microsoft.Extensions.Logging;
// using Microsoft.Extensions.Options;
// using System.Security.Claims;
// using System.Text;
// using System.Text.Json;

public class CustomTokenHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IDistributedCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<CustomTokenHandler> _logger;

    public CustomTokenHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        IDistributedCache cache,
        IHttpClientFactory httpClientFactory)
        : base(options, logger)
    {
        _cache = cache;
        _httpClientFactory = httpClientFactory;
        _logger = logger.CreateLogger<CustomTokenHandler>();
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader) ||
            !authHeader.ToString().StartsWith("Bearer "))
        {
            return AuthenticateResult.NoResult();
        }

        var token = authHeader.ToString().Substring("Bearer ".Length).Trim();
        var cacheKey = $"token:{token.Substring(0, Math.Min(50, token.Length))}"; // Truncate for key safety

        // Step 1: Check Redis cache first
        var cachedPrincipalJson = await _cache.GetStringAsync(cacheKey, Context.RequestAborted);
        if (!string.IsNullOrEmpty(cachedPrincipalJson))
        {
            var principal = JsonSerializer.Deserialize<ClaimsPrincipal>(cachedPrincipalJson, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }

        // Step 2: Introspect API call (with proxy via HttpClient)
        try
        {
            using var httpClient = _httpClientFactory.CreateClient("IntrospectClient");
            var requestContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("token", token)
            });
            var response = await httpClient.PostAsync("", requestContent, Context.RequestAborted); // "" = baseaddress + path

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Introspect failed: {StatusCode}", response.StatusCode);
                return AuthenticateResult.Fail("Token validation failed");
            }

            var introspectJson = await response.Content.ReadAsStringAsync(Context.RequestAborted);
            var introspectResult = JsonSerializer.Deserialize<JsonElement>(introspectJson);

            if (!introspectResult.GetProperty("active").GetBoolean())
            {
                return AuthenticateResult.Fail("Token inactive");
            }

            // Step 3: Build ClaimsPrincipal from introspect claims
            var claims = new List<Claim>();
            if (introspectResult.TryGetProperty("sub", out var sub)) claims.Add(new Claim(ClaimTypes.NameIdentifier, sub.GetString()!));
            if (introspectResult.TryGetProperty("subscriberId", out var subId)) claims.Add(new Claim("subscriberId", subId.GetString()!));
            if (introspectResult.TryGetProperty("sponsorId", out var sponId)) claims.Add(new Claim("sponsorId", sponId.GetString()!));
            if (introspectResult.TryGetProperty("businessUserId", out var bizId)) claims.Add(new Claim("businessUserId", bizId.GetString()!));
            if (introspectResult.TryGetProperty("permissions", out var perms))
            {
                // Handle array or string
                if (perms.ValueKind == JsonValueKind.Array)
                {
                    foreach (var perm in perms.EnumerateArray())
                    {
                        claims.Add(new Claim("permissions", perm.GetString()!));
                    }
                }
                else
                {
                    claims.Add(new Claim("permissions", perms.GetString()!));
                }
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            // Step 4: Cache back to Redis (TTL from exp claim or default)
            var expiry = introspectResult.TryGetProperty("exp", out var exp) ? TimeSpan.FromSeconds(exp.GetInt64()) : TimeSpan.FromMinutes(60);
            var cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = expiry > TimeSpan.FromMinutes(1) ? expiry.Add(TimeSpan.FromMinutes(-1)) : expiry // Buffer
            };
            var principalJson = JsonSerializer.Serialize(principal);
            await _cache.SetStringAsync(cacheKey, principalJson, cacheOptions, Context.RequestAborted);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Introspect error");
            return AuthenticateResult.Fail(ex.Message);
        }
    }
}

// 4. Using Claims in FastEndpoints (Unchanged)
// Once HttpContext.User is set, access as before. Endpoints auto-use the scheme.

public class SecureEndpoint : Endpoint<NoRequest>
{
    public override void Configure()
    {
        Get("/api/secure");
        RequireAuthorization("CustomTokenScheme"); // Specify scheme
        Permissions("moneyIn:Read"); // Checks "permissions" claims
    }

    public override async Task HandleAsync(NoRequest req, CancellationToken ct)
    {
        var subscriberId = this.User.FindFirst("subscriberId")?.Value;
        if (string.IsNullOrEmpty(subscriberId))
        {
            ThrowError(400, "Missing subscriberId");
            return;
        }

        await SendOkAsync(new { SubscriberId = subscriberId, Permissions = this.User.FindAll("permissions").Select(c => c.Value) });
    }
}

// Signing New Tokens (Optional, As Before)
// If you still need to sign new tokens (e.g., in a /token endpoint), keep the AKV RSA injection—it's independent of validation.
// 6. Testing and Best Practices

// Local Redis: Use docker run -d -p 6379:6379 redis for dev; set connection string.
// Mock Introspect: For temp testing without Ping, create a local endpoint returning mock JSON.
// Security: Use HTTPS for introspect. Blacklist revoked tokens in Redis (set "active:false" key).
// Performance: Cache hits ~ms; introspect latency depends on proxy/Ping.
// AKV Temp: Still bypass as needed for client secret.

// This custom flow integrates your exact process. If Ping's introspect differs (e.g., headers, response format), share a sample for tweaks!