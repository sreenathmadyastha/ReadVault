
// Program.cs
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using StackExchange.Redis;
using Microsoft.AspNetCore.Authentication;

using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Redis for enterprise cache (as per your flow)
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
});

// HttpClient for introspect (product token validation, proxy optional)
builder.Services.AddHttpClient("IntrospectClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["Ping:IntrospectEndpoint"] ?? "https://your-ping-domain.com/as/introspect.oauth2");
    // Client creds from AKV or local/env
    var clientSecret = builder.Configuration["ClientSecret"] ?? "local-temp-secret"; // Temp bypass
    client.DefaultRequestHeaders.Add("Authorization", $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes("clientId:" + clientSecret))}");
})
.ConfigurePrimaryHttpMessageHandler(() =>
{
    var useProxy = builder.Configuration.GetValue<bool>("Auth:UseCorporateProxy");
    var proxyUri = builder.Configuration["Auth:CorporateProxyUri"];
    if (useProxy && !string.IsNullOrEmpty(proxyUri))
    {
        return new HttpClientHandler { Proxy = new WebProxy(proxyUri), UseProxy = true };
    }
    return new HttpClientHandler();
});

// Custom handler for product token (no signing keys)
builder.Services.AddAuthentication("ProductTokenScheme")
    .AddScheme<AuthenticationSchemeOptions, CustomProductTokenHandler>("ProductTokenScheme", _ => { });

// RSA signing key (AKV or local temp bypass)
var keyVaultEndpoint = new Uri("https://your-keyvault-name.vault.azure.net/");
// Temp bypass: Comment below for local testing
// builder.Configuration.AddAzureKeyVault(keyVaultEndpoint, new DefaultAzureCredential());

builder.Services.AddSingleton<ISigningCredentialsProvider>(async provider =>
{
    // AKV version (uncomment for prod)
    // var keyClient = new KeyClient(keyVaultEndpoint, new DefaultAzureCredential());
    // var keyVaultKey = await keyClient.GetKeyAsync("your-rsa-key-name");
    // var rsa = keyVaultKey.Value.Key as RSA ?? throw new InvalidOperationException("RSA key not found.");

    // Temp local bypass
    var pfxBytes = File.ReadAllBytes("private-key.pfx"); // Local file
    var cert = new X509Certificate2(pfxBytes, "temp-password");
    var rsa = cert.GetRSAPrivateKey();

    return new RsaSecurityKey(rsa) { KeyId = "your-app-key-id" };
});

builder.Services.AddAuthorization()
    .AddFastEndpoints();

var app = builder.Build();

app.UseAuthentication()
   .UseAuthorization()
   .UseFastEndpoints();

app.Run();

// 2. Custom Handler for Product Token Validation
// Updated CustomProductTokenHandler.cs (renamed for clarity). Validates via Redis + introspect, extracts claims—no signing keys involved.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

public class CustomProductTokenHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IDistributedCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<CustomProductTokenHandler> _logger;

    public CustomProductTokenHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, IDistributedCache cache, IHttpClientFactory httpClientFactory)
        : base(options, logger)
    {
        _cache = cache;
        _httpClientFactory = httpClientFactory;
        _logger = logger.CreateLogger<CustomProductTokenHandler>();
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader) || !authHeader.ToString().StartsWith("Bearer "))
        {
            return AuthenticateResult.NoResult();
        }

        var token = authHeader.ToString().Substring("Bearer ".Length).Trim();
        var cacheKey = $"product-token:{token.Substring(0, Math.Min(50, token.Length))}"; // Truncated for safety

        // 1. Check enterprise Redis cache
        var cachedPrincipalJson = await _cache.GetStringAsync(cacheKey, Context.RequestAborted);
        if (!string.IsNullOrEmpty(cachedPrincipalJson))
        {
            var principal = JsonSerializer.Deserialize<ClaimsPrincipal>(cachedPrincipalJson);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            _logger.LogInformation("Product token validated from cache");
            return AuthenticateResult.Success(ticket);
        }

        // 2. Introspect API (corporate proxy if configured)
        try
        {
            using var httpClient = _httpClientFactory.CreateClient("IntrospectClient");
            var requestContent = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("token", token) });
            var response = await httpClient.PostAsync("", requestContent, Context.RequestAborted);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Introspect failed: {StatusCode}", response.StatusCode);
                return AuthenticateResult.Fail("Product token validation failed");
            }

            var introspectJson = await response.Content.ReadAsStringAsync(Context.RequestAborted);
            var introspectResult = JsonSerializer.Deserialize<JsonElement>(introspectJson);

            if (!introspectResult.GetProperty("active").GetBoolean())
            {
                return AuthenticateResult.Fail("Product token inactive");
            }

            // 3. Extract claims from introspect (no signing/validation keys needed)
            var claims = new List<Claim>();
            if (introspectResult.TryGetProperty("sub", out var sub)) claims.Add(new Claim(ClaimTypes.NameIdentifier, sub.GetString()!));
            if (introspectResult.TryGetProperty("subscriberId", out var subId)) claims.Add(new Claim("subscriberId", subId.GetString()!));
            if (introspectResult.TryGetProperty("sponsorId", out var sponId)) claims.Add(new Claim("sponsorId", sponId.GetString()!));
            if (introspectResult.TryGetProperty("businessUserId", out var bizId)) claims.Add(new Claim("businessUserId", bizId.GetString()!));
            if (introspectResult.TryGetProperty("permissions", out var perms))
            {
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

            // 4. Cache claims for future requests
            var expiry = introspectResult.TryGetProperty("exp", out var exp) ? TimeSpan.FromSeconds(exp.GetInt64()) : TimeSpan.FromMinutes(60);
            var cacheOptions = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = expiry.Add(TimeSpan.FromMinutes(-1)) };
            var principalJson = JsonSerializer.Serialize(principal);
            await _cache.SetStringAsync(cacheKey, principalJson, cacheOptions, Context.RequestAborted);

            _logger.LogInformation("Product token validated via introspect");
            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Introspect error for product token");
            return AuthenticateResult.Fail(ex.Message);
        }
    }
}
// 3. Endpoint: Exchange Product Token for New Signed Token
// This endpoint requires the product token (validated by middleware), extracts claims from this.User,
//  and signs a new token with your RSA key.
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class TokenExchangeEndpoint : Endpoint<NoRequest>
{
    private readonly ISigningCredentialsProvider _signingProvider;
    private readonly IConfiguration _config;

    public TokenExchangeEndpoint(ISigningCredentialsProvider signingProvider, IConfiguration config)
    {
        _signingProvider = signingProvider;
        _config = config;
    }

    public override void Configure()
    {
        Post("/exchange"); // e.g., /exchange with product Bearer token
        RequireAuthorization("ProductTokenScheme"); // Validates incoming product token
    }

    public override async Task HandleAsync(NoRequest req, CancellationToken ct)
    {
        // Claims already extracted from product token via handler
        var subscriberId = this.User.FindFirst("subscriberId")?.Value;
        if (string.IsNullOrEmpty(subscriberId))
        {
            ThrowError(401, "Invalid product token claims");
            return;
        }

        // Build new claims from product token claims
        var newClaims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, subscriberId),
            this.User.FindFirst("sponsorId")!, // Copy over
            this.User.FindFirst("businessUserId")!,
            new("permissions", string.Join(",", this.User.FindAll("permissions").Select(c => c.Value))) // Flatten
        };

        // Sign new token (only here—using your RSA)
        var signingCredentials = new SigningCredentials(_signingProvider.Rsa, SecurityAlgorithms.RsaSha256);

        var newToken = new JwtSecurityToken(
            issuer: _config["App:Issuer"] ?? "https://your-app.com",
            audience: _config["App:Audience"] ?? "your-internal-api",
            claims: newClaims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(30), // Short-lived
            signingCredentials: signingCredentials);

        var tokenHandler = new JwtSecurityTokenHandler();
        var newTokenString = tokenHandler.WriteToken(newToken);

        // Optional: Cache new principal if needed
        var cache = HttpContext.RequestServices.GetRequiredService<IDistributedCache>();
        var newPrincipal = new ClaimsPrincipal(new ClaimsIdentity(newClaims, "new-token"));
        var cacheKey = $"new-token:{subscriberId}";
        await cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(newPrincipal), new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30) }, ct);

        await SendOkAsync(new { Token = newTokenString, ExpiresAt = newToken.ValidTo });
    }
}

// 4. Using the New Token in Downstream Endpoints
// For endpoints using the new token, add a separate scheme if needed (e.g., AddJwtBearer for your app's issuer/keys). 
// But if self-validating, extend the handler or use the same custom one.
// public class SecureEndpoint : Endpoint<NoRequest>
// {
//     public override void Configure()
//     {
//         Get("/api/secure");
//         RequireAuthorization(); // Or specify scheme for new token
//         Permissions("moneyIn:Read");
//     }

//     public override async Task HandleAsync(NoRequest req, CancellationToken ct)
//     {
//         var subscriberId = this.User.FindFirst("subscriberId")?.Value;
//         await SendOkAsync(new { Message = $"Access granted for {subscriberId}" });
//     }
// }

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class TokenExchangeEndpoint : Endpoint<NoRequest>
{
    private readonly ISigningCredentialsProvider _signingProvider;
    private readonly IRefreshTokenService _refreshService;
    private readonly IConfiguration _config;

    public TokenExchangeEndpoint(ISigningCredentialsProvider signingProvider, IRefreshTokenService refreshService, IConfiguration config)
    {
        _signingProvider = signingProvider;
        _refreshService = refreshService;
        _config = config;
    }

    public override void Configure()
    {
        Post("/exchange");
        RequireAuthorization("ProductTokenScheme"); // Validates product token
    }

    public override async Task HandleAsync(NoRequest req, CancellationToken ct)
    {
        var subscriberId = this.User.FindFirst("subscriberId")?.Value;
        if (string.IsNullOrEmpty(subscriberId))
        {
            ThrowError(401, "Invalid product token claims");
            return;
        }

        // Build access token claims from product token
        var accessClaims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, subscriberId),
            this.User.FindFirst("sponsorId")!,
            this.User.FindFirst("businessUserId")!,
            new("permissions", string.Join(",", this.User.FindAll("permissions").Select(c => c.Value)))
        };

        // Sign access token
        var signingCredentials = new SigningCredentials(_signingProvider.Rsa, SecurityAlgorithms.RsaSha256);
        var accessToken = new JwtSecurityToken(
            issuer: _config["App:Issuer"] ?? "https://your-app.com",
            audience: _config["App:Audience"] ?? "your-internal-api",
            claims: accessClaims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: signingCredentials);

        var tokenHandler = new JwtSecurityTokenHandler();
        var accessTokenString = tokenHandler.WriteToken(accessToken);

        // Generate and store refresh token
        var refreshToken = await _refreshService.GenerateAndStoreAsync(subscriberId, ct);

        // Cache access principal if needed (as before)
        var cache = HttpContext.RequestServices.GetRequiredService<IDistributedCache>();
        var accessPrincipal = new ClaimsPrincipal(new ClaimsIdentity(accessClaims, "access"));
        var accessCacheKey = $"access:{subscriberId}";
        await cache.SetStringAsync(accessCacheKey, JsonSerializer.Serialize(accessPrincipal),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30) }, ct);

        await SendOkAsync(new
        {
            access_token = accessTokenString,
            token_type = "Bearer",
            expires_in = 1800, // 30 min in seconds
            refresh_token = refreshToken
        });
    }
}

// 4. New /renew Endpoint: Renew Access Token with Refresh
// Validates refresh token, issues new access token, rotates refresh.

public class TokenRenewEndpoint : Endpoint<TokenRenewRequest>
{
    private readonly ISigningCredentialsProvider _signingProvider;
    private readonly IRefreshTokenService _refreshService;
    private readonly IConfiguration _config;
    private readonly IDistributedCache _cache;

    public TokenRenewEndpoint(ISigningCredentialsProvider signingProvider, IRefreshTokenService refreshService,
        IConfiguration config, IDistributedCache cache)
    {
        _signingProvider = signingProvider;
        _refreshService = refreshService;
        _config = config;
        _cache = cache;
    }

    public override void Configure()
    {
        Post("/renew");
        AllowAnonymous(); // Refresh tokens sent in body, not Bearer
    }

    public override async Task HandleAsync(TokenRenewRequest req, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(req.RefreshToken))
        {
            ThrowError(400, "Refresh token required");
            return;
        }

        // Decode access token to get subscriberId (or send it in request)
        var tokenHandler = new JwtSecurityTokenHandler();
        if (!tokenHandler.CanReadToken(req.AccessToken) ||
            tokenHandler.ReadJwtToken(req.AccessToken).Claims.FirstOrDefault(c => c.Type == "subscriberId") is not Claim subClaim)
        {
            ThrowError(401, "Invalid access token");
            return;
        }

        var subscriberId = subClaim.Value;

        // Validate and rotate refresh token
        var (isValid, newRefreshToken) = await _refreshService.ValidateAndRenewAsync(req.RefreshToken, subscriberId, ct);
        if (!isValid)
        {
            await _refreshService.RevokeAsync(subscriberId, ct); // Cleanup
            ThrowError(401, "Invalid refresh token");
            return;
        }

        // Get cached claims or rebuild from access token
        var cachedJson = await _cache.GetStringAsync($"access:{subscriberId}", ct);
        var accessClaims = !string.IsNullOrEmpty(cachedJson)
            ? JsonSerializer.Deserialize<List<Claim>>(cachedJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            : tokenHandler.ReadJwtToken(req.AccessToken).Claims.ToList();

        // Sign new access token (same claims)
        var signingCredentials = new SigningCredentials(_signingProvider.Rsa, SecurityAlgorithms.RsaSha256);
        var newAccessToken = new JwtSecurityToken(
            issuer: _config["App:Issuer"] ?? "https://your-app.com",
            audience: _config["App:Audience"] ?? "your-internal-api",
            claims: accessClaims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: signingCredentials);

        var newAccessTokenString = tokenHandler.WriteToken(newAccessToken);

        // Update cache
        await _cache.SetStringAsync($"access:{subscriberId}", JsonSerializer.Serialize(accessClaims),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30) }, ct);

        await SendOkAsync(new
        {
            access_token = newAccessTokenString,
            token_type = "Bearer",
            expires_in = 1800,
            refresh_token = newRefreshToken // Rotated
        });
    }
}
public record TokenRenewRequest
{
    public string AccessToken { get; init; } = string.Empty; // For subscriberId extraction
    public string RefreshToken { get; init; } = string.Empty;
}

// var accessExpiry = tokenHandler.ReadJwtToken(req.AccessToken).ValidTo;
// if (DateTime.UtcNow > accessExpiry.AddMinutes(10))
// {
//     ThrowError(400, "Renewal window expired");
//     return;
// }
// // Proceed with validation/rotation