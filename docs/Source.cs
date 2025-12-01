using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMemoryCache(); // For your custom principal caching

// Load Ping config from appsettings.json or AKV (add to Key Vault if sensitive)
var keyVaultEndpoint = new Uri("https://your-keyvault-name.vault.azure.net/");
builder.Configuration.AddAzureKeyVault(keyVaultEndpoint, new DefaultAzureCredential());

// Ping-specific config (example from appsettings.json: "Ping": { "Issuer": "https://your-ping-domain.com/as/openauthnserver", "Audience": "your-api-audience" })
var pingIssuer = builder.Configuration["Ping:Issuer"] ?? throw new InvalidOperationException("Ping Issuer not configured.");
var pingAudience = builder.Configuration["Ping:Audience"];

// Register RSA private key from AKV as singleton for signing
builder.Services.AddSingleton(async provider =>
{
    var keyClient = new KeyClient(new Uri("https://your-keyvault-name.vault.azure.net/"), new DefaultAzureCredential());
    var keyVaultKey = await keyClient.GetKeyAsync("your-rsa-key-name"); // Key name in AKV
    var rsa = keyVaultKey.Value.Key as RSA;
    if (rsa == null) throw new InvalidOperationException("RSA key not found in AKV.");

    return new RsaSecurityKey(rsa)
    {
        KeyId = keyVaultKey.Value.KeyId // Matches public key ID in Ping
    };
}).As<ISigningKeyProvider>(); // Custom interface: public interface ISigningKeyProvider { /* the RsaSecurityKey */ }

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = pingIssuer; // Ping issuer URL; auto-fetches JWKS for public keys
        options.Audience = pingAudience;
        options.RequireHttpsMetadata = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true, // Validates against Ping's public keys
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        // Your custom caching after validation (unchanged)
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var cache = context.HttpContext.RequestServices.GetRequiredService<IMemoryCache>();
                var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
                var cacheEntryOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(50),
                    SlidingExpiration = TimeSpan.FromMinutes(5)
                };
                cache.Set($"auth:{userId}", context.Principal, cacheEntryOptions);
            },
            OnAuthenticationFailed = context =>
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync("{\"error\":\"Invalid token from Ping\"}");
            }
        };
    })
    .AddAuthorization()
    .AddFastEndpoints();

var app = builder.Build();

app.UseAuthentication()
   .UseAuthorization()
   .UseFastEndpoints();

app.Run();