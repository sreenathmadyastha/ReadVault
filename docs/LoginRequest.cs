using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class LoginEndpoint : Endpoint<LoginRequest>
{
    private readonly ISigningKeyProvider _signingKeyProvider;
    private readonly IConfiguration _config;

    public LoginEndpoint(ISigningKeyProvider signingKeyProvider, IConfiguration config)
    {
        _signingKeyProvider = signingKeyProvider;
        _config = config;
    }

    public override void Configure()
    {
        Post("/login");
        AllowAnonymous();
    }

    public override async Task HandleAsync(LoginRequest req, CancellationToken ct)
    {
        // Validate credentials against corporate IdP (e.g., call Ping's token endpoint)
        // For demo: Assume validation passes; in reality, acquire Ping token first if needed
        if (!await ValidateCredentialsAsync(req.Username, req.Password, ct))
        {
            ThrowError("Invalid credentials");
            return;
        }

        // Create claims (from Ping user info or local)
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "user123"),
            new("CustomClaim", "some-value"),
            new(ClaimTypes.Role, "Admin"),
            new("permissions", "Read:Users,Write:Users")
        };

        var signingCredentials = new SigningCredentials(
            new RsaSecurityKey(_signingKeyProvider.Rsa) { KeyId = _signingKeyProvider.KeyId }, // Use AKV RSA
            SecurityAlgorithms.RsaSha256);

        var token = new JwtSecurityToken(
            issuer: _config["App:Issuer"] ?? "https://your-app.com", // Your app's issuer
            audience: _config["App:Audience"] ?? "your-app-audience",
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: signingCredentials);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        // Optionally cache the principal here too
        await SendOkAsync(new { Token = tokenString, ExpiresAt = token.ValidTo });
    }

    private async Task<bool> ValidateCredentialsAsync(string username, string password, CancellationToken ct)
    {
        // Integrate with Ping: e.g., POST to /as/token with client credentials or resource owner flow
        // Use HttpClient with client secret from AKV
        return true; // Placeholder
    }
}