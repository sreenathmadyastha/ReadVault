using NUnit.Framework;
using System;
using System.Threading.Tasks;
using Moq;

namespace OAuthTests
{
    [TestFixture]
    public class OAuthTokenTests
    {
        private Mock<ITokenService> _mockTokenService;
        private Mock<ITokenRepository> _mockTokenRepository;
        private OAuthService _oauthService;
        private const int ACCESS_TOKEN_EXPIRY_MINUTES = 10;

        [SetUp]
        public void Setup()
        {
            _mockTokenService = new Mock<ITokenService>();
            _mockTokenRepository = new Mock<ITokenRepository>();
            _oauthService = new OAuthService(_mockTokenService.Object, _mockTokenRepository.Object);
        }

        #region Initial Token Generation Tests

        [Test]
        public async Task TC001_FirstTimeTokenRequest_ShouldGenerateNewTokens()
        {
            // Arrange
            var userId = "user123";
            var credentials = new UserCredentials { Username = "testuser", Password = "password123" };
            
            _mockTokenService.Setup(x => x.ValidateCredentials(credentials))
                .ReturnsAsync(true);
            _mockTokenService.Setup(x => x.GenerateAccessToken(userId))
                .Returns(new AccessToken { Token = "access_token_123", ExpiresAt = DateTime.UtcNow.AddMinutes(10) });
            _mockTokenService.Setup(x => x.GenerateRefreshToken(userId))
                .Returns(new RefreshToken { Token = "refresh_token_123" });

            // Act
            var result = await _oauthService.AuthenticateAsync(credentials);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.AccessToken);
            Assert.IsNotNull(result.RefreshToken);
            Assert.AreEqual("access_token_123", result.AccessToken.Token);
            Assert.AreEqual("refresh_token_123", result.RefreshToken.Token);
            _mockTokenRepository.Verify(x => x.StoreTokensAsync(It.IsAny<string>(), It.IsAny<TokenPair>()), Times.Once);
        }

        [Test]
        public async Task TC002_InvalidCredentials_ShouldReturnUnauthorized()
        {
            // Arrange
            var credentials = new UserCredentials { Username = "testuser", Password = "wrongpassword" };
            
            _mockTokenService.Setup(x => x.ValidateCredentials(credentials))
                .ReturnsAsync(false);

            // Act & Assert
            var ex = Assert.ThrowsAsync<UnauthorizedException>(
                async () => await _oauthService.AuthenticateAsync(credentials)
            );
            Assert.That(ex.Message, Does.Contain("Invalid credentials"));
            _mockTokenRepository.Verify(x => x.StoreTokensAsync(It.IsAny<string>(), It.IsAny<TokenPair>()), Times.Never);
        }

        #endregion

        #region Access Token Validation Tests

        [Test]
        public async Task TC003_ValidAccessTokenRequest_ShouldReturnExistingToken()
        {
            // Arrange
            var userId = "user123";
            var existingToken = new AccessToken 
            { 
                Token = "existing_access_token",
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                IssuedAt = DateTime.UtcNow.AddMinutes(-5)
            };

            _mockTokenRepository.Setup(x => x.GetAccessTokenAsync(userId))
                .ReturnsAsync(existingToken);
            _mockTokenService.Setup(x => x.IsTokenValid(existingToken))
                .Returns(true);

            // Act
            var result = await _oauthService.GetAccessTokenAsync(userId);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("existing_access_token", result.Token);
            Assert.AreEqual(existingToken.ExpiresAt, result.ExpiresAt);
            _mockTokenService.Verify(x => x.GenerateAccessToken(It.IsAny<string>()), Times.Never);
        }

        [Test]
        public async Task TC004_ExpiredAccessToken_ShouldReturnUnauthorized()
        {
            // Arrange
            var expiredToken = "expired_token_123";
            var token = new AccessToken 
            { 
                Token = expiredToken,
                ExpiresAt = DateTime.UtcNow.AddMinutes(-1)
            };

            _mockTokenService.Setup(x => x.ValidateAccessToken(expiredToken))
                .Returns(token);
            _mockTokenService.Setup(x => x.IsTokenValid(token))
                .Returns(false);

            // Act & Assert
            var ex = Assert.ThrowsAsync<TokenExpiredException>(
                async () => await _oauthService.ValidateAccessTokenAsync(expiredToken)
            );
            Assert.That(ex.Message, Does.Contain("expired"));
        }

        [Test]
        public void TC005_MalformedAccessToken_ShouldReturnUnauthorized()
        {
            // Arrange
            var malformedToken = "invalid.malformed.token";
            
            _mockTokenService.Setup(x => x.ValidateAccessToken(malformedToken))
                .Throws(new InvalidTokenFormatException("Invalid token format"));

            // Act & Assert
            var ex = Assert.ThrowsAsync<InvalidTokenFormatException>(
                async () => await _oauthService.ValidateAccessTokenAsync(malformedToken)
            );
            Assert.That(ex.Message, Does.Contain("Invalid token format"));
        }

        [Test]
        public async Task TC006_AccessTokenAtExactBoundary_ShouldBeExpired()
        {
            // Arrange
            var boundaryToken = new AccessToken 
            { 
                Token = "boundary_token",
                ExpiresAt = DateTime.UtcNow,
                IssuedAt = DateTime.UtcNow.AddMinutes(-10)
            };

            _mockTokenService.Setup(x => x.ValidateAccessToken(boundaryToken.Token))
                .Returns(boundaryToken);
            _mockTokenService.Setup(x => x.IsTokenValid(boundaryToken))
                .Returns(false);

            // Act & Assert
            var ex = Assert.ThrowsAsync<TokenExpiredException>(
                async () => await _oauthService.ValidateAccessTokenAsync(boundaryToken.Token)
            );
        }

        [Test]
        public async Task TC007_AccessTokenJustBeforeExpiry_ShouldBeValid()
        {
            // Arrange
            var almostExpiredToken = new AccessToken 
            { 
                Token = "almost_expired_token",
                ExpiresAt = DateTime.UtcNow.AddSeconds(1),
                IssuedAt = DateTime.UtcNow.AddMinutes(-10).AddSeconds(1)
            };

            _mockTokenService.Setup(x => x.ValidateAccessToken(almostExpiredToken.Token))
                .Returns(almostExpiredToken);
            _mockTokenService.Setup(x => x.IsTokenValid(almostExpiredToken))
                .Returns(true);

            // Act
            var result = await _oauthService.ValidateAccessTokenAsync(almostExpiredToken.Token);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.IsValid);
            Assert.IsTrue(result.TimeToExpiry.TotalSeconds <= 1);
        }

        #endregion

        #region Refresh Token Tests

        [Test]
        public async Task TC008_ValidRefreshToken_ShouldGenerateNewAccessToken()
        {
            // Arrange
            var userId = "user123";
            var refreshToken = "valid_refresh_token";
            var newAccessToken = new AccessToken 
            { 
                Token = "new_access_token",
                ExpiresAt = DateTime.UtcNow.AddMinutes(10)
            };

            _mockTokenService.Setup(x => x.ValidateRefreshToken(refreshToken))
                .ReturnsAsync((true, userId));
            _mockTokenService.Setup(x => x.GenerateAccessToken(userId))
                .Returns(newAccessToken);

            // Act
            var result = await _oauthService.RefreshAccessTokenAsync(refreshToken);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("new_access_token", result.AccessToken.Token);
            Assert.AreEqual(refreshToken, result.RefreshToken.Token);
            _mockTokenRepository.Verify(x => x.UpdateAccessTokenAsync(userId, newAccessToken), Times.Once);
        }

        [Test]
        public async Task TC009_RefreshTokenRotation_ShouldGenerateNewRefreshToken()
        {
            // Arrange
            var userId = "user123";
            var oldRefreshToken = "old_refresh_token";
            var newAccessToken = new AccessToken { Token = "new_access_token", ExpiresAt = DateTime.UtcNow.AddMinutes(10) };
            var newRefreshToken = new RefreshToken { Token = "new_refresh_token" };

            _mockTokenService.Setup(x => x.ValidateRefreshToken(oldRefreshToken))
                .ReturnsAsync((true, userId));
            _mockTokenService.Setup(x => x.GenerateAccessToken(userId))
                .Returns(newAccessToken);
            _mockTokenService.Setup(x => x.GenerateRefreshToken(userId))
                .Returns(newRefreshToken);
            _mockTokenService.Setup(x => x.IsRefreshTokenRotationEnabled())
                .Returns(true);

            // Act
            var result = await _oauthService.RefreshAccessTokenAsync(oldRefreshToken, rotateRefreshToken: true);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("new_access_token", result.AccessToken.Token);
            Assert.AreEqual("new_refresh_token", result.RefreshToken.Token);
            _mockTokenRepository.Verify(x => x.InvalidateRefreshTokenAsync(oldRefreshToken), Times.Once);
        }

        [Test]
        public async Task TC010_InvalidRefreshToken_ShouldReturnUnauthorized()
        {
            // Arrange
            var invalidRefreshToken = "invalid_refresh_token";
            
            _mockTokenService.Setup(x => x.ValidateRefreshToken(invalidRefreshToken))
                .ReturnsAsync((false, null));

            // Act & Assert
            var ex = Assert.ThrowsAsync<UnauthorizedException>(
                async () => await _oauthService.RefreshAccessTokenAsync(invalidRefreshToken)
            );
            Assert.That(ex.Message, Does.Contain("Invalid refresh token"));
        }

        [Test]
        public async Task TC011_ExpiredRefreshToken_ShouldRequireReauthentication()
        {
            // Arrange
            var expiredRefreshToken = "expired_refresh_token";
            
            _mockTokenService.Setup(x => x.ValidateRefreshToken(expiredRefreshToken))
                .ThrowsAsync(new TokenExpiredException("Refresh token expired"));

            // Act & Assert
            var ex = Assert.ThrowsAsync<TokenExpiredException>(
                async () => await _oauthService.RefreshAccessTokenAsync(expiredRefreshToken)
            );
            Assert.That(ex.Message, Does.Contain("expired"));
        }

        [Test]
        public async Task TC012_ReuseOldRefreshToken_ShouldInvalidateAllTokens()
        {
            // Arrange
            var userId = "user123";
            var reusedRefreshToken = "reused_refresh_token";
            
            _mockTokenRepository.Setup(x => x.IsRefreshTokenInvalidated(reusedRefreshToken))
                .ReturnsAsync(true);

            // Act & Assert
            var ex = Assert.ThrowsAsync<SecurityException>(
                async () => await _oauthService.RefreshAccessTokenAsync(reusedRefreshToken)
            );
            Assert.That(ex.Message, Does.Contain("token theft"));
            _mockTokenRepository.Verify(x => x.InvalidateAllUserTokensAsync(It.IsAny<string>()), Times.Once);
        }

        #endregion

        #region Concurrent Request Tests

        [Test]
        public async Task TC013_MultipleSimultaneousValidTokenRequests_ShouldSucceed()
        {
            // Arrange
            var userId = "user123";
            var validToken = new AccessToken 
            { 
                Token = "valid_token",
                ExpiresAt = DateTime.UtcNow.AddMinutes(5)
            };

            _mockTokenRepository.Setup(x => x.GetAccessTokenAsync(userId))
                .ReturnsAsync(validToken);
            _mockTokenService.Setup(x => x.IsTokenValid(validToken))
                .Returns(true);

            // Act
            var tasks = new Task<AccessToken>[5];
            for (int i = 0; i < 5; i++)
            {
                tasks[i] = _oauthService.GetAccessTokenAsync(userId);
            }
            var results = await Task.WhenAll(tasks);

            // Assert
            Assert.AreEqual(5, results.Length);
            Assert.That(results, Has.All.Property("Token").EqualTo("valid_token"));
        }

        [Test]
        public async Task TC014_ConcurrentRefreshTokenRequests_ShouldHandleRaceCondition()
        {
            // Arrange
            var userId = "user123";
            var refreshToken = "concurrent_refresh_token";
            var accessToken = new AccessToken { Token = "new_token", ExpiresAt = DateTime.UtcNow.AddMinutes(10) };
            
            var callCount = 0;
            _mockTokenService.Setup(x => x.ValidateRefreshToken(refreshToken))
                .ReturnsAsync(() => 
                {
                    callCount++;
                    return callCount == 1 ? (true, userId) : (false, null);
                });
            _mockTokenService.Setup(x => x.GenerateAccessToken(userId))
                .Returns(accessToken);

            // Act
            var task1 = _oauthService.RefreshAccessTokenAsync(refreshToken);
            var task2 = _oauthService.RefreshAccessTokenAsync(refreshToken);

            // Assert
            var result1 = await task1;
            Assert.ThrowsAsync<UnauthorizedException>(async () => await task2);
        }

        #endregion

        #region Edge Cases & Security Tests

        [Test]
        public void TC017_MissingToken_ShouldReturnUnauthorized()
        {
            // Arrange
            string nullToken = null;

            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(
                async () => await _oauthService.ValidateAccessTokenAsync(nullToken)
            );
        }

        [Test]
        public async Task TC018_TokenFromDifferentUser_ShouldReturnForbidden()
        {
            // Arrange
            var requestingUserId = "user123";
            var tokenUserId = "user456";
            var token = "token_for_different_user";

            _mockTokenService.Setup(x => x.ValidateAccessToken(token))
                .Returns(new AccessToken { Token = token, UserId = tokenUserId });

            // Act & Assert
            var ex = Assert.ThrowsAsync<ForbiddenException>(
                async () => await _oauthService.ValidateAccessTokenAsync(token, requestingUserId)
            );
            Assert.That(ex.Message, Does.Contain("not authorized"));
        }

        [Test]
        public async Task TC019_RevokedToken_ShouldReturnUnauthorized()
        {
            // Arrange
            var revokedToken = "revoked_token";
            
            _mockTokenRepository.Setup(x => x.IsTokenRevoked(revokedToken))
                .ReturnsAsync(true);

            // Act & Assert
            var ex = Assert.ThrowsAsync<TokenRevokedException>(
                async () => await _oauthService.ValidateAccessTokenAsync(revokedToken)
            );
            Assert.That(ex.Message, Does.Contain("revoked"));
        }

        [Test]
        public async Task TC020_TokenAfterPasswordChange_ShouldBeInvalidated()
        {
            // Arrange
            var userId = "user123";
            var token = "token_before_password_change";
            var passwordChangedAt = DateTime.UtcNow;
            var tokenIssuedAt = DateTime.UtcNow.AddMinutes(-5);

            _mockTokenRepository.Setup(x => x.GetPasswordChangedAtAsync(userId))
                .ReturnsAsync(passwordChangedAt);
            _mockTokenService.Setup(x => x.ValidateAccessToken(token))
                .Returns(new AccessToken { Token = token, UserId = userId, IssuedAt = tokenIssuedAt });

            // Act & Assert
            var ex = Assert.ThrowsAsync<TokenRevokedException>(
                async () => await _oauthService.ValidateAccessTokenAsync(token)
            );
            Assert.That(ex.Message, Does.Contain("password change"));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("   ")]
        public void TC021_NullOrEmptyToken_ShouldReturnBadRequest(string invalidToken)
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(
                async () => await _oauthService.ValidateAccessTokenAsync(invalidToken)
            );
        }

        #endregion

        #region Time-based Edge Cases

        [Test]
        public async Task TC024_SystemClockChanges_ShouldHandleGracefully()
        {
            // Arrange
            var token = new AccessToken 
            { 
                Token = "time_sensitive_token",
                IssuedAt = DateTime.UtcNow.AddMinutes(-5),
                ExpiresAt = DateTime.UtcNow.AddMinutes(5)
            };

            _mockTokenService.Setup(x => x.ValidateAccessToken(token.Token))
                .Returns(token);
            _mockTokenService.Setup(x => x.IsTokenValid(token))
                .Returns((AccessToken t) => t.ExpiresAt > DateTime.UtcNow);

            // Act
            var result = await _oauthService.ValidateAccessTokenAsync(token.Token);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.IsValid);
        }

        [Test]
        public async Task TC025_TokenIssuedAtMidnight_ShouldCalculateExpiryCorrectly()
        {
            // Arrange
            var midnightIssuedToken = new AccessToken 
            { 
                Token = "midnight_token",
                IssuedAt = DateTime.UtcNow.Date,
                ExpiresAt = DateTime.UtcNow.Date.AddMinutes(10)
            };

            _mockTokenService.Setup(x => x.GenerateAccessToken(It.IsAny<string>()))
                .Returns(midnightIssuedToken);

            // Act
            var userId = "user123";
            var result = _mockTokenService.Object.GenerateAccessToken(userId);

            // Assert
            Assert.AreEqual(10, (result.ExpiresAt - result.IssuedAt).TotalMinutes);
        }

        #endregion

        [TearDown]
        public void TearDown()
        {
            _mockTokenService = null;
            _mockTokenRepository = null;
            _oauthService = null;
        }
    }

    #region Mock Interfaces and Classes (For reference - create these in your actual project)

    public interface ITokenService
    {
        Task<bool> ValidateCredentials(UserCredentials credentials);
        AccessToken GenerateAccessToken(string userId);
        RefreshToken GenerateRefreshToken(string userId);
        bool IsTokenValid(AccessToken token);
        AccessToken ValidateAccessToken(string token);
        Task<(bool isValid, string userId)> ValidateRefreshToken(string refreshToken);
        bool IsRefreshTokenRotationEnabled();
    }

    public interface ITokenRepository
    {
        Task StoreTokensAsync(string userId, TokenPair tokens);
        Task<AccessToken> GetAccessTokenAsync(string userId);
        Task UpdateAccessTokenAsync(string userId, AccessToken token);
        Task InvalidateRefreshTokenAsync(string refreshToken);
        Task<bool> IsRefreshTokenInvalidated(string refreshToken);
        Task InvalidateAllUserTokensAsync(string userId);
        Task<bool> IsTokenRevoked(string token);
        Task<DateTime?> GetPasswordChangedAtAsync(string userId);
    }

    public class OAuthService
    {
        private readonly ITokenService _tokenService;
        private readonly ITokenRepository _tokenRepository;

        public OAuthService(ITokenService tokenService, ITokenRepository tokenRepository)
        {
            _tokenService = tokenService;
            _tokenRepository = tokenRepository;
        }

        public Task<TokenPair> AuthenticateAsync(UserCredentials credentials) => throw new NotImplementedException();
        public Task<AccessToken> GetAccessTokenAsync(string userId) => throw new NotImplementedException();
        public Task<ValidationResult> ValidateAccessTokenAsync(string token, string requestingUserId = null) => throw new NotImplementedException();
        public Task<TokenPair> RefreshAccessTokenAsync(string refreshToken, bool rotateRefreshToken = false) => throw new NotImplementedException();
    }

    public class UserCredentials
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class AccessToken
    {
        public string Token { get; set; }
        public DateTime ExpiresAt { get; set; }
        public DateTime IssuedAt { get; set; }
        public string UserId { get; set; }
    }

    public class RefreshToken
    {
        public string Token { get; set; }
    }

    public class TokenPair
    {
        public AccessToken AccessToken { get; set; }
        public RefreshToken RefreshToken { get; set; }
    }

    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public TimeSpan TimeToExpiry { get; set; }
    }

    public class UnauthorizedException : Exception
    {
        public UnauthorizedException(string message) : base(message) { }
    }

    public class TokenExpiredException : Exception
    {
        public TokenExpiredException(string message) : base(message) { }
    }

    public class InvalidTokenFormatException : Exception
    {
        public InvalidTokenFormatException(string message) : base(message) { }
    }

    public class SecurityException : Exception
    {
        public SecurityException(string message) : base(message) { }
    }

    public class ForbiddenException : Exception
    {
        public ForbiddenException(string message) : base(message) { }
    }

    public class TokenRevokedException : Exception
    {
        public TokenRevokedException(string message) : base(message) { }
    }

    #endregion
}