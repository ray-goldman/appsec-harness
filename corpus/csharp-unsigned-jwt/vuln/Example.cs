using Microsoft.IdentityModel.Tokens;
class Auth {
 void Configure(JwtBearerOptions options) {
  options.TokenValidationParameters = new TokenValidationParameters { RequireSignedTokens = false, ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = false };
 }
}
