using Microsoft.IdentityModel.Tokens;
class Auth {
 void Configure(JwtBearerOptions options, SecurityKey signingKey) {
  options.TokenValidationParameters = new TokenValidationParameters { RequireSignedTokens = true, ValidateIssuer = true, ValidateAudience = true, ValidateLifetime = true, ValidateIssuerSigningKey = true, IssuerSigningKey = signingKey, ValidIssuer = "https://issuer.example", ValidAudience = "files-api" };
 }
}
