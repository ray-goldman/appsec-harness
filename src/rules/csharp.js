'use strict';
const { requestReturns, passwordMd5, unsignedJwt } = require('../csharp-checks');
module.exports = [
  {
    id: 'CS-CMDI-002', title: 'Request parameter concatenated into a shell command in a controller action',
    owasp: 'A05', cwe: [78], severity: 'high', confidence: 'medium', languages: ['csharp'],
    checkCode: ctx => requestReturns('command', ctx),
    message: 'An explicitly bound request string is concatenated into a shell command in a supported straight-line controller action.',
    fix: 'Avoid shell wrappers; use ProcessStartInfo.ArgumentList with validated values.',
    refs: ['https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist'],
  },
  {
    id: 'CS-PATH-001', title: 'Request filename passed directly to PhysicalFile via Path.Combine',
    owasp: 'A01', cwe: [22], severity: 'high', confidence: 'medium', languages: ['csharp'],
    checkCode: ctx => requestReturns('path', ctx),
    message: 'A framework-bound string is combined with a base directory and returned without a visible containment check in the supported method body.',
    fix: 'Resolve the path and enforce directory containment before serving it; account for filesystem links.',
    refs: ['https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine'],
  },
  {
    id: 'CS-REDIRECT-001', title: 'Request parameter returned directly as a redirect destination',
    owasp: 'A01', cwe: [601], severity: 'medium', confidence: 'medium', languages: ['csharp'],
    checkCode: ctx => requestReturns('redirect', ctx),
    message: 'A framework-bound string reaches Redirect without validation in the supported method body.',
    fix: 'Use LocalRedirect or validate the destination with Url.IsLocalUrl and reject invalid values.',
    refs: ['https://learn.microsoft.com/en-us/aspnet/core/security/preventing-open-redirects'],
  },
  {
    id: 'CS-CRYPTO-001', title: 'MD5 hashes a password-named string parameter',
    owasp: 'A04', cwe: [327], severity: 'high', confidence: 'medium', languages: ['csharp'],
    checkCode: passwordMd5,
    message: 'MD5 directly hashes a parameter named pw, password or passwd. Verify that this is password storage or verification; parameter naming is a heuristic.',
    fix: 'Use a password hasher with a unique salt and suitable work factor, such as ASP.NET Core PasswordHasher.',
    refs: ['https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5351'],
  },
  {
    id: 'CS-JWT-001', title: 'Token validation parameters explicitly allow unsigned tokens',
    owasp: 'A07', cwe: [347], severity: 'high', confidence: 'medium', languages: ['csharp'],
    checkCode: unsignedJwt,
    message: 'RequireSignedTokens is explicitly false in a simple token-validation initializer. Verify how these options are used and whether later configuration overrides them.',
    fix: 'Require signed tokens and validate their signature, issuer, audience and lifetime.',
    refs: ['https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.requiresignedtokens'],
  },
];
