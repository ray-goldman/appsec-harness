'use strict';
const { configHits } = require('../dotnet-config');
const meta = {
  confidence: 'medium', severity: 'medium',
  appliesTo: rel => /(?:^|\/)(?:web|app)\.config$/i.test(rel),
};
// Settings are evidence to review, not proof of the effective deployed config.
module.exports = [
  {
    ...meta, id: 'NETCFG-DEBUG-001', title: 'ASP.NET debug compilation or remotely visible tracing enabled',
    owasp: 'A02', cwe: [489, 200], check: ({ raw }) => configHits(raw, 'debug'),
    message: 'Configuration explicitly enables debug compilation or tracing with localOnly=false. Check deployment transforms and inherited configuration.',
    fix: 'Disable debug compilation in production. Disable tracing or restrict it to local requests.',
    refs: ['https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/aspnet/performance/debug-mode-applications'],
  },
  {
    ...meta, id: 'NETCFG-ERR-001', title: 'Detailed ASP.NET, IIS or WCF errors enabled',
    owasp: 'A10', cwe: [209, 497], check: ({ raw }) => configHits(raw, 'errors'),
    message: 'Configuration explicitly enables detailed error or fault responses. These can disclose internal paths and exception details if active in deployment.',
    fix: 'Use customErrors RemoteOnly/On, IIS DetailedLocalOnly/Custom, and disable WCF includeExceptionDetailInFaults in production.',
    refs: ['https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httperrors/'],
  },
  {
    ...meta, id: 'NETCFG-COOKIE-001', title: 'ASP.NET cookie protection explicitly disabled',
    owasp: 'A02', cwe: [1004, 614], check: ({ raw }) => configHits(raw, 'cookies'),
    message: 'httpCookies explicitly disables HttpOnly or the SSL requirement. Check the effective settings of sensitive cookies.',
    fix: 'Set httpOnlyCookies and requireSSL to true for sensitive cookies and serve the application over HTTPS.',
    refs: ['https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.httpcookiessection'],
  },
  {
    ...meta, id: 'NETCFG-FORMS-001', title: 'ASP.NET forms or session configuration permits exposed tickets',
    owasp: 'A02', cwe: [614, 384], check: ({ raw }) => configHits(raw, 'forms'),
    message: 'Configuration explicitly permits forms tickets without SSL or session/ticket identifiers in URLs. Verify that these settings are active.',
    fix: 'Require SSL for forms authentication and use cookieless="UseCookies" for forms and session state.',
    refs: ['https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.formsauthenticationconfiguration'],
  },
  {
    ...meta, id: 'NETCFG-WCF-001', title: 'WCF binding explicitly disables security',
    owasp: 'A02', cwe: [319], check: ({ raw }) => configHits(raw, 'wcf'),
    message: 'A supported WCF binding sets security mode=None. Verify endpoint use and any external transport protection; anonymous clients alone do not imply unencrypted transport.',
    fix: 'Use the binding-appropriate transport or message security mode and validate the service identity.',
    refs: ['https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/transport-security-with-an-anonymous-client'],
  },
];
