'use strict';
// OWASP Top 10:2025 — category metadata and CWE mappings.
// Source: https://owasp.org/Top10/2025/ (per-category "List of Mapped CWEs").

const CATEGORIES = {
  A01: {
    name: 'Broken Access Control',
    url: 'https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/',
    cwes: [22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379, 402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862, 863, 918, 922, 1275],
  },
  A02: {
    name: 'Security Misconfiguration',
    url: 'https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/',
    cwes: [5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174],
  },
  A03: {
    name: 'Software Supply Chain Failures',
    url: 'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
    cwes: [447, 1035, 1104, 1329, 1357, 1395],
  },
  A04: {
    name: 'Cryptographic Failures',
    url: 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/',
    cwes: [261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241],
  },
  A05: {
    name: 'Injection',
    url: 'https://owasp.org/Top10/2025/A05_2025-Injection/',
    cwes: [20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917],
  },
  A06: {
    name: 'Insecure Design',
    url: 'https://owasp.org/Top10/2025/A06_2025-Insecure_Design/',
    cwes: [73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454, 472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841, 1021, 1022, 1125],
  },
  A07: {
    name: 'Authentication Failures',
    url: 'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/',
    cwes: [258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305, 306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392, 1393],
  },
  A08: {
    name: 'Software or Data Integrity Failures',
    url: 'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
    cwes: [345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926],
  },
  A09: {
    name: 'Security Logging & Alerting Failures',
    url: 'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/',
    cwes: [117, 221, 223, 532, 778],
  },
  A10: {
    name: 'Mishandling of Exceptional Conditions',
    url: 'https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/',
    cwes: [209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756],
  },
};

// Short names for CWEs the rule packs reference (used in reports).
const CWE_NAMES = {
  20: 'Improper Input Validation', 22: 'Path Traversal', 59: 'Link Following', 78: 'OS Command Injection',
  77: 'Command Injection', 79: 'Cross-site Scripting', 88: 'Argument Injection', 89: 'SQL Injection', 90: 'LDAP Injection',
  93: 'CRLF Injection', 94: 'Code Injection', 95: 'Eval Injection', 98: 'PHP File Inclusion', 113: 'HTTP Response Splitting',
  116: 'Improper Output Encoding', 117: 'Log Injection', 200: 'Sensitive Information Exposure', 208: 'Observable Timing Discrepancy',
  209: 'Error Message Information Leak', 215: 'Sensitive Info in Debug Code', 250: 'Execution with Unnecessary Privileges',
  259: 'Hard-coded Password', 260: 'Password in Configuration File', 269: 'Improper Privilege Management',
  276: 'Incorrect Default Permissions', 285: 'Improper Authorization', 287: 'Improper Authentication', 295: 'Improper Certificate Validation',
  306: 'Missing Authentication for Critical Function', 307: 'Excessive Authentication Attempts', 312: 'Cleartext Storage of Sensitive Info',
  319: 'Cleartext Transmission', 321: 'Hard-coded Cryptographic Key', 326: 'Inadequate Encryption Strength',
  327: 'Broken or Risky Crypto Algorithm', 328: 'Weak Hash', 329: 'Predictable IV', 330: 'Insufficiently Random Values',
  338: 'Weak PRNG', 345: 'Insufficient Verification of Data Authenticity', 346: 'Origin Validation Error', 347: 'Improper Signature Verification',
  352: 'Cross-Site Request Forgery', 353: 'Missing Integrity Check', 377: 'Insecure Temporary File', 384: 'Session Fixation',
  390: 'Error Detected Without Action', 396: 'Catch Generic Exception', 427: 'Uncontrolled Search Path Element', 434: 'Unrestricted File Upload',
  451: 'UI Misrepresentation', 470: 'Unsafe Reflection', 489: 'Active Debug Code', 494: 'Download of Code Without Integrity Check',
  502: 'Deserialization of Untrusted Data', 506: 'Embedded Malicious Code', 521: 'Weak Password Requirements', 532: 'Sensitive Info in Log File',
  538: 'Sensitive Info in Accessible File', 540: 'Sensitive Info in Source Code', 548: 'Directory Listing', 601: 'Open Redirect',
  611: 'XML External Entity', 614: 'Cookie Without Secure', 617: 'Reachable Assertion', 639: 'Authorization Bypass via User-Controlled Key',
  643: 'XPath Injection', 676: 'Use of Potentially Dangerous Function', 697: 'Incorrect Comparison', 703: 'Improper Exceptional Condition Handling',
  732: 'Incorrect Permission Assignment', 754: 'Improper Check for Unusual Conditions', 776: 'XML Entity Expansion', 798: 'Hard-coded Credentials',
  829: 'Inclusion from Untrusted Control Sphere', 830: 'Web Functionality from Untrusted Source', 862: 'Missing Authorization',
  915: 'Mass Assignment / Dynamic Attribute Modification', 916: 'Weak Password Hash', 917: 'Expression Language Injection',
  918: 'Server-Side Request Forgery', 922: 'Insecure Storage of Sensitive Info', 942: 'Permissive Cross-domain Policy',
  1004: 'Cookie Without HttpOnly', 1021: 'Clickjacking', 1022: 'window.opener Access', 1104: 'Unmaintained Third-Party Component',
  1275: 'Improper SameSite Cookie', 1321: 'Prototype Pollution', 1333: 'Regular Expression DoS', 1336: 'Server-Side Template Injection',
  1357: 'Insufficiently Trustworthy Component', 1395: 'Vulnerable Third-Party Component', 1007: 'Insufficient Visual Distinction of Homoglyphs',
};

// Other OWASP lists referenced by specific rules.
const EXTRA_REFS = {
  'LLM01:2025': { name: 'Prompt Injection', url: 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/' },
};

function cweLabel(id) {
  return `CWE-${id}${CWE_NAMES[id] ? ': ' + CWE_NAMES[id] : ''}`;
}

function categoryLabel(code) {
  const c = CATEGORIES[code];
  return c ? `${code}:2025 ${c.name}` : code;
}

module.exports = { CATEGORIES, CWE_NAMES, EXTRA_REFS, cweLabel, categoryLabel };
