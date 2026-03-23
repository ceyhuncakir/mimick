# Reporting Rules

Report quality directly impacts payout. Triagers are busy. Make their job easy.

---

## 1. NEVER USE THEORETICAL LANGUAGE

```
NEVER: "could potentially allow"
NEVER: "may allow an attacker to"
NEVER: "might be possible"
NEVER: "could lead to"
NEVER: "could be chained with X to cause Y"

ALWAYS: "An attacker can [exact action] by [exact method]"
```

If you can't write a concrete statement, you don't have a bug yet. Kill the finding.

## 2. RUN 7-QUESTION GATE BEFORE WRITING

Every finding must pass ALL 7 questions before you spend time on a report:

1. Is this in scope?
2. Can it be exploited right now?
3. Does it affect a real user?
4. Is the impact more than trivial?
5. Can I prove it?
6. Is it a duplicate of something I already reported?
7. Would a triage team accept this?

One NO = kill the finding immediately. N/A hurts your validity ratio more than missing a bug.

## 3. ALWAYS INCLUDE PROOF OF CONCEPT

Minimum bar per bug class:
- **IDOR** → show victim's actual data in the response (not just 200 OK)
- **XSS** → show actual cookie exfil (not just `alert(document.domain)`)
- **SSRF** → show actual internal service response (not just DNS callback)
- **SQLi** → show actual database content (not just error message)

A "technically possible" finding without PoC is Informational at best.

## 4. CVSS MUST MATCH ACTUAL IMPACT

Don't claim Critical for a Medium bug. Triagers trust you less for every overclaim.
Don't claim Medium for a Critical — you're leaving money on the table.

Use the CVSS 3.1 formula. Common scoring:
- IDOR read PII (auth required): 6.5 Medium
- Auth bypass → admin: 9.8 Critical
- SSRF → cloud metadata: 9.1 Critical

## 5. NEVER SUBMIT FROM THE ALWAYS-REJECTED LIST

These are always N/A. Never submit them standalone:

- Missing headers (CSP, HSTS, X-Frame-Options)
- GraphQL introspection alone
- Self-XSS
- Open redirect alone
- SSRF DNS-only
- Logout CSRF
- Missing cookie flags alone
- Rate limit on non-critical forms
- Banner/version disclosure without working exploit

Build the chain first. Prove it works. Then report.

## 6. VERIFY DATA ISN'T ALREADY PUBLIC

Before submitting an information disclosure finding:
1. Request the same endpoint without authentication.
2. Can you see the same data without auth?
3. If yes → not a bug.

## 7. TWO TEST ACCOUNTS FOR IDOR

Never test IDOR with only one account.
- Account A = attacker (your account doing the request)
- Account B = victim (whose data you're reading)

Report must show: "I sent request with Account A's token but Account B's ID, and received Account B's private data."

## 8. TITLE FORMULA — NEVER DEVIATE

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [scope]
```

Good:
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice
Missing auth on POST /api/admin/users allows unauthenticated creation of admin accounts
Stored XSS in profile bio field executes in admin panel — privilege escalation possible
```

Bad (never use):
```
IDOR vulnerability found
Security issue in API
XSS in user input
```

## 9. UNDER 600 WORDS PER FINDING

Structure each finding tightly:
- Sentence 1: What attacker can do (impact)
- Sentence 2-3: How (endpoint, parameter, method)
- Steps to reproduce: numbered, with exact HTTP request
- Impact: one paragraph, quantified
- Fix: 1-2 sentences

## 10. ESCALATION LANGUAGE (WHEN JUSTIFYING SEVERITY)

Use these when the impact is real:
```
"This requires only a free account — no special privileges."
"The data includes [PII type], subject to GDPR/CCPA requirements."
"An attacker can automate this — all [N] records in minutes."
"This is externally exploitable with no internal access required."
"Impact equivalent to a full breach of [feature/data type]."
```

## 11. SEPARATE BUGS = SEPARATE FINDINGS

If A and B are independent bugs (different endpoints, different impact):
- Report them as SEPARATE findings via separate `report_finding` calls.
- Only combine if they are part of ONE attack chain that requires both.

## 12. REPORT FORMAT (FINAL OUTPUT)

Use this exact structure for the final report:

### Summary
One paragraph: target, scope, what was tested, overall risk assessment.

### Findings
For each finding (ordered by severity, Critical → Info):

#### [SEVERITY] [Title following the title formula from Rule 8]
- **CVSS:** [score] ([vector string])
- **URL/Endpoint:** exact URL
- **Description:** What the bug is. Concrete language only (Rule 1).
- **Proof of Concept:**
  Exact request/response, curl command, or script output proving exploitation.
  Must meet the minimum bar for its bug class (Rule 3).
- **Impact:** What an attacker achieves. Quantified. Use escalation language (Rule 10) where applicable.
- **Remediation:** How to fix it. 1-2 sentences.

### Recon Summary
Attack surface overview: subdomains, live hosts, tech stack, WAF, open ports.

### Methodology
Brief list of what was done in each phase.
