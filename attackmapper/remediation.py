"""remediation.py — plain-English fix suggestions keyed by Finding
type. Purely informational (how to close a gap, never how to widen
one). Deliberately has no imports from anywhere else in the package,
so any layer (webapp, cli, a future report exporter) can look up a
remedy for a finding without creating a dependency cycle.
"""

from __future__ import annotations

REMEDIES: dict[str, str] = {
    "missing_security_headers": (
        "Add the missing headers at the web server or app-framework "
        "level: Strict-Transport-Security, X-Content-Type-Options: "
        "nosniff, X-Frame-Options (or frame-ancestors in a CSP), a "
        "Content-Security-Policy, Referrer-Policy, and Permissions-Policy."
    ),
    "leaked_credential": (
        "Rotate the exposed credential immediately, stop returning it in "
        "the response (move it server-side into an env var or secrets "
        "manager), and check access logs for signs it was already used."
    ),
    "known_backdoored_software": (
        "Take the affected service offline or isolate it until it can be "
        "rebuilt from a trusted, current package — don't just patch a "
        "backdoored build in place."
    ),
    "outdated_software": (
        "Upgrade to a current, supported release and enable automatic "
        "security updates where practical."
    ),
    "overprivileged_role": (
        "Apply least privilege: remove superuser/login rights from "
        "service accounts that don't need them and use a dedicated, "
        "narrowly-scoped role per application instead."
    ),
    "invalid_tls_certificate": (
        "Install a valid certificate for this exact hostname from a "
        "trusted CA (or fix a broken intermediate chain), and confirm "
        "the certificate covers every hostname it's served on."
    ),
    "weak_tls_protocol": (
        "Disable SSLv3/TLSv1.0/TLSv1.1 in the server's TLS configuration "
        "and require TLS 1.2 or newer, with modern cipher suites only."
    ),
    "expired_certificate": (
        "Renew the certificate immediately — an expired certificate "
        "breaks trust for every visitor, and many users click through "
        "the warning rather than turning back."
    ),
    "certificate_expiring_soon": (
        "Renew the certificate now and set up auto-renewal (e.g. "
        "certbot/ACME) so this doesn't recur."
    ),
    "exposed_sensitive_path": (
        "Remove the file from the web root or block it at the server "
        "config level (deny dotfiles, backups, and VCS directories by "
        "default), and rotate any credentials the exposed file contained."
    ),
    "cors_misconfiguration": (
        "Never combine a reflected/wildcard Access-Control-Allow-Origin "
        "with Access-Control-Allow-Credentials: true. Return an explicit "
        "allow-list of trusted origins instead."
    ),
    "cors_wildcard": (
        "If this endpoint doesn't need to be readable from any origin, "
        "replace the wildcard with an explicit allow-list."
    ),
    "information_disclosure": (
        "Suppress or generalize the header (turn off server version "
        "tokens, remove X-Powered-By) so software versions aren't "
        "advertised to every visitor."
    ),
    "insecure_cookie": (
        "Add the Secure and HttpOnly flags (and SameSite) to every "
        "session/auth cookie so it can't be read by JavaScript or sent "
        "over a plain-HTTP connection."
    ),
}

DEFAULT_REMEDY = (
    "Review this finding with whoever owns the asset and prioritize a "
    "fix by severity — no specific remedy is on file yet for this "
    "finding type."
)


def remedy_for(finding_type: str) -> str:
    """Best-effort remediation text for a Finding.type. Always returns
    something usable, even for a finding type this table doesn't know
    about yet."""
    return REMEDIES.get(finding_type, DEFAULT_REMEDY)
