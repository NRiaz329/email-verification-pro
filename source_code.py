"""
Core email verification engine.

Improvements over the original version:
  - `is_disposable` no longer hits the network on every call (was fetching
    two GitHub lists per email -- slow and fragile). Uses the bundled
    offline list from `disposable_domains.py` instead.
  - SMTP checks now have real timeouts (the original `smtplib.SMTP(host)`
    call had no timeout and could hang indefinitely on a slow/filtering
    mail server).
  - Adds catch-all detection: many mail servers accept RCPT TO for *any*
    address ("catch-all"), which makes a bare 250 response meaningless.
    We probe a random mailbox at the same domain to detect this.
  - Adds role-based address detection (info@, support@, admin@, ...).
  - Adds "free/consumer provider" detection (gmail, yahoo, outlook, ...).
  - Everything DNS/network related is cached (`lru_cache`) so bulk
    processing of many addresses on the same domain is fast and doesn't
    re-hit the network per row.
  - Adds `full_check()` which runs everything and returns a single dict
    with a 0-100 confidence score and a verdict, so the UI doesn't have to
    re-implement this logic.
"""

import random
import re
import smtplib
import socket
import string
from functools import lru_cache

import dns.resolver
import dns.exception

from disposable_domains import get_disposable_domains
from popular_domains import emailDomains

SMTP_TIMEOUT = 6
DNS_TIMEOUT = 3

resolver = dns.resolver.Resolver()
resolver.timeout = DNS_TIMEOUT
resolver.lifetime = DNS_TIMEOUT

ROLE_BASED_PREFIXES = {
    "admin", "administrator", "support", "info", "sales", "contact",
    "help", "helpdesk", "billing", "abuse", "postmaster", "webmaster",
    "noreply", "no-reply", "donotreply", "do-not-reply", "hostmaster",
    "root", "security", "marketing", "office", "mail", "team", "hr",
    "jobs", "careers", "press", "media", "news", "feedback", "service",
}

FREE_PROVIDER_DOMAINS = set(str(d) for d in emailDomains)


def is_valid_email(email: str) -> bool:
    """Syntax validation. Guards against non-string / empty input too."""
    if not isinstance(email, str) or not email or "@" not in email:
        return False

    pattern = r'''
        ^                         # Start of string
        (?!.*[._%+-]{2})          # No consecutive special characters
        [a-zA-Z0-9._%+-]{1,64}    # Local part: allowed characters and length limit
        (?<![._%+-])              # No special characters at the end of local part
        @                         # "@" symbol
        [a-zA-Z0-9.-]+            # Domain part: allowed characters
        (?<![.-])                 # No special characters at the end of domain
        \.[a-zA-Z]{2,}$           # Top-level domain with minimum 2 characters
    '''
    return re.match(pattern, email.strip(), re.VERBOSE) is not None


def get_domain(email: str) -> str:
    return email.split('@')[1].lower().strip() if '@' in email else ''


@lru_cache(maxsize=2048)
def _resolve(record_type: str, domain: str):
    """Cached DNS lookup. Returns a tuple of records (possibly empty) so the
    result is hashable/cacheable, or None on a hard failure."""
    try:
        answers = resolver.resolve(domain, record_type)
        return tuple(str(r) for r in answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return tuple()
    except Exception:
        return tuple()


@lru_cache(maxsize=2048)
def get_mx_records(domain: str):
    """Returns MX hosts sorted by preference (best first). Falls back to
    the domain's own A record (some domains accept mail directly)."""
    mx_answers = _resolve('MX', domain)
    if mx_answers:
        # dnspython MX string looks like "10 mail.example.com."
        parsed = []
        for rec in mx_answers:
            parts = rec.split()
            if len(parts) == 2:
                try:
                    parsed.append((int(parts[0]), parts[1].rstrip('.')))
                except ValueError:
                    parsed.append((999, parts[1].rstrip('.')))
        parsed.sort(key=lambda x: x[0])
        return tuple(host for _, host in parsed)

    if _resolve('A', domain):
        return (domain,)
    return tuple()


def has_valid_mx_record(domain: str) -> bool:
    return len(get_mx_records(domain)) > 0


def is_role_based(email: str) -> bool:
    local_part = email.split('@')[0].lower() if '@' in email else ''
    local_part = local_part.split('+')[0]  # strip +tag addressing
    return local_part in ROLE_BASED_PREFIXES


def is_free_provider(domain: str) -> bool:
    return domain.lower() in FREE_PROVIDER_DOMAINS


def is_disposable(domain: str) -> bool:
    return domain.lower() in get_disposable_domains()


def _smtp_probe(mx_host: str, mail_from: str, rcpt_to: str):
    """Returns True/False/None (None = inconclusive, e.g. connection blocked
    or timed out -- very common on cloud hosts, whose IPs are widely
    blocked/greylisted by mail providers)."""
    try:
        with smtplib.SMTP(mx_host, timeout=SMTP_TIMEOUT) as smtp:
            smtp.ehlo_or_helo_if_needed()
            smtp.mail(mail_from)
            code, _ = smtp.rcpt(rcpt_to)
            return code == 250
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
            smtplib.SMTPHeloError, socket.timeout, ConnectionRefusedError,
            OSError):
        return None
    except Exception:
        return None


def verify_email(email: str) -> bool:
    """Kept for backwards compatibility with the original API: returns a
    plain bool (treats "inconclusive" as False, i.e. can't confirm)."""
    result, _ = verify_email_deliverability(email)
    return bool(result)


def verify_email_deliverability(email: str):
    """
    Returns (deliverable, catch_all):
      deliverable: True / False / None (None = SMTP check was inconclusive,
        e.g. blocked by the mail server or the network -- this is *very*
        common when running from a cloud host / free hosting tier, so the
        UI should treat None as "unknown", not "invalid").
      catch_all: True if the domain appears to accept mail for any address
        (meaning a 250 response doesn't actually confirm the mailbox
        exists), False if not catch-all, None if undetermined.
    """
    domain = get_domain(email)
    mx_hosts = get_mx_records(domain)
    if not mx_hosts:
        return False, None

    deliverable = None
    for host in mx_hosts:
        deliverable = _smtp_probe(host, '', email)
        if deliverable is not None:
            break

    if deliverable is not True:
        return deliverable, None

    # Probe a random mailbox to check for catch-all behaviour.
    random_local = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    fake_email = f"{random_local}@{domain}"
    catch_all_result = None
    for host in mx_hosts:
        catch_all_result = _smtp_probe(host, '', fake_email)
        if catch_all_result is not None:
            break

    return deliverable, catch_all_result


def full_check(email: str) -> dict:
    """Runs every check and returns a single result dict with a 0-100
    confidence score and a verdict string: Valid / Risky / Unknown / Invalid."""
    result = {
        "email": email,
        "syntax_valid": False,
        "domain": "",
        "mx_valid": False,
        "disposable": False,
        "role_based": False,
        "free_provider": False,
        "smtp_deliverable": None,
        "catch_all": None,
        "score": 0,
        "verdict": "Invalid",
        "notes": [],
    }

    if not is_valid_email(email):
        result["notes"].append("Failed syntax validation.")
        return result
    result["syntax_valid"] = True

    domain = get_domain(email)
    result["domain"] = domain

    if not has_valid_mx_record(domain):
        result["notes"].append("Domain has no valid MX/A record; can't receive mail.")
        return result
    result["mx_valid"] = True

    result["disposable"] = is_disposable(domain)
    result["role_based"] = is_role_based(email)
    result["free_provider"] = is_free_provider(domain)

    deliverable, catch_all = verify_email_deliverability(email)
    result["smtp_deliverable"] = deliverable
    result["catch_all"] = catch_all

    if deliverable is False:
        result["notes"].append("Mail server rejected the address (mailbox likely doesn't exist).")
    elif deliverable is None:
        result["notes"].append("SMTP check was inconclusive (server blocked/greylisted the probe -- common from cloud hosts).")
    elif catch_all:
        result["notes"].append("Domain accepts mail for any address (catch-all); existence of this specific mailbox isn't confirmed.")

    if result["disposable"]:
        result["notes"].append("Domain is a known disposable/temporary email provider.")
    if result["role_based"]:
        result["notes"].append("Looks like a role-based address (e.g. info@, support@) rather than a personal inbox.")

    # --- Scoring ---
    score = 0
    score += 20  # syntax valid
    score += 25  # mx valid
    score += 0 if result["disposable"] else 15
    if deliverable is True and not catch_all:
        score += 30
    elif deliverable is True and catch_all:
        score += 15
    elif deliverable is None:
        score += 12  # unknown, not penalized as hard as a confirmed reject
    else:
        score += 0
    score += 0 if result["role_based"] else 10
    result["score"] = min(100, score)

    if result["disposable"]:
        result["verdict"] = "Risky"
    elif deliverable is False:
        result["verdict"] = "Invalid"
    elif result["score"] >= 80:
        result["verdict"] = "Valid"
    elif result["score"] >= 55:
        result["verdict"] = "Risky"
    else:
        result["verdict"] = "Unknown"

    return result
