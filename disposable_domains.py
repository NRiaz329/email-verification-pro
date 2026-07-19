"""
Offline disposable / temporary email domain list.

Why this file exists
---------------------
The original tool called out to two GitHub-hosted blocklists on *every single
email check*. That means:
  - every check paid a network round trip (slow, and blocks the SMTP thread)
  - a GitHub outage / rate limit silently broke disposable detection
  - deployed on a free host, this could get you rate-limited fast

Instead we ship a curated, offline list of well-known disposable/burner
domains (a few hundred of the most common providers). This is instant and
100% free. `refresh_from_remote()` is provided as an *optional* extra: if the
app has internet access, you can periodically pull the bigger community
lists and merge them into a local cache file, without paying that cost on
every request.
"""

import json
import os
import time

CACHE_FILE = os.path.join(os.path.dirname(__file__), ".disposable_cache.json")
CACHE_TTL_SECONDS = 60 * 60 * 24 * 7  # 1 week

# Curated, offline, no-network-required baseline list.
BASE_DISPOSABLE_DOMAINS = {
    "mailinator.com", "mailinator.net", "mailinator2.com", "mailinater.com",
    "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "guerrillamailblock.com", "sharklasers.com",
    "10minutemail.com", "10minutemail.net", "10minemail.com",
    "temp-mail.org", "tempmail.com", "tempmail.net", "tempmail.de",
    "tempinbox.com", "tempinbox.co", "tempr.email", "temporaryemail.us",
    "throwawaymail.com", "throwam.com", "trashmail.com", "trashmail.net",
    "trashmail.me", "trash-mail.com", "trashmail.io", "trashmail.ws",
    "yopmail.com", "yopmail.net", "yopmail.fr", "cool.fr.nf",
    "dispostable.com", "mailnesia.com", "maildrop.cc", "fakeinbox.com",
    "getnada.com", "nada.email", "mytemp.email", "mohmal.com",
    "moakt.com", "moakt.cc", "emailondeck.com", "spam4.me",
    "mintemail.com", "spamgourmet.com", "mailcatch.com", "discard.email",
    "discardmail.com", "discardmail.de", "mailexpire.com", "meltmail.com",
    "mt2015.com", "mt2014.com", "mt2009.com", "einrot.com", "einrot.de",
    "fake-mail.net", "fakemailgenerator.com", "burnermail.io",
    "anonbox.net", "anonymbox.com", "spambox.us", "spamex.com",
    "spamfree24.org", "spamfree24.de", "spamfree24.com", "spamavert.com",
    "byom.de", "e4ward.com", "emailsensei.com", "getairmail.com",
    "harakirimail.com", "jetable.org", "jetable.net", "jetable.com",
    "mailtemp.info", "mailslurp.com", "mailslurp.net", "mailslurp.biz",
    "tempail.com", "tempmailo.com", "temp-mail.io", "temp-mail.ru",
    "dropmail.me", "inboxbear.com", "instant-mail.de", "koszmail.pl",
    "kurzepost.de", "lifebyfood.com", "linshiyouxiang.net", "mailin8r.com",
    "mailimate.com", "mail-temporaire.fr", "mailtothis.com", "mytrashmail.com",
    "no-spam.ws", "nobulk.com", "noclickemail.com", "nomail2me.com",
    "nospamfor.us", "nowmymail.com", "objectmail.com", "obobbo.com",
    "onewaymail.com", "pookmail.com", "quickinbox.com", "rcpt.at",
    "recode.me", "recursor.net", "regbypass.com", "safersignup.de",
    "safetymail.info", "sendspamhere.com", "shieldedmail.com",
    "shitmail.me", "skeefmail.com", "slopsbox.com", "smellrear.com",
    "snakemail.com", "sneakemail.com", "sofimail.com", "sogetthis.com",
    "spam.la", "spambob.com", "spambob.net", "spambob.org",
    "spambog.com", "spambog.de", "spambog.ru", "spamcannon.com",
    "spamcero.com", "spamcon.org", "spamcorptastic.com", "spamcowboy.com",
    "spamday.com", "spamdecoy.net", "spameater.com", "spamherelots.com",
    "spamhereplease.com", "spamhole.com", "spamify.com", "spaml.com",
    "spaml.de", "spammotel.com", "spamobox.com", "spamoff.de",
    "spamsalad.in", "spamslicer.com", "spamspot.com", "spamthis.co.uk",
    "spamthisplease.com", "spamtrail.com", "supergreatmail.com",
    "supermailer.jp", "suremail.info", "teleworm.com", "teleworm.us",
    "thisisnotmyrealemail.com", "throam.com", "tilien.com", "tittbit.in",
    "toiaas.com", "tradermail.info", "trbvm.com", "trickmail.net",
    "turual.com", "twinmail.de", "tyldd.com", "uggsrock.com",
    "umail.net", "uroid.com", "venompen.com", "veryrealemail.com",
    "vidchart.com", "viditag.com", "viewcastmedia.com", "viewcastmedia.net",
    "viewcastmedia.org", "walala.org", "walkmail.net", "webemail.me",
    "weg-werf-email.de", "wegwerfadresse.de", "wegwerfemail.de",
    "wegwerfemail.net", "wegwerfmail.de", "wegwerfmail.info",
    "wegwerfmail.net", "wegwerfmail.org", "wetrainbayarea.com",
    "wetrainbayarea.org", "wh4f.org", "whatiaas.com", "whatpaas.com",
    "whopy.com", "wilemail.com", "willselfdestruct.com", "winemaven.info",
    "wronghead.com", "wuzup.net", "wuzupmail.net", "xagloo.com",
    "xemaps.com", "xents.com", "xmaily.com", "xoxy.net", "yuurok.com",
    "zetmail.com", "zippymail.info", "zoemail.org", "zomg.info",
    "1secmail.com", "1secmail.net", "1secmail.org", "20minutemail.com",
    "33mail.com", "3trtretgfrfe.com", "5ghgfhw2334.com", "9ox.net",
    "airmail.cc", "armyspy.com", "cuvox.de", "dayrep.com", "einrot.com",
    "fleckens.hu", "gustr.com", "jourrapide.com", "rhyta.com",
    "superrito.com", "teleworm.us", "nwytg.net", "nwytg.com",
    "getairmail.net", "getairmail.org", "guerillamail.com",
    "guerillamail.net", "guerillamail.biz", "guerillamail.org",
    "guerillamailblock.com", "pokemail.net", "correo.blogos.net",
    "curryworld.de", "deadaddress.com", "despam.it", "devnullmail.com",
    "letthemeatspam.com", "loadby.us", "mailbidon.com", "mailbiscuit.com",
    "mailblocks.com", "mailbucket.org", "mailguard.me",
    "10mail.org", "20mail.it", "33mail.net", "any.pink", "cust.in",
    "dodgeit.com", "dodgit.com", "dodgit.org", "explodemail.com",
    "fastacura.com", "filzmail.com", "getonemail.com", "getonemail.net",
    "hidzz.com", "hopemail.biz", "ieatspam.eu", "ieatspam.info",
    "incognitomail.com", "incognitomail.net", "incognitomail.org",
    "kaspop.com", "keepmymail.com", "killmail.com", "killmail.net",
    "kir.ch.tc", "klassmaster.com", "klassmaster.net", "klzlk.com",
    "lookugly.com", "lopl.co.cc", "lroid.com", "lukop.dk",
    "maboard.com", "mail-filter.com", "mail-temporaire.com",
    "mail.by", "mail4trash.com", "mailmoat.com", "mailnull.com",
    "mailscrap.com", "mailshell.com", "mailtemp.net", "mailzilla.com",
    "mailzilla.org", "mbx.cc", "mega.zik.dj", "meinspamschutz.de",
    "spamgoes.in", "tempemail.net", "tempemail.com", "tempemail.co.za",
    "tempemail.biz", "tempymail.com", "tmail.ws", "tmailinator.com",
    "trbvn.com", "trialmail.de", "yopmail.com.br", "zippiernet.com",
}


def _load_cache():
    if not os.path.exists(CACHE_FILE):
        return set()
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if time.time() - data.get("updated_at", 0) > CACHE_TTL_SECONDS:
            return set(data.get("domains", []))  # stale but still usable
        return set(data.get("domains", []))
    except Exception:
        return set()


def get_disposable_domains():
    """Combined offline base list + anything picked up from a prior refresh."""
    return BASE_DISPOSABLE_DOMAINS | _load_cache()


def cache_age_seconds():
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return time.time() - data.get("updated_at", 0)
    except Exception:
        return None


def refresh_from_remote(urls=None, timeout=5):
    """
    OPTIONAL: pull larger community-maintained blocklists and merge them into
    a local JSON cache, so future runs stay offline-fast. Only call this from
    a background/maintenance action (e.g. a manual "Refresh list" button or a
    scheduled job) -- never per-request. Requires `requests` and outbound
    internet access; fails silently (returns False) if unavailable, so the
    app keeps working off the bundled list either way.
    """
    import requests  # local import: only needed for this optional path

    urls = urls or [
        "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
        "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt",
    ]
    merged = set()
    ok = False
    for url in urls:
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    merged.add(line)
            ok = True
        except Exception as e:
            print(f"[disposable_domains] Skipped {url}: {e}")

    if ok:
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as fh:
                json.dump({"updated_at": time.time(), "domains": sorted(merged)}, fh)
        except Exception as e:
            print(f"[disposable_domains] Could not write cache: {e}")
    return ok
