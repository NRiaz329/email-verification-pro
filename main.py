import io
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import streamlit as st

import source_code as sc
import disposable_domains
from popular_domains import emailDomains
from suggestion import suggest_email_domain

st.set_page_config(
    page_title="Email Verification Pro",
    page_icon="✅",
    layout="centered",
)

VERDICT_COLORS = {
    "Valid": "#1db954",
    "Risky": "#ff9f1c",
    "Unknown": "#8d8d8d",
    "Invalid": "#e63946",
}


def verdict_badge(verdict: str) -> str:
    color = VERDICT_COLORS.get(verdict, "#8d8d8d")
    return (
        f'<span style="background-color:{color};color:white;padding:3px 12px;'
        f'border-radius:14px;font-weight:600;font-size:0.85rem;">{verdict}</span>'
    )


def bool_badge(value, true_label="Yes", false_label="No", unknown_label="Unknown"):
    if value is True:
        return '<span style="color:#1db954;font-weight:600;">' + true_label + '</span>'
    if value is False:
        return '<span style="color:#e63946;font-weight:600;">' + false_label + '</span>'
    return '<span style="color:#8d8d8d;font-weight:600;">' + unknown_label + '</span>'


# ---------------------------------------------------------------------------
# Bulk processing helpers
# ---------------------------------------------------------------------------

def _extract_emails_from_df(df: pd.DataFrame):
    """Robustly pull email strings out of the first column, skipping blanks
    and non-string junk instead of crashing on the first bad row (the
    original code did `row[0].strip()` with no guard at all)."""
    emails = []
    if df.empty:
        return emails
    for value in df.iloc[:, 0]:
        if pd.isna(value):
            continue
        email = str(value).strip()
        if email:
            emails.append(email)
    return emails


def read_uploaded_emails(input_file) -> list:
    file_extension = input_file.name.split('.')[-1].lower()

    if file_extension == 'csv':
        df = pd.read_csv(input_file, header=None)
        return _extract_emails_from_df(df)
    elif file_extension == 'xlsx':
        df = pd.read_excel(input_file, header=None)
        return _extract_emails_from_df(df)
    elif file_extension == 'txt':
        text = input_file.read().decode('utf-8', errors='ignore')
        return [line.strip() for line in text.splitlines() if line.strip()]
    else:
        st.warning("Unsupported file format. Please provide a CSV, XLSX, or TXT file.")
        return []


def run_bulk_checks(emails: list, max_workers: int = 12) -> pd.DataFrame:
    """Runs full_check on every email concurrently (huge speedup for bulk
    files -- the original did this one row at a time, synchronously, with a
    live network+SMTP round trip per email)."""
    results = [None] * len(emails)
    progress = st.progress(0.0, text=f"Verifying 0 / {len(emails)}...")
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx = {
            executor.submit(sc.full_check, email): idx
            for idx, email in enumerate(emails)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                results[idx] = {
                    "email": emails[idx], "syntax_valid": False, "domain": "",
                    "mx_valid": False, "disposable": False, "role_based": False,
                    "free_provider": False, "smtp_deliverable": None,
                    "catch_all": None, "score": 0, "verdict": "Invalid",
                    "notes": [f"Error during check: {e}"],
                }
            done += 1
            progress.progress(done / len(emails), text=f"Verifying {done} / {len(emails)}...")

    progress.empty()

    rows = []
    for r in results:
        rows.append({
            "Email": r["email"],
            "Verdict": r["verdict"],
            "Score": r["score"],
            "Domain": r["domain"],
            "MX Valid": r["mx_valid"],
            "Disposable": r["disposable"],
            "Role-based": r["role_based"],
            "Free Provider": r["free_provider"],
            "SMTP Deliverable": r["smtp_deliverable"],
            "Catch-all": r["catch_all"],
            "Notes": "; ".join(r["notes"]),
        })
    result_df = pd.DataFrame(rows)
    result_df.index = range(1, len(result_df) + 1)
    return result_df


def summary_metrics(result_df: pd.DataFrame):
    counts = result_df["Verdict"].value_counts()
    cols = st.columns(4)
    for col, verdict in zip(cols, ["Valid", "Risky", "Unknown", "Invalid"]):
        col.metric(verdict, int(counts.get(verdict, 0)))


# ---------------------------------------------------------------------------
# Single-email UI
# ---------------------------------------------------------------------------

def render_single_email_tab():
    email = st.text_input("Enter an email address:")

    if st.button("Verify", type="primary"):
        if not email:
            st.warning("Please enter an email address.")
            return

        with st.spinner("Verifying..."):
            result = sc.full_check(email)

        if not result["syntax_valid"]:
            st.error("Invalid email format. Please enter a valid email address.")
            return

        if not result["mx_valid"]:
            st.warning("Not valid: MX record not found for this domain.")
            suggested_domains = suggest_email_domain(result["domain"], emailDomains)
            if suggested_domains:
                st.info("Did you mean one of these domains?")
                for suggested_domain in suggested_domains:
                    st.write(f"- {suggested_domain}")
            else:
                st.warning("No suggested domains found.")
            return

        st.markdown("**Result:**  " + verdict_badge(result["verdict"]), unsafe_allow_html=True)
        st.progress(result["score"] / 100, text=f"Confidence score: {result['score']}/100")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Syntax", "OK")
        col2.metric("MX Record", "OK")
        col3.metric("Disposable", "Yes" if result["disposable"] else "No")
        col4.metric("Role-based", "Yes" if result["role_based"] else "No")

        st.markdown(
            f"**SMTP deliverable:** {bool_badge(result['smtp_deliverable'])} &nbsp;&nbsp; "
            f"**Catch-all domain:** {bool_badge(result['catch_all'])} &nbsp;&nbsp; "
            f"**Free/consumer provider:** {bool_badge(result['free_provider'])}",
            unsafe_allow_html=True,
        )

        if result["notes"]:
            with st.expander("Details"):
                for note in result["notes"]:
                    st.write(f"- {note}")

        with st.expander("See Domain Information (WHOIS)"):
            try:
                import whois  # imported here, not at module level, so a
                               # missing/broken whois package can't crash
                               # the entire app on startup
            except ImportError:
                st.info("WHOIS lookup isn't available in this environment (the `python-whois` package isn't installed). The rest of the tool works normally.")
            else:
                try:
                    dm_info = whois.whois(result["domain"])
                    st.write("Registrar:", dm_info.registrar)
                    st.write("Server:", dm_info.whois_server)
                    st.write("Country:", dm_info.country)
                except Exception:
                    st.error("Domain information retrieval failed (the WHOIS server may be blocking/rate-limiting this request).")


# ---------------------------------------------------------------------------
# Bulk UI
# ---------------------------------------------------------------------------

def render_bulk_tab():
    st.header("Bulk Email Processing")
    st.caption("Upload a CSV, XLSX, or TXT file with one email per row/line.")

    input_file = st.file_uploader("Upload a CSV, XLSX, or TXT file", type=["csv", "xlsx", "txt"])
    max_rows = st.number_input(
        "Max rows to process (safety cap for free hosting tiers)",
        min_value=1, max_value=5000, value=500, step=50,
    )

    if input_file:
        emails = read_uploaded_emails(input_file)
        if not emails:
            st.warning("No emails found in the uploaded file.")
            return

        if len(emails) > max_rows:
            st.info(f"File has {len(emails)} rows; only the first {max_rows} will be processed. Raise the cap above if needed.")
            emails = emails[:max_rows]

        if st.button(f"Verify {len(emails)} emails", type="primary"):
            result_df = run_bulk_checks(emails)
            st.success("Processing completed.")
            summary_metrics(result_df)
            st.dataframe(result_df, use_container_width=True)

            csv_bytes = result_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download results as CSV",
                data=csv_bytes,
                file_name="email_verification_results.csv",
                mime="text/csv",
            )


def render_sidebar():
    with st.sidebar:
        st.subheader("Disposable domain list")
        age = disposable_domains.cache_age_seconds()
        base_count = len(disposable_domains.BASE_DISPOSABLE_DOMAINS)
        total_count = len(disposable_domains.get_disposable_domains())
        st.caption(f"{total_count} domains loaded ({base_count} bundled offline).")
        if age is not None:
            st.caption(f"Remote cache last refreshed {int(age // 3600)}h ago.")
        else:
            st.caption("Remote cache not refreshed yet (running on the bundled offline list).")

        if st.button("Refresh from remote lists (needs internet)"):
            with st.spinner("Fetching community disposable-domain lists..."):
                ok = disposable_domains.refresh_from_remote()
            if ok:
                st.success("Refreshed successfully.")
            else:
                st.warning("Could not reach remote lists (no internet access, or a network block). Still using the bundled offline list.")

        st.divider()
        st.caption(
            "Free & open-source: this tool uses no paid APIs. "
            "MX/SMTP checks use free public DNS; disposable-domain detection "
            "runs entirely offline by default."
        )


def main():
    try:
        with open('style.css') as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except FileNotFoundError:
        pass

    st.title("Email Verification Tool", help="Checks syntax, DNS/MX records, SMTP deliverability, catch-all behavior, and disposable-domain status.")
    st.info(
        "SMTP/catch-all checks can be inconclusive when run from cloud or free-tier hosting, "
        "since many mail providers block or greylist unfamiliar servers. "
        "Treat 'Unknown' results as inconclusive rather than invalid."
    )

    render_sidebar()

    if not sc.smtp_port_reachable():
        st.warning(
            "⚠️ Outbound SMTP (port 25) appears to be blocked in this hosting environment "
            "(this is normal on Streamlit Community Cloud, Render, Railway, and most free "
            "hosts — cloud providers block it by default to prevent spam). "
            "That means the mailbox-existence check cannot run here: every result will show "
            "'Unknown' for SMTP deliverability rather than a false 'Valid'. "
            "Syntax, MX/DNS, disposable-domain, and role-based checks are unaffected and still fully accurate."
        )

    t1, t2 = st.tabs(["Single Email", "Bulk Email Processing"])
    with t1:
        render_single_email_tab()
    with t2:
        render_bulk_tab()


if __name__ == "__main__":
    main()
