import google.generativeai as genai
import json

API_KEY = "AIzaSyAtaNZ0BiGnRQujxmeiXe9iCGKT_h4WmPU"
genai.configure(api_key=API_KEY)

def analyze_log_with_ai(log_text, instance_name):
    """Analyze OpenStack logs using Gemini."""
    prompt = f"""You are a cloud security expert analyzing OpenStack logs.
Analyze the following instance log for {instance_name}.

Detect the following:
- SSH brute force
- sudo abuse
- suspicious processes
- network anomalies
- API misuse
- lateral movement

Respond EXACTLY in this format, with no markdown formatting:
ANOMALY_FOUND: yes/no
SEVERITY: High/Medium/Low/None
FINDINGS:
- finding 1
- finding 2
RECOMMENDATION: Your recommendation here

--- LOG START ---
{log_text}
--- LOG END ---
"""
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        return parse_ai_response(response.text, instance_name)
    except Exception as e:
        return {
            "instance": instance_name,
            "anomaly_found": False,
            "severity": "None",
            "findings": [f"Error communicating with AI: {str(e)}"],
            "recommendation": "Check API key and network.",
            "raw": str(e)
        }

def parse_ai_response(response_text, instance_name):
    """Parse the structured response from Gemini."""
    result = {
        "instance": instance_name,
        "anomaly_found": False,
        "severity": "None",
        "findings": [],
        "recommendation": "",
        "raw": response_text
    }
    
    lines = response_text.strip().split('\n')
    parsing_findings = False
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.startswith("ANOMALY_FOUND:"):
            val = line.split(":", 1)[1].strip().lower()
            result["anomaly_found"] = val == "yes"
            parsing_findings = False
        elif line.startswith("SEVERITY:"):
            result["severity"] = line.split(":", 1)[1].strip()
            parsing_findings = False
        elif line.startswith("FINDINGS:"):
            parsing_findings = True
            # Might be findings on the same line
            rem = line.split(":", 1)[1].strip()
            if rem:
                result["findings"].append(rem.lstrip("- "))
        elif line.startswith("RECOMMENDATION:"):
            result["recommendation"] = line.split(":", 1)[1].strip()
            parsing_findings = False
        elif parsing_findings and line.startswith("-"):
            result["findings"].append(line.lstrip("- "))
            
    return result

def get_sample_logs():
    """Returns sample logs for testing/demo."""
    return {
        "web-server-01": "May 4 12:00:00 sshd[123]: Failed password for root from 192.168.1.100 port 22\nMay 4 12:00:02 sshd[123]: Failed password for root from 192.168.1.100 port 22\nMay 4 12:00:05 sshd[123]: Failed password for root from 192.168.1.100 port 22",
        "db-server-01": "May 4 12:05:00 sudo[456]: user NOT in sudoers ; TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash\nMay 4 12:05:10 kernel: TCP: Treason uncloaked! Peer 10.0.0.5:4444",
        "app-server-01": "May 4 12:10:00 systemd[1]: Started web application.\nMay 4 12:15:00 CRON[789]: (root) CMD (/usr/bin/healthcheck.sh)"
    }

def analyze_all_instances(logs_dict):
    """Analyze multiple instance logs."""
    results = []
    for instance, log in logs_dict.items():
        results.append(analyze_log_with_ai(log, instance))
    return results

if __name__ == "__main__":
    logs = get_sample_logs()
    print(json.dumps(analyze_all_instances(logs), indent=2))
