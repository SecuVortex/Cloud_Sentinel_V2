import configparser
import os
import glob
from rules import RULES

def _find_config(pattern):
    """Auto-detect config path using glob."""
    paths = glob.glob(pattern)
    return paths[0] if paths else None

# Auto-detect real MicroStack config paths
CONFIG_FILES = {
    "Nova": _find_config("/snap/microstack/*/etc/nova/nova.conf"),
    "Cinder": _find_config("/snap/microstack/*/etc/cinder/cinder.conf"),
    "Neutron": _find_config("/snap/microstack/*/etc/neutron/neutron.conf"),
    "Keystone": _find_config("/snap/microstack/*/etc/keystone/keystone.conf"),
    "Glance": _find_config("/snap/microstack/*/etc/glance/glance-api.conf")
}

print("\n=== Cloud Sentinel — Config Path Detection ===")
for svc, path in CONFIG_FILES.items():
    status = path if path else "Not found"
    print(f"  {svc:10s}: {status}")
print("=============================================\n")

def parse_config(filepath):
    config = configparser.ConfigParser()
    try:
        with open(filepath, 'r') as f:
            config.read_file(f)
        return config
    except Exception as e:
        return None

def run_scan():
    results = []

    for rule in RULES:
        service = rule["service"]
        filepath = CONFIG_FILES.get(service)

        if filepath is None or not os.path.exists(filepath):
            results.append({
                "id": rule["id"],
                "service": service,
                "parameter": rule["parameter"],
                "expected": rule["expected"],
                "actual": "N/A",
                "severity": rule["severity"],
                "remediation": rule["remediation"],
                "status": "NOT FOUND"
            })
            continue

        config = parse_config(filepath)

        if config is None:
            actual = "UNREADABLE"
            status = "ERROR"
        else:
            section = rule["section"]
            parameter = rule["parameter"]
            try:
                # configparser can handle fallback mechanisms, but basic get is enough
                actual = config.get(section, parameter)
            except (configparser.NoSectionError, configparser.NoOptionError):
                actual = "NOT SET"

            if actual.lower() == rule["expected"].lower():
                status = "PASS"
            else:
                status = "FAIL"

        results.append({
            "id": rule["id"],
            "service": service,
            "parameter": rule["parameter"],
            "expected": rule["expected"],
            "actual": actual,
            "severity": rule["severity"],
            "remediation": rule["remediation"],
            "status": status
        })

    return results

if __name__ == "__main__":
    results = run_scan()
    for r in results:
        print(f"[{r['status']}] {r['id']} - {r['parameter']} (Severity: {r['severity']})")
