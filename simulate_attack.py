import os
import random
import time

MOCK_DIR = "mock_configs"
CONFIG_FILES = {
    "nova.conf": {
        "allow_resize_to_same_host": ["false", "true"],
        "use_neutron": ["true", "false"],
        "force_config_drive": ["true", "false"]
    },
    "cinder.conf": {
        "enable_v3_api": ["true", "false"],
        "os_region_name": ["RegionOne", "RegionTwo"]
    },
    "neutron.conf": {
        "auth_strategy": ["keystone", "noauth"],
        "allow_overlapping_ips": ["true", "false"]
    },
    "swift.conf": {
        "auth_uri": ["http://controller:5000", "http://malicious-site.com:5000"]
    }
}

def simulate_attack():
    print("🚀 Starting Misconfiguration Simulation...")
    for filename, params in CONFIG_FILES.items():
        filepath = os.path.join(MOCK_DIR, filename)
        if not os.path.exists(filepath):
            continue
        
        # Read current content
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        # Randomly flip parameters
        new_lines = []
        for line in lines:
            if '=' in line:
                key, val = line.split('=', 1)
                key = key.strip()
                if key in params:
                    # Randomly pick a value (can be the same or different)
                    new_val = random.choice(params[key])
                    line = f"{key} = {new_val}\n"
            new_lines.append(line)
        
        # Write back
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
        print(f"✅ Updated {filename}")

if __name__ == "__main__":
    while True:
        simulate_attack()
        print("Waiting 5 seconds for next update...")
        time.sleep(5)
