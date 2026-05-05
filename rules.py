import json
import os

RULES_FILE = os.path.join(os.path.dirname(__file__), 'rules_config.json')

def load_rules():
    """Load security rules from rules_config.json."""
    if not os.path.exists(RULES_FILE):
        print(f"Warning: {RULES_FILE} not found. Falling back to default rules.")
        return []

    try:
        with open(RULES_FILE, 'r') as f:
            rules = json.load(f)
            print(f"Loaded {len(rules)} rules from {RULES_FILE}")
            return rules
    except json.JSONDecodeError as e:
        print(f"Error parsing {RULES_FILE}: {e}")
        return []
    except Exception as e:
        print(f"Error loading rules: {e}")
        return []

RULES = load_rules()
