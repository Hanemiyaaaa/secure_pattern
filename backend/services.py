import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(BASE_DIR, "security_policy.json")
LOG_FILE = os.path.join(BASE_DIR, "event_log.txt")

def load_policy():
    if not os.path.exists(POLICY_PATH):
        default = {
            "data_storage": "unassigned",
            "data_encryption": "cloud_provider",
            "access_control": "restaurant_owner",
            "incident_response": "unassigned"
        }
        with open(POLICY_PATH, "w") as f:
            json.dump(default, f, indent=4)
    with open(POLICY_PATH) as f:
        return json.load(f)

def save_event(event: str):
    with open(LOG_FILE, "a") as f:
        f.write(f"{event}\n")

def find_unassigned():
    policy = load_policy()
    return [k for k, v in policy.items() if v == "unassigned"]

def log_unauthorized_access(username: str, endpoint: str):
    event = f"Unauthorized access attempt by user '{username}' to endpoint '{endpoint}'"
    save_event(event)
