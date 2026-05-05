import os
import openstack

def get_connection():
    """Establish OpenStack connection using environment variables."""
    try:
        conn = openstack.connect(
            auth_url="http://10.20.20.1:5000/v3",
            project_name=os.environ.get("OS_PROJECT_NAME", "admin"),
            username=os.environ.get("OS_USERNAME", "admin"),
            password=os.environ.get("OS_PASSWORD", "secret"),
            region_name="RegionOne",
            user_domain_name="Default",
            project_domain_name="Default",
            timeout=3
        )
        # Test connection immediately so we fail fast instead of in every scan
        conn.authorize()
        return conn
    except Exception as e:
        print(f"Connection error: {e}")
        return None

def scan_instances(conn):
    instances = []
    try:
        for server in conn.compute.servers():
            ips = []
            for network, addresses in server.addresses.items():
                for addr in addresses:
                    ips.append(addr.get("addr"))
            
            instances.append({
                "id": server.id,
                "name": server.name,
                "status": server.status,
                "ip": ", ".join(ips),
                "flavor": server.flavor.get("id") if server.flavor else "Unknown",
                "image": server.image.get("id") if server.image else "Unknown"
            })
    except Exception as e:
        print(f"Error scanning instances: {e}")
    return instances

def get_instance_logs(conn):
    logs = {}
    try:
        for server in conn.compute.servers():
            try:
                # get console output (limit length to prevent massive logs)
                output = conn.compute.get_server_console_output(server.id, length=100)
                logs[server.name] = output if output else "No console output available."
            except Exception as e:
                logs[server.name] = f"Error retrieving logs: {e}"
    except Exception as e:
        print(f"Error retrieving instances for logs: {e}")
    return logs

def scan_security_groups(conn):
    groups = []
    try:
        for sg in conn.network.security_groups():
            risks = []
            for rule in sg.security_group_rules:
                if rule.remote_ip_prefix == "0.0.0.0/0":
                    if rule.port_range_min == 22 or rule.port_range_max == 22:
                        risks.append("SSH (22) exposed to 0.0.0.0/0")
                    elif rule.port_range_min == 3389 or rule.port_range_max == 3389:
                        risks.append("RDP (3389) exposed to 0.0.0.0/0")
                    elif rule.port_range_min is None:
                        risks.append("ALL ports exposed to 0.0.0.0/0")
            
            groups.append({
                "id": sg.id,
                "name": sg.name,
                "risks": risks,
                "status": "FAIL" if risks else "PASS"
            })
    except Exception as e:
        print(f"Error scanning security groups: {e}")
    return groups

def scan_networks(conn):
    networks = []
    try:
        for net in conn.network.networks():
            risks = []
            if net.is_router_external:
                risks.append("Network is public/external")
            if not net.is_port_security_enabled:
                risks.append("Port security is disabled")
                
            networks.append({
                "id": net.id,
                "name": net.name,
                "risks": risks,
                "status": "FAIL" if risks else "PASS"
            })
    except Exception as e:
        print(f"Error scanning networks: {e}")
    return networks

def scan_volumes(conn):
    volumes = []
    try:
        for vol in conn.block_storage.volumes():
            risks = []
            if not vol.is_encrypted:
                risks.append("Volume is unencrypted")
            if vol.status == "available":
                risks.append("Volume is unused (available)")
                
            volumes.append({
                "id": vol.id,
                "name": vol.name,
                "risks": risks,
                "status": "FAIL" if risks else "PASS"
            })
    except Exception as e:
        print(f"Error scanning volumes: {e}")
    return volumes

def scan_images(conn):
    images = []
    try:
        for img in conn.image.images():
            risks = []
            if img.visibility == "public":
                risks.append("Image is public")
            
            images.append({
                "id": img.id,
                "name": img.name,
                "risks": risks,
                "status": "FAIL" if risks else "PASS"
            })
    except Exception as e:
        print(f"Error scanning images: {e}")
    return images

def scan_users(conn):
    users = []
    try:
        for user in conn.identity.users():
            risks = []
            if not user.is_enabled:
                risks.append("User is inactive")
            
            users.append({
                "id": user.id,
                "name": user.name,
                "risks": risks,
                "status": "FAIL" if risks else "PASS"
            })
    except Exception as e:
        print(f"Error scanning users: {e}")
    return users

def run_live_scan():
    """Execute full live scan against the OpenStack cluster."""
    conn = get_connection()
    if not conn:
        return {
            "error": "Could not connect to OpenStack API. Ensure OS_PASSWORD is set."
        }
        
    return {
        "instances": scan_instances(conn),
        "logs": get_instance_logs(conn),
        "security_groups": scan_security_groups(conn),
        "networks": scan_networks(conn),
        "volumes": scan_volumes(conn),
        "images": scan_images(conn),
        "users": scan_users(conn)
    }

if __name__ == "__main__":
    import json
    print(json.dumps(run_live_scan(), indent=2))
