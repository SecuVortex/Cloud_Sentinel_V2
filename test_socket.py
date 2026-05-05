import socket
def check_port(host, port, timeout=1):
    try:
        socket.create_connection((host, port), timeout=timeout)
        return True
    except OSError:
        return False

print(check_port('10.20.20.1', 5000))
