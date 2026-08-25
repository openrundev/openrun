import os
import socket
import time

# Runs the app image with this command as a sidecar. Inherits the app env:
# the cache address, the app params (app_name) but not the app PORT
CACHE_ADDR = os.environ["CL_SIDECAR_CACHE_ADDR"]


def cache_set(key, value):
    host, port = CACHE_ADDR.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=2) as conn:
        conn.sendall(f"set {key} 0 0 {len(value)}\r\n{value}\r\n".encode())
        conn.recv(64)


count = 0
while True:
    count += 1
    # The cache sidecar stops with the app on idle shutdown while this
    # worker (always_on) keeps running: retry instead of crashing
    try:
        cache_set("worker_heartbeat", "alive role=%s app_name=%s port=%s count=%d" % (
            os.environ.get("WORKER_ROLE", "-"), os.environ.get("app_name", "-"),
            os.environ.get("PORT", "-"), count))
    except OSError:
        pass
    time.sleep(0.5)
