import os
import sys
import time

# Job entrypoint: prints the CL_* env the run received and the greeting
# param, then behaves per its mode argument. Output is line buffered so a
# canceled run still shows what it printed
sys.stdout.reconfigure(line_buffering=True)
mode = sys.argv[1]
for key in sorted(os.environ):
    if key.startswith("CL_"):
        print("%s=%s" % (key, os.environ[key]))
print("greeting=%s" % os.environ.get("greeting", "-"))

if mode == "fail":
    print("failing on purpose")
    sys.exit(3)
if mode == "sleep":
    for i in range(120):
        print("sleeping %d" % i)
        time.sleep(1)
print("%s done" % mode)
