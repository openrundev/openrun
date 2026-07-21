load("fs.in", "fs")
load("exec.in", "exec")
load("http.in", "http")

def handler(req):
   exec.run("sh", ["-c", "rm -rf /tmp/fileapptmp"])
   exec.run("sh", ["-c", "mkdir /tmp/fileapptmp"])
   ret1 = exec.run("sh", ["-c", "echo \"abc\" > /tmp/fileapptmp/testfileapp.txt"])
   ret11 = exec.run("sh", ["-c", "echo \"abc\" > /tmp/fileapptmp/testfileapp2.txt"])
   ret2 = fs.serve_tmp_file("/tmp/fileapptmp/testfileapp.txt") # single_access=True is default
   ret3 = fs.serve_tmp_file("/tmp/fileapptmp/testfileapp2.txt", single_access=False)

   # AppUrl is "scheme://host" + AppPath; strip AppPath back off to get the
   # bare origin, since serve_tmp_file's url is already app-path-relative.
   # This avoids hardcoding the server's port, which varies per test run.
   origin = req.AppUrl[:len(req.AppUrl) - len(req.AppPath)]

   # First attempt works
   ret4 = http.get(origin + ret2.value["url"])
   ret5 = http.get(origin + ret3.value["url"], error_on_fail=True)
   # Second attempt  fails for file1 (it got deleted on first GET call), works for file2 as it is multi_access
   ret6 = http.get(origin + ret2.value["url"], error_on_fail=False)
   if ret6.value.status_code == 200:
      return "Error: %d" % ret6.value.status_code
   ret7 = http.get(origin + ret3.value["url"])

   ret8 = fs.find("/tmp/fileapptmp", "testfileapp.txt")
   if len(ret8.value) != 0:
      return "Error: expected no files on disk %s"  % ret8.value
   ret9 = fs.find("/tmp/fileapptmp", "testfileapp2.txt")
   if len(ret9.value) == 0:
      return "Error: expected files on disk"

   return "Success"

app = ace.app("file test",
              routes = [ace.api("/", type=ace.TEXT)],
              permissions = [
              ace.permission("fs.in", "serve_tmp_file"),
              ace.permission("fs.in", "find"),
              ace.permission("exec.in", "run"),
              ace.permission("http.in", "get")]
             )
