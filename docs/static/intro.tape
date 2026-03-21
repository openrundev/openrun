# export PS1="$ "

# Setup openrun.toml with these defaults
#[security]
#app_default_auth_type = "none"
#[client]
#default_format = "basic"


Output intro_dark.gif
Output intro_dark.mp4
Set Theme "Hipster Green"
#Set Theme { "name": "Custom", "background": "#f0ede6", "foreground": "#007700", "selectionBackground": "#3d3c58", "cursorAccent": "#b3b0d6", "cursor": "#b3b0d6" }

Set FontSize 32
Set Width 1200
Set Height 1000
Set Shell "bash"

Hide
Type 'rm -rf openrun.db* flask/app.pye flask/static flask/config_gen.lock && /usr/bin/clear' Enter Sleep 1
Type 'podman stop -at 1 && /usr/bin/clear' Enter Sleep 3
Type 'sed -ie "s/Again/World/" flask/app.py && /usr/bin/clear' Enter
Show

Type "# Start the OpenRun server" Sleep 600ms Enter
Type "openrun server start &" Sleep 600ms Enter
Sleep 1 Enter

Type "# Install app from GitHub url" Sleep 400ms Enter
Type "# This app runs within OpenRun server," Enter
Type "# no containers required" Sleep 400ms Enter
Type "openrun app create --approve github.com/openrundev/apps/system/disk_usage /du" Sleep 400ms Enter
Sleep 2
Enter 2
Type "# List apps, -i option shows internal apps also" Sleep 400ms Enter
Type "# Prod apps always have a staging env" Sleep 400ms Enter
Type "openrun app list -i" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "# Setup a Flask app, from local source" Sleep 400ms Enter
Type "# Requires Docker or Podman to be running" Sleep 400ms Enter
Type "podman ps" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "# Create a dir with source files" Sleep 400ms Enter
Type "cat flask/app.py" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "# --spec option sets the app template to use" Sleep 400ms Enter
Type "# --dev creates app in dev mode" Sleep 400ms Enter
Sleep 1
Type "openrun app create --dev --spec python-flask --approve ./flask /flaskdev" Sleep 400ms  Enter
Sleep 1 Enter 2

Type "# Create a prod mode app also" Sleep 400ms Enter
Sleep 1
Type "openrun app create --spec python-flask --approve ./flask /flask" Sleep 400ms  Enter
Sleep 1 Enter 2

Type "openrun app list -i" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "# No containers yet, lazy load on first request" Sleep 400ms Enter
Type "podman ps" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "# Send an API request to the app" Sleep 400ms Enter
Type "curl -k https://localhost:25223/flaskdev" Enter Sleep 3 Enter 2

Type "podman ps" Sleep 400ms  Enter
Type "# Flask app is running in container" Sleep 400ms  Enter
Sleep 1 Enter 2

Type "# Change the app code" Sleep 400ms  Enter
Type "sed -ie s/World/Again/ flask/app.py" Sleep 400ms  Enter
Sleep 1 Enter 2

Type "curl -k https://localhost:25223/flaskdev" Enter Sleep 2 Enter
Type "# Dev app automatically updated" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "curl -k https://localhost:25223/flask_cl_stage" Enter Sleep 2 Enter
Type "# Prod apps needs explicit reload" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "openrun app reload /flask" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "curl -k https://localhost:25223/flask_cl_stage" Enter Sleep 2 Enter
Type "# Stage is updated" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "openrun app list -i" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "# Promote to prod when stage looks good" Sleep 400ms  Enter
Type "openrun app promote /flask" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "curl -k https://localhost:25223/flask" Enter Sleep 3 Enter
Type "# Prod is updated now" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "# Apps can be installed at the domain level" Sleep 400ms  Enter
Type "# Install proxy to google, - means no source code" Sleep 400ms  Enter
Type "openrun app create --spec proxy --approve -param url=https://www.google.com - google.localhost:/" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "curl -ksI https:/google.localhost:25223 | head -4" Enter Sleep 2
Type "# The API call is proxied to google" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "# Install apps which use React and Websockets" Sleep 400ms  Enter
Type "# Streamlit builds a UI from python code" Sleep 400ms  Enter
Type "# Easily build internal tools" Sleep 400ms  Enter
Type "openrun app create --spec python-streamlit --branch master --approve github.com/streamlit/streamlit-example /streamlit" Sleep 400ms Enter
Sleep 2 Enter

Type "openrun app list -i" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "# Do atomic reload across multiple apps" Sleep 400ms  Enter
Type "# In dry-run mode" Sleep 400ms  Enter
Type 'openrun app reload --dry-run all' Sleep 400ms  Enter
Sleep 3 Enter 2

Type "# Or without dry-run, promoting immediately" Sleep 400ms  Enter
Type 'openrun app reload --promote /flask' Sleep 400ms  Enter
Sleep 3 Enter 2

Type "openrun app list -i" Sleep 400ms  Enter
Sleep 3 Enter 2


Type "# All code/config changes are staged by default" Sleep 400ms Enter
Type "# No more scrambling to revert broken prod apps!!" Sleep 400ms Enter
Type "# Reverts are also easy, if still needed" Sleep 400ms Enter
Type "openrun version list /flask" Sleep 400ms Enter
Sleep 1 Enter 1

Type "openrun version revert /flask" Sleep 400ms Enter
Sleep 1 Enter 1

Type "openrun version list /flask" Sleep 400ms Enter
Sleep 1 Enter 3


Type "# OpenRun - Web app management platform" Sleep 400ms  Enter
Type "# Easy, light-weight web app management"  Enter
Type "# for internal tools. Setup OAuth auth easily" Sleep 400ms  Enter 2
Type "# Cross-platform, works on Linux/Windows/OSX" Sleep 400ms Enter
Sleep 6
