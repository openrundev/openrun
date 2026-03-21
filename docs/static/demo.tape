# vhs script
# export PS1="$ "

Output demo_light.gif
Output demo_light.mp4
#Set Theme "Hipster Green"
Set Theme { "name": "Custom", "background": "#f0ede6", "foreground": "#007700", "selectionBackground": "#3d3c58", "cursorAccent": "#b3b0d6", "cursor": "#b3b0d6" }

Set FontSize 32
Set Width 1200
Set Height 1000
Set Shell "bash"

Hide
Type '/usr/bin/clear' Enter Sleep 2
Show

Type "# Start the OpenRun server" Sleep 600ms Enter
Type "openrun server start &" Sleep 600ms Enter
Sleep 2 Enter

Type "# Install an app using CLI" Sleep 400ms Enter
Type "openrun app create --approve github.com/openrundev/apps/system/disk_usage /du" Sleep 400ms Enter
Sleep 2
Enter 2
Type "# Every app has a staging location" Sleep 400ms Enter
Type "openrun app list -i" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "# Apps can be created declaratively" Sleep 400ms Enter
Type "# utils.star defines multiple apps" Sleep 400ms Enter
Type "cat utils.star" Sleep 400ms  Enter
Sleep 3 Enter 2

Type "# Install apps using declarative interface" Sleep 400ms Enter
Type "openrun apply --approve github.com/openrundev/openrun/examples/utils.star" Sleep 400ms Enter
Sleep 2 Enter 2
Type "# List apps" Sleep 400ms Enter
Type "openrun app list" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "# ** Enable GitOps in one command **" Sleep 400ms Enter
Sleep 2 Enter 2
Type "openrun sync schedule --approve --promote github.com/openrundev/openrun/examples/utils.star" Sleep 400ms  Enter
Sleep 4 Enter 2
Type "# This creates an automated background sync" Sleep 400ms Enter
Type "# New apps are auto created from config" Sleep 400ms Enter
Type "# Existing apps get auto code/config updates" Sleep 400ms Enter
Type "openrun sync list" Sleep 400ms  Enter
Sleep 2 Enter 2

Type "# OpenRun - App deployment simplified" Sleep 400ms  Enter
Type "# Easily deploy internal tools across a team." Sleep 400ms  Enter 2
Type "# Cross-platform, works on Linux/Windows/OSX" Sleep 400ms Enter
Sleep 4

Hide
Type 'openrun server stop && rm -rf metadata/*' Enter
Show


