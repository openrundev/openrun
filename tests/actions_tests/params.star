# Params for the actions test app, covering every input type the action
# form UI supports: text, int, boolean, list-options select, suggest-based
# select, password, textarea, file upload and hidden params.

param("app_name", description="Name of the app to operate on", default="orders-api")

param("env", description="Target environment (strict searchable dropdown, value must be in the list)", default="dev")

param("options_env", type=LIST, description="Options for env", default=["dev", "staging", "prod"])

param("region", description="Deploy region (COMBO: pick a suggestion or type a custom value)", default="", display_type=COMBO)

param("replicas", type=INT, description="Number of replicas to run", default=2)

param("notify", type=BOOLEAN, description="Notify the team after the run", default=True)

param("api_token", description="API token used for the deploy call", default="", display_type=PASSWORD)

param("notes", description="Release notes for this deploy", default="", display_type="textarea:5")

param("upload", description="File to process", default="", display_type=FILE)

param("audit_tag", description="Internal audit tag, hidden in all actions", default="cli-only")
