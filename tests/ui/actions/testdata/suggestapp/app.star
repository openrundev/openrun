# Fixture for the action form suggest flow browser test
# (TestSuggestDropdownAfterSwap). The org options include the values which
# exposed the searchable-select settle bug: quotes and non-ASCII text.
ORGS = ['"test¢£¡¤©«µ³±¶¾¿ÀÆÊÑØÜÞßæçøÐ◦‣₩πψΣΞσ1234', "05-01_tanya", "alpha", "Ω≈∑test"]

def run(dry_run, args):
    return ace.result("org is " + args.org)

def suggest(args):
    return {"org": ORGS}

app = ace.app("Suggest Test App", actions=[ace.action("Pick Org", "/", run, suggest=suggest)])
