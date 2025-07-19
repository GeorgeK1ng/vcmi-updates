import urllib.request
import re
from datetime import datetime
import json
import os

URL = "https://builds.vcmi.download/branch/beta/Windows/"
FILENAME = "updates/latest-nightly.json"

print("Fetching builds index...")
response = urllib.request.urlopen(URL)
html = response.read().decode('utf-8')

# Match filenames
matches = re.findall(r'VCMI-branch-beta-([a-f0-9]+)\.exe', html)
if not matches:
    raise RuntimeError("No builds found!")

build_hash = matches[-1]
build_filename = f"VCMI-branch-beta-{build_hash}.exe"
download_url = f"{URL}{build_filename}"

# Match date for the latest build
line_match = re.search(rf'{re.escape(build_filename)}</a></td><td align="right">([0-9]{{4}}-[A-Za-z]{{3}}-[0-9]{{2}} [0-9]{{2}}:[0-9]{{2}})', html)
if not line_match:
    raise RuntimeError("Upload date not found!")

upload_date_str = line_match.group(1)
build_date = datetime.strptime(upload_date_str, "%Y-%b-%d %H:%M").isoformat()

# Output object
data = {
    "updateType": "nightly",
    "version": f"VCMI 1.7-dev-{build_hash}",
    "commit": build_hash,
    "buildDate": build_date,
    "changeLog": "Latest nightly build from develop branch.",
    "downloadLinks": {
        "windows": download_url
    },
    "history": []
}

# Write JSON
os.makedirs("updates", exist_ok=True)
with open(FILENAME, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
print(f"Generated {FILENAME}")
