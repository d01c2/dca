import subprocess
import glob
import re
import sys


key_bytes = ["??"] * 8

config_files = glob.glob("*.config")

if not config_files:
    print("[Error] No .config file")
    sys.exit(1)

for config_file in config_files:
    print(f"Processing {config_file}...")

    try:
        result = subprocess.run(
            ["daredevil", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        output = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[Error] daredevil failed for {config_file}: {e.stderr.strip()}")
        continue

    key_byte_sections = re.finditer(
        r"Best 10 candidates for key byte #(\d+) according to [^\n]+\n((?:\s*\d+:\s*0x[0-9a-fA-F]{2}.*\n?)+)",
        output,
    )

    for section in key_byte_sections:
        byte_index = int(section.group(1))
        candidates_text = section.group(2)

        if byte_index < 0 or byte_index > 7:
            print(
                f"[Warning] Skipped: Key byte number {byte_index} out of range in {config_file}"
            )
            continue

        candidate_match = re.search(
            r"^\s*\d+:\s*0x([0-9a-fA-F]{2})", candidates_text, re.MULTILINE
        )
        if candidate_match:
            best_candidate = candidate_match.group(1).lower()
            key_bytes[byte_index] = best_candidate
            print(f"Recovered Key byte number #{byte_index}: {best_candidate}")
        else:
            print(
                f"[Warning] Could not find best candidate for key byte #{byte_index} in {config_file}"
            )

round_key = ""
for i in range(8):
    byte = key_bytes[i]
    if byte == "??":
        print(f"[Warning] Key byte number #{i} was not recovered yet")
    round_key += byte

print(f"Recovered Round Key: {round_key}")

try:
    with open("flag", "w") as f:
        f.write(f"Round Key: {round_key}\n")
    print("Final key appended to ./flag")
except Exception as e:
    print(f"[Error] Could not write to flag file: {e}")
    sys.exit(1)
