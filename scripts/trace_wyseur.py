import sys
from deadpool_dca import *


def processinput(iblock, blocksize):
    p = f"{iblock:0{2 * blocksize}x}"
    return None, [p[j * 2 : (j + 1) * 2] for j in range(len(p) // 2)]


def processoutput(output, blocksize):
    lines = output.split("\n")
    output_line = next(x for x in lines if x.startswith("OUTPUT"))
    hex_str = "".join(output_line[10:].split(" "))
    return int(hex_str, 16)


print("Solving Wyseur Challenge 2007...")

command = [
    "Tracer",
    "-t",
    "ls.db",
    "--",
    "./wbDES/wbDES_wyseur2007",
    "11",
    "22",
    "33",
    "44",
    "55",
    "66",
    "77",
    "88",
]

try:
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
    )

except subprocess.CalledProcessError as e:
    print(f"Error executing Tracer command: {e.stderr}")
    sys.exit(1)

T = TracerPIN("./wbDES/wbDES_wyseur2007", processinput, processoutput, ARCH.i386, 8)
T.run(100)

bin2daredevil(config={"algorithm": "DES", "position": "LUT/DES_SBOX"})
