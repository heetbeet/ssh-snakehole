"""A terminal producer which needs no keyboard input or capability replies."""

import sys

sys.stdout.write(
    "BURST-BEGIN\n" + "burst-line\n" * 10000 + "BURST-END\nAPP-QUERY:\x1b[c"
)
sys.stdout.flush()
