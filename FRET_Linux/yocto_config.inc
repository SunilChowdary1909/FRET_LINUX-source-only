# --- FRET Analysis Config ---
MACHINE ?= "qemuarm64"
EXTRA_IMAGE_FEATURES += "tools-debug debug-tweaks"
DEBUG_BUILD = "1"
INHIBIT_PACKAGE_STRIP = "1"
INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
# Limit parallelism to avoid thread exhaustion
BB_NUMBER_THREADS = "8"
PARALLEL_MAKE = "-j 8"
