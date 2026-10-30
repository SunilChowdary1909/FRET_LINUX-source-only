#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: sudo $0 <app_name>"
    echo "Example: sudo $0 state_machine_app"
    exit 1
fi

APP_NAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$SCRIPT_DIR/bin/$APP_NAME"
ROOTFS="../linux_artifacts/rootfs.ext4"
MOUNT_POINT="/tmp/rootfs_mount_$$"

if [ ! -f "$BIN_PATH" ]; then
    echo "Error: Binary not found: $BIN_PATH"
    echo "Run ./build_apps.sh first"
    exit 1
fi

if [ ! -f "$ROOTFS" ]; then
    echo "Error: rootfs not found: $ROOTFS"
    exit 1
fi

echo "========================================="
echo " Installing $APP_NAME to rootfs"
echo "========================================="
echo "Binary: $BIN_PATH"
echo "Rootfs: $ROOTFS"
echo ""

# Create temporary mount point
mkdir -p "$MOUNT_POINT"

# Mount rootfs
echo "Mounting rootfs..."
mount -o loop "$ROOTFS" "$MOUNT_POINT"

# Create apps directory
echo "Creating /home/apps directory..."
mkdir -p "$MOUNT_POINT/home/apps"

# Copy binary
echo "Copying $APP_NAME..."
cp "$BIN_PATH" "$MOUNT_POINT/home/apps/"
chmod +x "$MOUNT_POINT/home/apps/$APP_NAME"

# Create startup script
echo "Creating autostart script..."
cat > "$MOUNT_POINT/home/apps/run_demo.sh" << 'EOF'
#!/bin/sh
echo "Starting state machine demo..."
cd /home/apps
./state_machine_app 100 200 &
echo "Demo app started (PID: $!)"
EOF
chmod +x "$MOUNT_POINT/home/apps/run_demo.sh"

# Show what's in the apps directory
echo ""
echo "Contents of /home/apps:"
ls -lh "$MOUNT_POINT/home/apps/"

# Unmount
echo ""
echo "Unmounting rootfs..."
umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

echo ""
echo "========================================="
echo " Installation Complete!"
echo "========================================="
echo ""
echo "To run in QEMU:"
echo "  (inside QEMU shell)"
echo "  cd /home/apps"
echo "  ./state_machine_app 50 200"
echo ""
echo "Or use autostart:"
echo "  sh /home/apps/run_demo.sh"
echo ""
