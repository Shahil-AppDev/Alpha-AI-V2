#!/bin/bash

# Setup SSH Key on Server
SERVER_HOST="157.180.107.154"
SERVER_USER="root"
PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLVxvZJak1eaIkRHLdhaqVFFm2RGA7nuLr1fnjIZjdevXgYLiJJ5QVwF1ezzmXeLqOwQLoXu6AhLIdfTvmMD9wBlzQI21FqTobMyK0Gd1uAjd4QfEL0HpMoLBMjSP5tk7Y4YZoze6JCrVuOkR9MoDDa0bLyh4TMc9qfHZnxMp7HRGYAuIlEwDIy95MN1PPJ0ewLCtLoLDI9G56ilp4nizJG+vBpxTY7yirhWNvES0rjMIIoe9acLYqVEoVnEvX8GcmZURGXSYy5saFdKqPaestEKEoAw9km68WUunwb8eMim8VW66F7YVuF+riSk1XNpLK9oZrrq0AcuBxirRuCYR+ZQ5YJxxwEZEYZrLeR9JmDATAH4NBsu7PYZaGdo2UWwY7/ucjjN/XszRzCiFwEpVhs6KKKnIgaIcaxGRYob/zMVXqgD1E+5c7L4wWr4Z2n8qF612Zc5mn99gBzuzAL/UlwJAS0ea9pVxMVAjrayga7lDAkRTq5x57YecTz2zeG3Tby5+PfbUR9vE0+pteB0OM0QFNMNCKECWRDuMh7VxifED3lKRgUAGuLCAbMg52AIGgAFpoDpyZPGuhOhOUtetb7oNDZ/B+Ova1iYbPtu7XpBXOtNpp2wzLLclsKVRGaFNWbr8erlXJxFZ7mX72Pap2YpR7razxNKSLDtzOXqLTrw== github-actions@alpha-ai"

echo "Setting up SSH key on server..."

# Use ssh-copy-id if available, otherwise use manual method
if command -v ssh-copy-id &> /dev/null; then
    echo "$PUBLIC_KEY" | ssh-copy-id -i - $SERVER_USER@$SERVER_HOST
else
    # Manual method
    cat github-actions-key.pub | ssh $SERVER_USER@$SERVER_HOST "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
fi

echo "Testing SSH key authentication..."
ssh -o PasswordAuthentication=no $SERVER_USER@$SERVER_HOST "echo 'SSH key setup successful!'"

if [ $? -eq 0 ]; then
    echo "✅ SSH key authentication working!"
else
    echo "❌ SSH key authentication failed. Please check the setup."
    exit 1
fi
