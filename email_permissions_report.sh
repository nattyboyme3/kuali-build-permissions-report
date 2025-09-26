#!/bin/bash

# Email Kuali Permissions Report Script
# Usage: ./email_permissions_report.sh recipient@example.com [app_id]
# 
# Examples:
#   ./email_permissions_report.sh admin@university.edu                    # All apps report
#   ./email_permissions_report.sh admin@university.edu 68b050dade5d57027  # Single app report

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate virtual environment relative to script location
source "$SCRIPT_DIR/venv/bin/activate"

set -euo pipefail

# Check if recipient email is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <recipient_email> [app_id]"
    echo ""
    echo "Examples:"
    echo "  $0 admin@university.edu                    # Generate report for all apps"
    echo "  $0 admin@university.edu 68b050dade5d57027  # Generate report for single app"
    exit 1
fi

RECIPIENT="$1"
APP_ID="${2:-}"

# Check if mail command is available
if ! command -v mail >/dev/null 2>&1; then
    echo "Error: 'mail' command not found. Please install mailutils or similar package."
    echo "On Ubuntu/Debian: sudo apt-get install mailutils"
    echo "On macOS: mail should be available by default"
    exit 1
fi

# Set up temporary files
TEMP_DIR=$(mktemp -d)
OUTPUT_FILE="$TEMP_DIR/permissions_output.txt"
ERROR_FILE="$TEMP_DIR/permissions_error.txt"

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Change to script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting Kuali Permissions Report..."
echo "Recipient: $RECIPIENT"

if [ -n "$APP_ID" ]; then
    echo "Mode: Single app report for $APP_ID"
    SUBJECT="Kuali Permissions Report - App $APP_ID"
else
    echo "Mode: All apps report"
    SUBJECT="Kuali Permissions Report - All Applications"
fi

# Run the permissions client and capture output
echo "Running permissions analysis..."
if [ -n "$APP_ID" ]; then
    # Single app mode
    python permissions_client.py "$APP_ID" > "$OUTPUT_FILE" 2> "$ERROR_FILE"
else
    # All apps mode
    python permissions_client.py > "$OUTPUT_FILE" 2> "$ERROR_FILE"
fi

EXIT_CODE=$?

# Check if the script ran successfully
if [ $EXIT_CODE -ne 0 ]; then
    echo "Error: Permissions client failed with exit code $EXIT_CODE"
    echo "Error output:"
    cat "$ERROR_FILE"
    
    # Send error email
    {
        echo "Kuali Permissions Report failed to generate."
        echo ""
        echo "Exit code: $EXIT_CODE"
        echo ""
        echo "Error output:"
        cat "$ERROR_FILE"
        echo ""
        echo "Standard output:"
        cat "$OUTPUT_FILE"
    } | mail -s "ERROR: $SUBJECT" "$RECIPIENT"
    
    exit $EXIT_CODE
fi

# Extract CSV filename from output
CSV_FILE=""
if grep -q "CSV_FILE:" "$OUTPUT_FILE"; then
    CSV_FILE=$(grep "CSV_FILE:" "$OUTPUT_FILE" | cut -d: -f2)
    echo "Found CSV file: $CSV_FILE"
else
    echo "Warning: No CSV file found in output"
fi

# Prepare email body
EMAIL_BODY="$TEMP_DIR/email_body.txt"
{
    echo "Kuali Permissions Report completed successfully."
    echo ""
    echo "Report Details:"
    if [ -n "$APP_ID" ]; then
        echo "  Mode: Single application report"
        echo "  App ID: $APP_ID"
    else
        echo "  Mode: All applications report"
    fi
    echo "  Generated: $(date)"
    echo ""
    
    if [ -n "$CSV_FILE" ] && [ -f "$CSV_FILE" ]; then
        echo "CSV report is attached to this email."
        echo ""
    fi
    
    echo "Full output:"
    echo "============"
    cat "$OUTPUT_FILE"
    
    if [ -s "$ERROR_FILE" ]; then
        echo ""
        echo "Warnings/Errors:"
        echo "==============="
        cat "$ERROR_FILE"
    fi
} > "$EMAIL_BODY"

# Send email with or without attachment
echo "Sending email to $RECIPIENT..."

if [ -n "$CSV_FILE" ] && [ -f "$CSV_FILE" ]; then
    # Send with CSV attachment
    if command -v uuencode >/dev/null 2>&1; then
        # Use uuencode for attachment (more widely available)
        {
            cat "$EMAIL_BODY"
            echo ""
            echo "--- CSV Report Attachment ---"
            uuencode "$CSV_FILE" "$(basename "$CSV_FILE")"
        } | mail -s "$SUBJECT" "$RECIPIENT"
    else
        # Fallback: try to use mail with attachment flag (if supported)
        if mail -A "$CSV_FILE" -s "$SUBJECT" "$RECIPIENT" < "$EMAIL_BODY" 2>/dev/null; then
            echo "Email sent with attachment using -A flag"
        else
            # Final fallback: include CSV content in email body
            echo "Warning: Could not attach file, including CSV content in email body"
            {
                cat "$EMAIL_BODY"
                echo ""
                echo "--- CSV Report Content ---"
                cat "$CSV_FILE"
            } | mail -s "$SUBJECT" "$RECIPIENT"
        fi
    fi
else
    # Send without attachment
    mail -s "$SUBJECT" "$RECIPIENT" < "$EMAIL_BODY"
fi

echo "Email sent successfully!"

if [ -n "$CSV_FILE" ] && [ -f "$CSV_FILE" ]; then
    echo "CSV file location: $CSV_FILE"
fi

echo "Done."