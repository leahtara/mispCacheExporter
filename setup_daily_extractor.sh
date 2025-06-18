#!/bin/bash
# This script sets up a daily cron job to run the MISP DB IOC extractor

# Get the absolute path to the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
EXTRACTOR_SCRIPT="$SCRIPT_DIR/misp_db_extractor.py"

# Make the script executable
chmod +x "$EXTRACTOR_SCRIPT"

# Create a temp file for the crontab
TEMP_CRON=$(mktemp)

# Export current crontab
crontab -l > "$TEMP_CRON" 2>/dev/null || echo "# New crontab" > "$TEMP_CRON"

# Check if the entry already exists
if ! grep -q "misp_db_extractor.py" "$TEMP_CRON"; then
    # Add the cron job - run daily at 2AM
    echo "# ThreatIntel Co-Pilot: Daily MISP IOC extraction" >> "$TEMP_CRON"
    echo "0 2 * * * cd $SCRIPT_DIR && python3 $EXTRACTOR_SCRIPT >> $SCRIPT_DIR/cron_extract.log 2>&1" >> "$TEMP_CRON"
    
    # Install the new crontab
    crontab "$TEMP_CRON"
    echo "Cron job installed. The MISP DB IOC extractor will run daily at 2:00 AM."
else
    echo "Cron job for MISP DB IOC extractor already exists."
fi

# Clean up
rm "$TEMP_CRON"

echo "Setup complete."
echo "Note: Make sure to edit misp_db_config.json to set your database credentials."
