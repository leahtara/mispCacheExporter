#!/bin/bash
# This script sets up daily cron jobs to run MISP feed fetching and the MISP DB IOC extractor

# Get the absolute path to the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
EXTRACTOR_SCRIPT="$SCRIPT_DIR/misp_db_extractor.py"
CONFIG_FILE="$SCRIPT_DIR/misp_api_config.json"

# Make the extractor script executable
chmod +x "$EXTRACTOR_SCRIPT"

# Ask user for MISP API key if not already stored
if [ -f "$CONFIG_FILE" ]; then
    echo "API configuration file already exists."
    read -p "Do you want to update the API key? (y/n): " update_key
    if [ "$update_key" = "y" ]; then
        read -p "Enter your MISP API key: " api_key
        echo "{\"api_key\":\"$api_key\"}" > "$CONFIG_FILE"
        echo "API key updated."
    fi
else
    read -p "Enter your MISP API key: " api_key
    echo "{\"api_key\":\"$api_key\"}" > "$CONFIG_FILE"
    echo "API key stored in $CONFIG_FILE."
fi

# Get API key from config file
API_KEY=$(grep -o '"api_key":"[^"]*' "$CONFIG_FILE" | cut -d'"' -f4)

# Create a temp file for the crontab
TEMP_CRON=$(mktemp)

# Export current crontab
crontab -l > "$TEMP_CRON" 2>/dev/null || echo "# New crontab" > "$TEMP_CRON"

# Check if the feed fetching entry already exists
if ! grep -q "fetchFromAllFeeds" "$TEMP_CRON"; then
    # Add the feed fetching cron job - run daily at 5 minutes past midnight
    echo "# ThreatIntel Co-Pilot: Daily MISP feed fetching" >> "$TEMP_CRON"
    echo "5 0 * * * /usr/bin/curl -XPOST --insecure --header \"Authorization: $API_KEY\" --header \"Accept: application/json\" --header \"Content-Type: application/json\" https://localhost/feeds/fetchFromAllFeeds >> $SCRIPT_DIR/cron_fetch.log 2>&1" >> "$TEMP_CRON"
    echo "Feed fetching cron job installed. Will run daily at 12:05 AM."
else
    echo "Cron job for MISP feed fetching already exists."
fi

# Check if the extractor entry already exists
if ! grep -q "misp_db_extractor.py" "$TEMP_CRON"; then
    # Add the extraction cron job - run daily at 2AM
    echo "# ThreatIntel Co-Pilot: Daily MISP IOC extraction" >> "$TEMP_CRON"
    echo "0 2 * * * cd $SCRIPT_DIR && python3 $EXTRACTOR_SCRIPT >> $SCRIPT_DIR/cron_extract.log 2>&1" >> "$TEMP_CRON"
    echo "IOC extractor cron job installed. Will run daily at 2:00 AM."
else
    echo "Cron job for MISP DB IOC extractor already exists."
fi

# Install the new crontab
crontab "$TEMP_CRON"

# Clean up
rm "$TEMP_CRON"

echo "Setup complete."
echo "Note: Make sure to edit misp_db_config.json to set your database credentials."
echo "The API key is stored in $CONFIG_FILE. Protect this file with appropriate permissions."

# Set restricted permissions on the config file
chmod 600 "$CONFIG_FILE"
