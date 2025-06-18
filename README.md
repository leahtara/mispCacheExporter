# MISP DB IOC Extractor

This tool connects to a locally running MISP MySQL/MariaDB database and extracts Indicators of Compromise (IOCs) that were created or updated in the last 24 hours. It's designed to be run as a daily cron job to fetch and cache recent threat indicators.

## Features

* Connects securely to a local MISP database
* Extracts IOCs from the past 24 hours (configurable)
* Supports multiple IOC types (IP addresses, domains, URLs, hashes, etc.)
* Optimized database query to reduce overhead
* Saves results in both JSON format and SQLite database for easy access
* Configurable via external JSON configuration file
* Comprehensive logging
* Includes cron job setup script

## Requirements

* Python 3.6+
* MySQL Connector for Python: `pip install mysql-connector-python`
* Access to the MISP MySQL/MariaDB database (usually on localhost)

## Installation

1. Clone or download this repository to your local machine
2. Install the required Python package:
   ```
   pip install mysql-connector-python
   ```
3. Edit the configuration file (`misp_db_config.json`) with your MISP database credentials

## Configuration

Edit `misp_db_config.json` to configure the script:

```json
{
    "database": {
        "host": "localhost",
        "port": 3306,
        "user": "YOUR_USERNAME",
        "password": "YOUR_PASSWORD",
        "database": "misp"
    },
    "extraction": {
        "hours_lookback": 24,
        "ioc_types": [
            "ip-src", "ip-dst", "domain", "hostname", "url", 
            "md5", "sha1", "sha256", "filename", "email-src", 
            "email-dst", "mutex", "regkey", "snort", "yara"
        ]
    },
    "output": {
        "json_file": "misp_recent_iocs.json",
        "cache_db": "ioc_cache.db"
    }
}
```

## Usage

### Manual Execution

Run the script directly:

```bash
python3 misp_db_extractor.py
```

You can specify a custom configuration file:

```bash
python misp_db_extractor.py --config /path/to/your/config.json
```

### Setting Up as a Cron Job

A helper script is provided to set up a daily cron job that runs at 2AM:

```bash
bash setup_daily_extractor.sh
```

## Output

The script generates two outputs:

1. A JSON file (`misp_recent_iocs.json` by default) containing all extracted IOCs
2. A SQLite database (`ioc_cache.db` by default) for efficient querying and downstream processing

## Example JSON Output

```json
[
    {
        "event_id": 123,
        "event_uuid": "5f9c8d7e-1a2b-3c4d-5e6f-7g8h9i0j1k2l",
        "event_info": "Ransomware Campaign June 2025",
        "event_date": "2025-06-17",
        "event_timestamp": "2025-06-17 15:30:21",
        "attribute_id": 456,
        "attribute_type": "ip-dst",
        "attribute_category": "Network activity",
        "attribute_value": "192.0.2.123",
        "attribute_timestamp": "2025-06-17 15:30:21",
        "attribute_comment": "C2 server for ransomware",
        "attribute_to_ids": 1
    },
    ...
]
```

## SQLite Database Schema

The IOCs are stored in a SQLite database with the following schema:

```sql
CREATE TABLE misp_iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    event_uuid TEXT,
    event_info TEXT,
    event_date TEXT,
    event_timestamp TEXT,
    attribute_id INTEGER,
    attribute_type TEXT,
    attribute_category TEXT,
    attribute_value TEXT,
    attribute_timestamp TEXT,
    attribute_comment TEXT,
    attribute_to_ids INTEGER,
    import_time TEXT
)
```

## Integration

The extracted IOCs can be easily integrated with other components of the ThreatIntel Co-Pilot project for further processing and analysis.

## Logging

Logs are written to both the console and a log file (`misp_db_extractor.log`) in the same directory as the script.

## Error Handling

The script includes comprehensive error handling for:
- Database connection failures
- Query execution errors
- File I/O issues
- General exceptions

## License

This script is part of the ThreatIntel Co-Pilot project.
