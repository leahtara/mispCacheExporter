#!/usr/bin/env python3
"""
MISP Database IOC Extractor

This script connects to a locally running MISP MySQL/MariaDB database and extracts
IOCs (Indicators of Compromise) from the last 24 hours. It's designed to be run
as a daily cron job to cache recently added/updated threat indicators.

The script outputs a list of dictionaries containing IOC data which can be
used for further processing or converted to JSON for downstream applications.

Usage:
    python misp_db_extractor.py [config_file]

    If config_file is not provided, the script will look for misp_db_config.json
    in the same directory.

Requirements:
    - MySQL Connector for Python: pip install mysql-connector-python
    - Access to the MISP database (usually on localhost)
"""

import os
import sys
import logging
import json
import datetime
import argparse
import mysql.connector
from mysql.connector import Error
import shutil  # Added for file operations

# Set up the script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Configure logging
LOG_FILE = os.path.join(SCRIPT_DIR, 'misp_db_extractor.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('misp_db_extractor')

def load_config(config_path=None):
    """
    Load configuration from JSON file
    
    Args:
        config_path: Path to configuration file (optional)
        
    Returns:
        dict: Configuration dictionary
    """
    if not config_path:
        config_path = os.path.join(SCRIPT_DIR, 'misp_db_config.json')
    
    try:
        with open(config_path, 'r') as config_file:
            config = json.load(config_file)
            logger.info(f"Loaded configuration from {config_path}")
            return config
    except Exception as e:
        logger.error(f"Error loading configuration from {config_path}: {e}")
        logger.warning("Using default configuration")
        return {
            "database": {
                "host": "localhost", 
                "port": 3306,
                "user": "USERNAME",
                "password": "PASSWORD", 
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
                "cache_db": "ioc_cache.db",
                "backup_db": "ioc_cache_yesterday.db"  # Added backup db name
            }
        }

# Parse command line arguments
parser = argparse.ArgumentParser(description='Extract IOCs from MISP database')
parser.add_argument('--config', help='Path to configuration file')
args = parser.parse_args()

# Load configuration
config = load_config(args.config)

# Database connection configuration
DB_CONFIG = config['database']

# IOC Types to extract (MISP attribute types)
IOC_TYPES = config['extraction']['ioc_types']

def connect_to_db():
    """
    Establish a connection to the MISP database.
    
    Returns:
        connection: MySQL connection object or None if connection fails
    """
    try:
        logger.info("Connecting to MISP database...")
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            logger.info(f"Successfully connected to MISP database (MySQL version: {connection.server_info})")
            return connection
    except Error as e:
        logger.error(f"Error connecting to MISP database: {e}")
        return None


def fetch_recent_iocs(connection, hours=None):
    """
    Fetch IOCs from the MISP database that were created or updated 
    in the last specified number of hours.
    
    Args:
        connection: MySQL connection object
        hours: Number of hours to look back (None will use config value)
        
    Returns:
        list: List of dictionaries containing IOC data
    """
    if hours is None:
        hours = config['extraction']['hours_lookback']
    iocs = []
    cursor = None
    
    try:
        if not connection or not connection.is_connected():
            logger.error("Database connection is not established")
            return iocs
            
        cursor = connection.cursor(dictionary=True)
        
        # Calculate timestamp for the lookback period
        lookback_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
        timestamp = lookback_time.strftime("%Y-%m-%d %H:%M:%S")
        
        # SQL query to fetch recent IOCs
        # This query joins the events and attributes tables to get comprehensive IOC data
        query = """
        SELECT 
            e.id as event_id,
            e.uuid as event_uuid,
            e.info as event_info,
            e.date as event_date,
            e.timestamp as event_timestamp,
            a.id as attribute_id,
            a.type as attribute_type,
            a.category as attribute_category,
            a.value1 as attribute_value,
            a.timestamp as attribute_timestamp,
            a.comment as attribute_comment,
            a.to_ids as attribute_to_ids
        FROM 
            events e
        JOIN 
            attributes a ON e.id = a.event_id
        WHERE 
            a.type IN ({})
            AND (a.timestamp >= %s OR e.timestamp >= %s)
        ORDER BY 
            a.timestamp DESC
        """.format(','.join(['%s'] * len(IOC_TYPES)))
        
        # Execute the query with parameters
        params = IOC_TYPES + [timestamp, timestamp]
        cursor.execute(query, params)
        
        # Fetch and process results
        for row in cursor:
            # Convert timestamps to readable format
            if 'event_timestamp' in row and row['event_timestamp']:
                event_dt = datetime.datetime.fromtimestamp(row['event_timestamp'])
                row['event_timestamp'] = event_dt.strftime("%Y-%m-%d %H:%M:%S")
                
            if 'attribute_timestamp' in row and row['attribute_timestamp']:
                attr_dt = datetime.datetime.fromtimestamp(row['attribute_timestamp'])
                row['attribute_timestamp'] = attr_dt.strftime("%Y-%m-%d %H:%M:%S")
                
            iocs.append(row)
            
        logger.info(f"Retrieved {len(iocs)} IOCs from the past {hours} hours")
        
    except Error as e:
        logger.error(f"Error querying MISP database: {e}")
    finally:
        if cursor:
            cursor.close()
            
    return iocs


def save_to_json(iocs, output_file=None):
    """
    Save the IOCs to a JSON file.
    
    Args:
        iocs: List of IOC dictionaries
        output_file: File path for the JSON output (None will use config value)
    """
    if output_file is None:
        output_file = os.path.join(SCRIPT_DIR, config['output']['json_file'])
    try:
        with open(output_file, 'w') as f:
            json.dump(iocs, f, indent=4)
        logger.info(f"Successfully saved {len(iocs)} IOCs to {output_file}")
    except Exception as e:
        logger.error(f"Error saving IOCs to file {output_file}: {e}")


def backup_cache_db(db_path, backup_path=None):
    """
    Create a backup of the existing cache database.
    
    Args:
        db_path: Path to the current SQLite database file
        backup_path: Path where backup will be saved (None will use config value)
    
    Returns:
        bool: True if backup was successful or not needed, False if it failed
    """
    if backup_path is None:
        backup_path = os.path.join(SCRIPT_DIR, config['output'].get('backup_db', 'ioc_cache_yesterday.db'))
    
    try:
        # Check if the current cache exists
        if os.path.exists(db_path):
            # Backup the existing file
            shutil.copy2(db_path, backup_path)
            logger.info(f"Created backup of IOC cache at {backup_path}")
            
            # Remove the current file to start fresh
            os.remove(db_path)
            logger.info(f"Removed old IOC cache at {db_path} to create fresh database")
        else:
            logger.info(f"No existing IOC cache found at {db_path}, no backup needed")
        return True
    except Exception as e:
        logger.error(f"Error backing up cache database: {e}")
        return False


def save_to_cache_db(iocs, db_path=None):
    """
    Save the IOCs to a SQLite cache database.
    
    Args:
        iocs: List of IOC dictionaries
        db_path: Path to the SQLite database file (None will use config value)
    """
    if db_path is None:
        db_path = os.path.join(SCRIPT_DIR, config['output']['cache_db'])
    
    # Backup the existing database before proceeding
    backup_path = os.path.join(SCRIPT_DIR, config['output'].get('backup_db', 'ioc_cache_yesterday.db'))
    if not backup_cache_db(db_path, backup_path):
        logger.warning("Proceeding with database update without backup")
    
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS misp_iocs (
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
            import_time TEXT,
            executive_summary TEXT
        )
        ''')
        
        # Create indices for faster lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attribute_type ON misp_iocs (attribute_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attribute_value ON misp_iocs (attribute_value)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_id ON misp_iocs (event_id)')
        
        # Insert IOCs into database
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for ioc in iocs:
            cursor.execute('''
            INSERT INTO misp_iocs (
                event_id, event_uuid, event_info, event_date, event_timestamp,
                attribute_id, attribute_type, attribute_category, attribute_value,
                attribute_timestamp, attribute_comment, attribute_to_ids, import_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ioc.get('event_id'),
                ioc.get('event_uuid'),
                ioc.get('event_info'),
                ioc.get('event_date'),
                ioc.get('event_timestamp'),
                ioc.get('attribute_id'),
                ioc.get('attribute_type'),
                ioc.get('attribute_category'),
                ioc.get('attribute_value'),
                ioc.get('attribute_timestamp'),
                ioc.get('attribute_comment'),
                ioc.get('attribute_to_ids', 0),
                current_time
            ))
        
        conn.commit()
        logger.info(f"Successfully saved {len(iocs)} IOCs to cache database {db_path}")
        
    except Exception as e:
        logger.error(f"Error saving IOCs to cache database {db_path}: {e}")
    finally:
        if 'conn' in locals():
            conn.close()


def main():
    """
    Main function to orchestrate the IOC extraction process.
    """
    try:
        # Connect to the database
        connection = connect_to_db()
        if not connection:
            logger.error("Failed to connect to database. Exiting.")
            sys.exit(1)
            
        # Fetch the recent IOCs
        hours_lookback = config['extraction']['hours_lookback']
        logger.info(f"Fetching IOCs from the last {hours_lookback} hours")
        iocs = fetch_recent_iocs(connection)
        
        if not iocs:
            logger.warning("No IOCs found in the specified time period")
        else:
            # Save to JSON file
            json_file = config['output']['json_file']
            json_path = os.path.join(SCRIPT_DIR, json_file)
            save_to_json(iocs, json_path)
            
            # Save to cache database
            db_file = config['output']['cache_db']
            db_path = os.path.join(SCRIPT_DIR, db_file)
            save_to_cache_db(iocs, db_path)
            
            logger.info(f"Process completed successfully. Retrieved {len(iocs)} IOCs.")
            
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
    finally:
        # Close the database connection
        if 'connection' in locals() and connection and connection.is_connected():
            connection.close()
            logger.info("Database connection closed")


if __name__ == "__main__":
    main()
