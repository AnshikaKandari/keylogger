import sqlite3
import json
from datetime import datetime

DB_NAME = 'keylogger_detections.db'

def init_db():
    """Initialize the database and create tables if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create detections table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL,  -- 'process' or 'file'
            pid INTEGER,  -- NULL for files
            name TEXT,
            path TEXT,
            reason TEXT,
            status TEXT DEFAULT 'detected'
        )
    ''')

    conn.commit()
    conn.close()

def save_detection(scan_type, pid=None, name=None, path=None, reason=None):
    """Save a detection to the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    timestamp = datetime.now().isoformat()

    cursor.execute('''
        INSERT INTO detections (timestamp, scan_type, pid, name, path, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, scan_type, pid, name, path, reason))

    conn.commit()
    conn.close()

def get_all_detections():
    """Retrieve all detections from the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM detections ORDER BY timestamp DESC')
    rows = cursor.fetchall()

    conn.close()
    return rows

def get_detections_by_type(scan_type):
    """Retrieve detections by type ('process' or 'file')."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM detections WHERE scan_type = ? ORDER BY timestamp DESC', (scan_type,))
    rows = cursor.fetchall()

    conn.close()
    return rows

def clear_all_detections():
    """Clear all detections from the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM detections')
    conn.commit()
    conn.close()

# Initialize database on import
init_db()

# Test function to verify database functionality
if __name__ == "__main__":
    print("Testing database functionality...")

    # Test saving a detection
    save_detection('process', 1234, 'test_process', 'C:\\test.exe', 'Test detection')
    save_detection('file', None, None, 'C:\\test.py', 'Suspicious content')

    # Test retrieving detections
    detections = get_all_detections()
    print(f"Found {len(detections)} detections:")
    for detection in detections:
        print(detection)

    print("Database test completed!")
