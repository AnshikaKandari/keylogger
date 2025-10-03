# Keylogger with Tkinter GUI

This repository contains a Python keylogger with security detector and Tkinter-based GUI for process scanning and database integration.

## What’s included
- Python security tools (root repo)
  - `detector.py`: scans processes/files for suspicious patterns
  - `spytool.py`: dummy long-running tool for testing
  - `gui.py`: Tkinter-based GUI for process scanning with database integration
  - `db.py`: SQLite database module for storing detection results
  - Images: `s2.png`, `screenshot.png`

## Database Functionality
The project now includes SQLite database integration for storing and retrieving detection results:

- **Database File**: `keylogger_detections.db` (created automatically)
- **Features**:
  - Stores process and file detections with timestamps
  - GUI includes "View History" button to display saved detections
  - Automatic saving after each scan
- **Viewing Database**: Run `python view_db.py` to see all stored detections in a formatted table

## Notes
- The Tkinter GUI provides an interface for scanning and viewing detection history.


