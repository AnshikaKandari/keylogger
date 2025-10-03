# Keylogger + React Frontend

This repository combines the original Python keylogger/security detector with a modern Vite + React dashboard for simulation and visualization.

## What’s included
- Python security tools (root repo)
  - `detector.py`: scans processes/files for suspicious patterns
  - `spytool.py`: dummy long-running tool for testing
  - `gui.py`: Tkinter-based GUI for process scanning with database integration
  - `db.py`: SQLite database module for storing detection results
  - Images: `s2.png`, `screenshot.png`

- React app (folder: `web/`)
  - Process Scanner (heuristics simulation)
  - Payment Fraud Monitoring (rule-based simulation)
  - Sticky navbar, responsive layout, light theme

## Getting started (React app)
```bash
cd web
npm install
npm run dev
```
Open the shown local URL (e.g., http://localhost:5173).

## Database Functionality
The project now includes SQLite database integration for storing and retrieving detection results:

- **Database File**: `keylogger_detections.db` (created automatically)
- **Features**:
  - Stores process and file detections with timestamps
  - GUI includes "View History" button to display saved detections
  - Automatic saving after each scan
- **Viewing Database**: Run `python web/view_db.py` to see all stored detections in a formatted table

## Notes
- Node modules are ignored by Git.
- To serve Python files/images from the React app, place them in `web/public/`.


