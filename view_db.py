import db

def main():
    print("🔍 Viewing all detections in the database:\n")

    detections = db.get_all_detections()

    if detections:
        print(f"Total detections: {len(detections)}\n")
        print("ID | Timestamp | Type | PID | Name | Path | Reason")
        print("-" * 80)
        for detection in detections:
            id, timestamp, scan_type, pid, name, path, reason, status = detection
            print(f"{id} | {timestamp} | {scan_type} | {pid or 'N/A'} | {name or 'N/A'} | {path or 'N/A'} | {reason}")
    else:
        print("No detections found in the database.")

if __name__ == "__main__":
    main()
