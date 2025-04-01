#!/usr/bin/env python3
"""
Update progress tracking for the fleet management implementation plan.
This script should be executed at the end of each implementation turn.
"""

import json
import sys
import os
from datetime import datetime
from tasks import progress

def update_progress():
    """Update progress tracking with command line arguments"""
    if len(sys.argv) < 2:
        print("Usage: python update_progress.py [action] [data]")
        print("Actions: current, completed, next")
        print("Example: python update_progress.py current 'Implementing resource discovery module'")
        return
    
    action = sys.argv[1].lower()
    data = sys.argv[2] if len(sys.argv) > 2 else None
    
    if action == "current" and data:
        progress.current_focus = [data]
    elif action == "completed" and data:
        progress.completed.append(data)
    elif action == "next" and data:
        progress.next_steps.append(data)
    elif action == "save":
        # Save current progress to JSON file for persistence
        with open("progress_history.json", "a") as f:
            timestamp = datetime.now().isoformat()
            entry = {
                "timestamp": timestamp,
                "current_focus": progress.current_focus,
                "completed": progress.completed,
                "next_steps": progress.next_steps
            }
            f.write(json.dumps(entry) + "\n")
        print(f"Progress saved at {timestamp}")
    else:
        print(f"Unknown action: {action}")
    
    # Display current progress
    print(progress)

if __name__ == "__main__":
    update_progress() 