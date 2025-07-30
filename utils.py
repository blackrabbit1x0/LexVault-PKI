import os
import platform

VAULT_LOCK_FILE = "vault.lock"

def get_usb_path():
    system = platform.system()

    # Windows: detect removable drives using pywin32
    if system == "Windows":
        try:
            import win32file
            drive_bits = win32file.GetLogicalDrives()
            for i in range(26):
                mask = 1 << i
                if drive_bits & mask:
                    drive_letter = f"{chr(65 + i)}:/"
                    drive_type = win32file.GetDriveType(drive_letter)
                    if drive_type == win32file.DRIVE_REMOVABLE:
                        return drive_letter
        except ImportError:
            print("pywin32 is not installed. Run: pip install pywin32")

    # Linux: scan /media/[user]/ for any mounted folder
    elif system == "Linux":
        media_path = f"/media/{os.getlogin()}"
        if os.path.exists(media_path):
            for item in os.listdir(media_path):
                full_path = os.path.join(media_path, item)
                if os.path.ismount(full_path):
                    return full_path

    return None

def save_hidden_file(path, content):
    with open(path, "wb") as f:
        f.write(content)
    if platform.system() == "Windows":
        os.system(f'attrib +h "{path}"')  # Make it hidden

def set_readonly(path):
    os.chmod(path, 0o444)  # Read-only on Unix/Windows
