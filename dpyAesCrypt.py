import argparse
import threading
import pyAesCrypt
import os
import queue
import sys
import time
import zipfile
from termcolor import cprint, colored

# Globals
stop_flag = threading.Event()
lock = threading.Lock()
q = queue.Queue()
result = []
progress = {'checked': 0}
start_time = time.time()
total_passwords = 0


def is_valid_pyaescrypt(file_path):
    try:
        with open(file_path, "rb") as f:
            magic = f.read(8)
            return b"AES" in magic or b"pyAesCrypt" in magic
    except Exception:
        return False


def parse_range(range_str):
    if not range_str:
        return (0, float('inf'))
    parts = range_str.split(":")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise argparse.ArgumentTypeError("Invalid format for -l. Use start:end like 1:6")
    return int(parts[0]), int(parts[1])


def attempt_decrypt(password, encrypted_file, buffer_size):
    try:
        with open(encrypted_file, "rb") as fIn:
            # We write to a temporary file (decrypted output) to test if password works.
            # Using os.devnull used earlier was fine for correctness detection, but if you
            # plan to keep the decrypted file we will re-decrypt later to the real output file.
            with open(os.devnull, "wb") as fOut:
                pyAesCrypt.decryptStream(fIn, fOut, password.strip(), buffer_size, os.path.getsize(encrypted_file))
        return True
    except Exception:
        return False


def worker(args):
    while not stop_flag.is_set():
        try:
            password = q.get_nowait()
        except queue.Empty:
            break

        if args.verbose:
            print(f"[離] Trying: {password.strip()}")
        if args.length[0] <= len(password.strip()) <= args.length[1]:
            if attempt_decrypt(password, args.file, args.buffer):
                with lock:
                    result.append(password.strip())
                stop_flag.set()
                break
        with lock:
            progress['checked'] += 1
        q.task_done()


def show_progress():
    bar_length = 30
    while not stop_flag.is_set():
        tried = progress['checked']
        total = total_passwords
        percent = tried / total if total > 0 else 0
        filled_len = int(bar_length * percent)
        bar = '█' * filled_len + '░' * (bar_length - filled_len)
        eta_seconds = int((time.time() - start_time) / (tried + 1) * (total - tried)) if tried else 0
        eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))
        sys.stdout.write(f"\r[] Progress: {bar} {percent*100:.2f}% | ETA: {eta_str} | Tried {tried}/{total}")
        sys.stdout.flush()
        time.sleep(1)
    print()


def unzip_file(zip_path, password=None, extract_to=None):
    """
    Attempts to unzip `zip_path` to `extract_to` directory (default: basename without .zip).
    If `password` is provided, it will be used (encoded as utf-8) — note: Python's zipfile only
    supports legacy ZipCrypto passworded archives, not AES-encrypted zip files.
    Returns True on success, False otherwise.
    """
    try:
        if not zipfile.is_zipfile(zip_path):
            cprint(f"[❗] {zip_path} is not a valid ZIP file.", "yellow")
            return False

        if extract_to is None:
            extract_to = os.path.splitext(zip_path)[0]

        os.makedirs(extract_to, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            pwd_bytes = password.encode('utf-8') if password else None
            try:
                if pwd_bytes:
                    zf.extractall(path=extract_to, pwd=pwd_bytes)
                else:
                    zf.extractall(path=extract_to)
            except RuntimeError as e:
                # Bad password or unsupported encryption for zipfile module
                cprint(f"[❌] Failed to extract ZIP (bad password or unsupported encryption): {e}", "red")
                return False
            except zipfile.BadZipFile as e:
                cprint(f"[❌] Bad ZIP file: {e}", "red")
                return False

        cprint(f"[] ZIP extracted to: {extract_to}", "green")
        return True

    except Exception as e:
        cprint(f"[❌] Error while unzipping: {e}", "red")
        return False


def main():
    parser = argparse.ArgumentParser(description="pyAesCrypt Brute-force Tool")
    parser.add_argument("file", help="Encrypted .aes file")
    parser.add_argument("wordlist", help="Path to wordlist")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-b", "--buffer", type=int, default=64 * 1024, help="Buffer size in bytes (default: 65536)")
    parser.add_argument("-l", "--length", type=parse_range, default=(0, float('inf')), help="Password length range (e.g., 1:6)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if not args.file or not args.wordlist:
        print("❗ File and wordlist are required. Use -h for help.")
        sys.exit(1)

    if not is_valid_pyaescrypt(args.file):
        cprint("[❌] This file is not a valid pyAesCrypt v2 encrypted file.", "red")
        sys.exit(1)

    global total_passwords
    try:
        with open(args.wordlist, "r", errors="ignore") as f:
            passwords = f.readlines()
        total_passwords = len(passwords)
    except Exception as e:
        cprint(f"[❌] Error loading wordlist: {e}", "red")
        sys.exit(1)

    cprint("\n[] dpyAesCrypt.py – pyAesCrypt Brute Forcer\n", "cyan")
    cprint(f"[] Starting brute-force with {args.threads} threads...", "yellow")

    for pwd in passwords:
        q.put(pwd)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(args,))
        t.start()
        threads.append(t)

    progress_thread = threading.Thread(target=show_progress)
    progress_thread.start()

    for t in threads:
        t.join()

    stop_flag.set()
    progress_thread.join()

    if result:
        cracked_pw = result[0]
        cprint(f"\n[✅] Password found: {colored(cracked_pw, 'green')}", "green")

        # Automatically decrypt the file to a output filename (same name without .aes)
        output_file = os.path.basename(args.file).replace(".aes", "")
        try:
            with open(args.file, "rb") as fIn, open(output_file, "wb") as fOut:
                pyAesCrypt.decryptStream(fIn, fOut, cracked_pw, args.buffer, os.path.getsize(args.file))
            cprint(f"[] File decrypted successfully as: {output_file}", "green")

            # If the decrypted file is a zip, attempt to unzip it using the cracked password
            if zipfile.is_zipfile(output_file):
                cprint("[] Decrypted file is a ZIP. Attempting to extract...", "yellow")
                # Try to unzip using the same password; unzip_file prints status/errors
                unzip_success = unzip_file(output_file, password=cracked_pw)
                if not unzip_success:
                    cprint("[ℹ️] Extraction failed or the zip uses unsupported encryption. "
                           "Consider using pyzipper for AES-encrypted ZIPs.", "yellow")
            else:
                cprint("[ℹ️] Decrypted file is not a ZIP, skipping extraction.", "yellow")

        except Exception as e:
            cprint(f"[❌] Error decrypting: {e}", "red")
    else:
        cprint("\n[❌] Password not found in wordlist.", "red")


if __name__ == "__main__":
    main()
