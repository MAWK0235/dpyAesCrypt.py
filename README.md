# dpyAesCrypt.py
dAescrypt.py is a multithreaded brute-force tool to crack .aes files encrypted using the pyAesCrypt library. It supports password length filtering, progress display with ETA, and optional decryption after cracking.
# Warning
Only use for low length password protected files to brutforce with a wordlist , beacuse higher the password length higher the execution cost and time
# Usage
python3 dpyAesCrypt.py <file> <wordlist>
python3 dpyAesCrypt.py file.aes wordlist.txt
python3 dpyAesCrypt.py <file> <wordlist> -t 50
# Disclaimer
This tool is intended for educational and ethical penetration testing purposes only. Unauthorized access to encrypted data is illegal. Use it only on systems and files you own or have explicit permission to test. The author is not responsible for any misuse or damages.
