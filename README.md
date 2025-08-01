# dpyAesCrypt.py
dAescrypt.py is a multithreaded brute-force tool to crack .aes files encrypted using the pyAesCrypt library. It supports password length filtering, progress display with ETA, and optional decryption after cracking.
# Warning
Only intended for brute-forcing files protected with short passwords using a wordlist. As password length increases, the time and computational cost grow significantly, making this tool less practical for long or complex passwords.
# Usage
- `python3 dpyAesCrypt.py <file> <wordlist>`
- `python3 dpyAesCrypt.py file.aes wordlist.txt`
- `python3 dpyAesCrypt.py <file> <wordlist> -t 50`

# Disclaimer
This tool is intended for educational and ethical penetration testing purposes only. Unauthorized access to encrypted data is illegal. Use it only on systems and files you own or have explicit permission to test. The author is not responsible for any misuse or damages.
