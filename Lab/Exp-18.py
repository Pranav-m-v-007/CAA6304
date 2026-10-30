import hashlib
import os

# Sample known malware hashes (demonstration values)
malware_database = {
    "5d41402abc4b2a76b9719d911017c592"
}

def calculate_hash(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


filename = input("Enter file path: ")

if not os.path.isfile(filename):
    print("File not found!")

else:
    file_hash = calculate_hash(filename)

    print("SHA-256 Hash:", file_hash)

    if file_hash in malware_database:
        print("Warning: Malware Detected!")

    else:
        print("No Known Malware Found.")
