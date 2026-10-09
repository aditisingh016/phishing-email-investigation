import hashlib
from pathlib import Path


FILE_PATH = Path("sample_data/phishing_email.eml")


def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def main():

    if not FILE_PATH.exists():

        print(f"File not found: {FILE_PATH}")
        return

    file_hash = calculate_sha256(FILE_PATH)

    print("\n" + "=" * 60)
    print("EVIDENCE INTEGRITY CHECK")
    print("=" * 60)

    print(f"\nEvidence file : {FILE_PATH}")
    print(f"SHA-256       : {file_hash}")

    print("\nUse this hash to verify that the evidence file")
    print("has not been modified after acquisition.")

    print("=" * 60)


if __name__ == "__main__":
    main()