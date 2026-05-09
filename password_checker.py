# Import the regular expression module.
# We use this to search for patterns inside passwords,
# such as uppercase letters, numbers, and special characters.
import re

# Import the CSV module.
# We use this to create a CSV report when checking multiple passwords.
import csv

# Import getpass.
# We use this so the password is hidden when the user types it.
import getpass

# Import Path from pathlib.
# We use this to check whether a file exists.
from pathlib import Path


# These are constant variables.
# They store the names of the files used by the program.
COMMON_PASSWORDS_FILE = "common_passwords.txt"
TEST_PASSWORDS_FILE = "test_passwords.txt"
CSV_REPORT_FILE = "password_report.csv"


def load_common_passwords(file_path):
    """
    This function opens the common_passwords.txt file,
    reads every password inside it,
    converts each password to lowercase,
    and stores them in a set.

    A set is used because it is fast for checking whether
    a password exists in the common password list.
    """

    try:
        # Open the file in read mode.
        # "r" means read.
        # encoding="utf-8" helps Python read text correctly.
        with open(file_path, "r", encoding="utf-8") as file:

            # Read the file line by line.
            # line.strip() removes spaces and new lines.
            # line.lower() converts the password to lowercase.
            # if line.strip() ignores empty lines.
            return set(line.strip().lower() for line in file if line.strip())

    except FileNotFoundError:
        # If the file does not exist, show a warning.
        # The program will continue, but common password checking will be skipped.
        print(f"[!] {file_path} not found. Continuing without common password check.")

        # Return an empty set so the program does not crash.
        return set()


def check_password_strength(password, common_passwords):
    """
    This is the main password checking function.

    It checks the password for:
    - length
    - uppercase letters
    - lowercase letters
    - numbers
    - special characters
    - common passwords
    - repeated characters
    - predictable patterns

    It returns:
    - strength label
    - score
    - list of issues found
    """

    # Start the password score at 0.
    score = 0

    # This list stores problems found in the password.
    issues = []

    # -------------------------
    # 1. Check password length
    # -------------------------

    if len(password) >= 12:
        # Passwords with 12 or more characters get 2 points.
        score += 2

    elif len(password) >= 8:
        # Passwords between 8 and 11 characters get 1 point.
        score += 1

        # This is not a serious issue, but 12+ characters is better.
        issues.append("Password is acceptable length, but 12+ characters is recommended.")

    else:
        # Passwords shorter than 8 characters get no points.
        issues.append("Password is too short. Use at least 12 characters.")

    # -------------------------
    # 2. Check uppercase letters
    # -------------------------

    # This searches for at least one uppercase letter from A to Z.
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        issues.append("Missing uppercase letter.")

    # -------------------------
    # 3. Check lowercase letters
    # -------------------------

    # This searches for at least one lowercase letter from a to z.
    if re.search(r"[a-z]", password):
        score += 1
    else:
        issues.append("Missing lowercase letter.")

    # -------------------------
    # 4. Check numbers
    # -------------------------

    # This searches for at least one number from 0 to 9.
    if re.search(r"[0-9]", password):
        score += 1
    else:
        issues.append("Missing number.")

    # -------------------------
    # 5. Check special characters
    # -------------------------

    # This searches for any character that is NOT a letter or number.
    # Examples: ! @ # $ % & *
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        issues.append("Missing special character.")

    # -------------------------
    # 6. Check common passwords
    # -------------------------

    # Convert the password to lowercase and check if it exists
    # in the common password list.
    if password.lower() in common_passwords:
        # If the password is common, subtract 2 points.
        score -= 2
        issues.append("Password is found in the common password list.")

    # -------------------------
    # 7. Check repeated characters
    # -------------------------

    # This regex checks for the same character repeated 3 or more times.
    # Examples: aaa, 111, $$$
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        issues.append("Password contains repeated characters.")

    # -------------------------
    # 8. Check predictable patterns
    # -------------------------

    # These are simple patterns attackers may guess easily.
    simple_patterns = [
        "123",
        "1234",
        "12345",
        "abc",
        "qwerty",
        "password",
        "admin",
        "letmein",
        "welcome",
        "iloveyou",
        "2024",
        "2025",
        "2026"
    ]

    # This set stores patterns found in the password.
    # A set avoids duplicate entries.
    found_patterns = set()

    # Check each pattern inside the password.
    for pattern in simple_patterns:
        if pattern in password.lower():
            found_patterns.add(pattern)

    # Subtract points for predictable patterns.
    for pattern in sorted(found_patterns):
        score -= 1
        issues.append(f"Password contains a predictable pattern: {pattern}")

    # -------------------------
    # 9. Keep score in safe range
    # -------------------------

    # The score should not be below 0 or above 8.
    score = max(0, min(score, 8))

    # -------------------------
    # 10. Decide strength label
    # -------------------------

    if score <= 2:
        strength = "Very Weak"

    elif score <= 4:
        strength = "Weak"

    elif score <= 6:
        strength = "Medium"

    else:
        strength = "Strong"

    # Return the final result to the part of the program that called this function.
    return strength, score, issues


def print_recommendations():
    """
    This function prints advice for creating better passwords.
    """

    print("\nRecommendations:")
    print("- Use at least 12 characters.")
    print("- Use uppercase and lowercase letters.")
    print("- Include numbers and special characters.")
    print("- Avoid names, birthdays, and common words.")
    print("- Avoid patterns like 123, abc, qwerty, password, or admin.")
    print("- Use a password manager to generate and store strong passwords.")


def mask_password(password):
    """
    This function hides the password when displaying results.

    Example:
    CyberSecurity2026!

    becomes:

    ******************
    """

    # If the password is empty, show a message instead of stars.
    if len(password) == 0:
        return "[empty password]"

    # Return stars with the same length as the password.
    return "*" * len(password)


def display_result(password, strength, score, issues):
    """
    This function prints the final result in a clean format.
    """

    print("\nResult")
    print("------")

    # Print the masked password, not the real password.
    print(f"Password: {mask_password(password)}")

    # Print the strength label.
    print(f"Strength: {strength}")

    # Print the score.
    print(f"Score: {score}/8")

    # If the issues list is not empty, print each issue.
    if issues:
        print("\nIssues found:")
        for issue in issues:
            print(f"- {issue}")

    # If there are no issues, print this message.
    else:
        print("\nNo major issues found.")

    # Print password improvement advice.
    print_recommendations()


def check_single_password(common_passwords):
    """
    This function handles menu option 1.

    It asks the user to enter one password,
    checks the password,
    and displays the result.
    """

    # Ask the user to enter a password.
    # getpass hides the password while typing.
    password = getpass.getpass("Enter password to check: ")

    # If the user enters nothing, show an error.
    if not password:
        print("[!] Password cannot be empty.")
        return

    # Check the password strength.
    strength, score, issues = check_password_strength(password, common_passwords)

    # Display the result.
    display_result(password, strength, score, issues)


def check_passwords_from_file(common_passwords):
    """
    This function handles menu option 2.

    It opens test_passwords.txt,
    checks every password inside the file,
    displays the results,
    and saves a CSV report.
    """

    # Check whether test_passwords.txt exists.
    if not Path(TEST_PASSWORDS_FILE).exists():
        print(f"[!] {TEST_PASSWORDS_FILE} not found.")
        return

    # Open test_passwords.txt in read mode.
    with open(TEST_PASSWORDS_FILE, "r", encoding="utf-8") as file:

        # Read every non-empty line as a password.
        passwords = [line.strip() for line in file if line.strip()]

    # If the file exists but has no passwords, show an error.
    if not passwords:
        print(f"[!] {TEST_PASSWORDS_FILE} is empty.")
        return

    # Open or create the CSV report file.
    # "w" means write mode.
    # newline="" prevents extra blank lines in the CSV.
    with open(CSV_REPORT_FILE, "w", newline="", encoding="utf-8") as csvfile:

        # Create a CSV writer.
        writer = csv.writer(csvfile)

        # Write the header row.
        # We do not store the actual password for security reasons.
        writer.writerow(["Password_Length", "Strength", "Score", "Issues"])

        # Check each password from test_passwords.txt.
        for password in passwords:

            # Check the password strength.
            strength, score, issues = check_password_strength(password, common_passwords)

            # Display result in the terminal.
            display_result(password, strength, score, issues)

            # Convert the issues list into one text string.
            if issues:
                issues_text = "; ".join(issues)
            else:
                issues_text = "No major issues found"

            # Write result to the CSV file.
            # Only password length is saved, not the real password.
            writer.writerow([len(password), strength, score, issues_text])

    # Tell the user that the report was created.
    print(f"\n[+] Report saved as {CSV_REPORT_FILE}")


def main():
    """
    This is the main function.

    It loads the common password list,
    shows the menu,
    and calls the correct function based on the user's choice.
    """

    # Load the common passwords from common_passwords.txt.
    common_passwords = load_common_passwords(COMMON_PASSWORDS_FILE)

    # Keep showing the menu until the user chooses Exit.
    while True:
        print("\nPassword Strength Checker")
        print("=========================")
        print("1. Check one password")
        print("2. Check passwords from test_passwords.txt and export CSV report")
        print("3. Exit")

        # Ask the user to choose an option.
        # strip() removes extra spaces.
        choice = input("Choose an option: ").strip()

        # Option 1: Check one password.
        if choice == "1":
            check_single_password(common_passwords)

        # Option 2: Check passwords from test_passwords.txt.
        elif choice == "2":
            check_passwords_from_file(common_passwords)

        # Option 3: Exit the program.
        elif choice == "3":
            print("Goodbye.")
            break

        # If the user enters anything else, show an error.
        else:
            print("[!] Invalid option selected. Please choose 1, 2, or 3.")


# This line starts the program.
# It means: only run main() if this file is executed directly.
if __name__ == "__main__":
    main()