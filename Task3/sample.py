import os
import subprocess
import sys
import ast

def secure_eval(user_input):
    try:
        return ast.literal_eval(user_input)
    except Exception:
        return "Invalid input"

def get_password():
    return os.environ.get("APP_PASSWORD")

def secure_file_access(filename, base_dir="safe_dir"):
    safe_path = os.path.abspath(os.path.join(base_dir, filename))
    if not safe_path.startswith(os.path.abspath(base_dir)):
        return "Invalid filename"
    try:
        with open(safe_path, 'r') as f:
            return f.read()
    except Exception:
        return "File not found or inaccessible"

def command_injection(user_input):
    # Vulnerable: unsanitized input in shell command
    subprocess.call(f"echo {user_input}", shell=True)

def main():
    user_input = input("Enter something to eval: ")
    print(secure_eval(user_input))
    print(get_password())
    filename = input("Enter filename to read: ")
    print(secure_file_access(filename))
    cmd_input = input("Enter something to echo: ")
    command_injection(cmd_input)

if __name__ == "__main__":
    main()
