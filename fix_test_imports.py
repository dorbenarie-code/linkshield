import os
import re

TESTS_DIR = "tests"

def fix_imports_in_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    updated_lines = []
    changes_made = False

    for line in lines:
        new_line = re.sub(r"^(from|import)\s+scanner(\.|$)", r"\1 app.scanner\2", line)
        new_line = re.sub(r"^(from|import)\s+services(\.|$)", r"\1 app.services\2", new_line)
        new_line = re.sub(r"^(from|import)\s+utils(\.|$)", r"\1 app.utils\2", new_line)
        new_line = re.sub(r"^(from|import)\s+reports(\.|$)", r"\1 app.reports\2", new_line)
        new_line = re.sub(r"^(from|import)\s+infra(\.|$)", r"\1 app.infra\2", new_line)
        if new_line != line:
            changes_made = True
        updated_lines.append(new_line)

    if changes_made:
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(updated_lines)
        print(f"✅ Fixed imports in: {file_path}")

def walk_and_fix_imports():
    for root, _, files in os.walk(TESTS_DIR):
        for file in files:
            if file.endswith(".py"):
                fix_imports_in_file(os.path.join(root, file))

if __name__ == "__main__":
    walk_and_fix_imports()
