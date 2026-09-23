import os
import re

def replace_in_file(filepath, old_str, new_str):
    if not os.path.exists(filepath):
        print(f"Not found: {filepath}")
        return
    with open(filepath, 'r') as f:
        content = f.read()
    new_content = content.replace(old_str, new_str)
    with open(filepath, 'w') as f:
        f.write(new_content)
    print(f"Updated {filepath}")

def replace_regex_in_file(filepath, pattern, repl):
    if not os.path.exists(filepath):
        return
    with open(filepath, 'r') as f:
        content = f.read()
    new_content = re.sub(pattern, repl, content)
    with open(filepath, 'w') as f:
        f.write(new_content)
    print(f"Regex updated {filepath}")

# Direct replacements
files = [
    'CHANGELOG.md',
    'installer/Multi-Guard.iss',
    'src/ui/mainwindow.ui',
    'updates/version.txt',
    '.github/workflows/build-and-release.yml'
]

for f in files:
    replace_in_file(f, '2.0.3.0', '2.0.4.0')

# Version.h replacement
replace_regex_in_file('Version.h', r'#define APP_VERSION_PATCH\s+3', '#define APP_VERSION_PATCH   4')

# Let's also update the changelog in updates/version.txt explicitly
with open('updates/version.txt', 'r') as f:
    vtxt = f.read()

vtxt_new = """2.0.4.0
Url=>https://github.com/kacperjelinski1/multi-guard/releases/latest/download/Multi-Guard-Setup.exe
Changelog=>
Multi-Guard Endpoint Security 2.0.4.0:
- Dodano deinstalator przywracający zmiany (ikona Defender wraca do traya)
- Rozszerzona integracja ochrony WWW o wszystkie przeglądarki Chromium (Brave, Opera, Vivaldi)
- Pełna integracja zapory sieciowej (Firewall) z użyciem Netsh
- Skanowanie systemu w pełni opiera się na module Microsoft Defender z powiadomieniami
- Zaktualizowana wersja 2.0.4.0 w stopce i oknie O programie"""

with open('updates/version.txt', 'w') as f:
    f.write(vtxt_new)

