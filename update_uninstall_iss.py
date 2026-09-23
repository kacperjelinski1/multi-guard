import sys

def update_uninstall_iss(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    target_str = "Remove-Item -Path 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\Extensions\\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue;"
    new_str = target_str + " Remove-Item -Path 'HKLM:\\SOFTWARE\\BraveSoftware\\Brave-Browser\\Extensions\\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\\SOFTWARE\\WOW6432Node\\BraveSoftware\\Brave-Browser\\Extensions\\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\\SOFTWARE\\Opera Software\\Extensions\\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\\SOFTWARE\\WOW6432Node\\Opera Software\\Extensions\\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\\SOFTWARE\\Vivaldi\\Extensions\\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path 'HKLM:\\SOFTWARE\\WOW6432Node\\Vivaldi\\Extensions\\multiguard_webshield' -Recurse -Force -ErrorAction SilentlyContinue;"
    
    content = content.replace(target_str, new_str)

    with open(filepath, 'w') as f:
        f.write(content)

update_uninstall_iss("installer/Multi-Guard.iss")
