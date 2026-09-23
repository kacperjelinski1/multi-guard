import sys

def update_iss(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    new_registrations = """    // Rejestracja rozszerzenia Multi-Guard WebShield w przeglądarkach Chrome i Edge i innych
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Google\Chrome\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Google\Chrome\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Google\Chrome\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Google\Chrome\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Edge\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Edge\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\BraveSoftware\Brave-Browser\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Opera Software\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Opera Software\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Opera Software\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Opera Software\Extensions\multiguard_webshield', 'version', '1.2.0');

    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Vivaldi\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Vivaldi\Extensions\multiguard_webshield', 'version', '1.2.0');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Vivaldi\Extensions\multiguard_webshield', 'path', ExpandConstant('{app}\\browser_extension'));
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\WOW6432Node\Vivaldi\Extensions\multiguard_webshield', 'version', '1.2.0');"""

    old_registrations_start = "    // Rejestracja rozszerzenia Multi-Guard WebShield w przeglądarkach Chrome i Edge\n"
    start_idx = content.find(old_registrations_start)
    if start_idx == -1:
        print("Could not find start idx")
        return
        
    end_idx = content.find("    // Wywołanie komend PowerShell", start_idx)
    
    content = content[:start_idx] + new_registrations + "\n\n" + content[end_idx:]

    with open(filepath, 'w') as f:
        f.write(content)

update_iss("installer/Multi-Guard.iss")
