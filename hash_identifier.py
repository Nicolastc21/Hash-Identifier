import sys
import re
import argparse
from typing import List, Dict

def identify_hash(target: str) -> List[Dict[str, str]]:

    target = target.strip()
    candidates = []

    if target.startswith("eyJ"):
        return [{"name": "JWT (not a hash)", "confidence": "High", 
                 "reason": "Leading eyJ is base64 of {\" — JWT structure, not a hash"}]
    
    if re.match(r"^[A-Za-z0-9+/]+={1,2}$", target) and len(target) > 20:
        return [{"name": "Base64 Blob (not a hash)", "confidence": "Medium", 
                 "reason": "Standard Base64 padding (=) detected, likely encoded data"}]

    prefix_signatures = {
        r"^\$2[aby]\$": ("bcrypt", "High", "Prefix $2* — bcrypt PHC string (2b variant is current)"),
        r"^\$argon2(i|d|id)\$": ("Argon2", "High", "Prefix $argon2* — modern PHC string, the current standard"),
        r"^\$apr1\$": ("Apache MD5-crypt", "High", "Prefix $apr1$ — Apache htpasswd MD5 variant (htpasswd -m)"),
        r"^\$1\$": ("MD5-crypt", "High", "Prefix $1$ — Traditional Linux MD5-crypt"),
        r"^\$5\$": ("SHA-256-crypt", "High", "Prefix $5$ — Linux SHA-256 crypt"),
        r"^\$6\$": ("SHA-512-crypt", "High", "Prefix $6$ — Linux SHA-512 crypt"),
        r"^pbkdf2_sha256\$": ("PBKDF2-SHA256", "High", "Prefix pbkdf2_sha256$ — Django framework default"),
        r"^\{SSHA\}": ("SSHA", "High", "Prefix {SSHA} — LDAP Salted SHA-1"),
        r"^\{SHA\}": ("SHA", "High", "Prefix {SHA} — LDAP SHA-1"),
        r"^\{SMD5\}": ("SMD5", "High", "Prefix {SMD5} — LDAP Salted MD5"),
    }

    for pattern, (name, conf, reason) in prefix_signatures.items():
        if re.search(pattern, target, re.IGNORECASE):
            return [{"name": name, "confidence": conf, "reason": reason}]

    if re.match(r"^\*[A-Fa-f0-9]{40}$", target):
        return [{"name": "MySQL5", "confidence": "High", "reason": "Starts with * followed by 40 uppercase hex chars"}]
    
    if re.match(r"^[^:]+::[^:]+:[^:]+:[^:]+$", target):
        return [{"name": "NetNTLMv1/v2", "confidence": "High", "reason": "NetNTLM shape (User::Domain:Challenge:Hash)"}]

    if re.match(r"^[./A-Za-z0-9]{13}$", target):
        candidates.append({"name": "DES crypt", "confidence": "Low", 
                           "reason": "13 chars of base64-like alphabet — traditional Unix crypt format"})

    if re.match(r"^[A-Fa-f0-9]+$", target):
        length = len(target)
        
        if length == 32:
            candidates.extend([
                {"name": "MD5", "confidence": "High", "reason": "32 hex chars — most likely candidate at this length"},
                {"name": "NTLM", "confidence": "Medium", "reason": "32 hex chars — common in Windows environments"},
                {"name": "MD4", "confidence": "Low", "reason": "32 hex chars — older, obsolete Windows hash"}
            ])
        elif length == 40:
            candidates.extend([
                {"name": "SHA-1", "confidence": "High", "reason": "40 hex chars — most likely candidate at this length"},
                {"name": "RIPEMD-160", "confidence": "Low", "reason": "40 hex chars — less common alternative"}
            ])
        elif length == 64:
            candidates.extend([
                {"name": "SHA-256", "confidence": "High", "reason": "64 hex chars — most likely candidate at this length"},
                {"name": "SHA-3-256", "confidence": "Medium", "reason": "64 hex chars — modern alternative"},
                {"name": "BLAKE2s", "confidence": "Low", "reason": "64 hex chars — valid cryptographic candidate"}
            ])
        elif length == 96:
            candidates.append({"name": "SHA-384", "confidence": "High", "reason": "96 hex chars — most likely candidate"})
        elif length == 128:
            candidates.extend([
                {"name": "SHA-512", "confidence": "High", "reason": "128 hex chars — most likely candidate at this length"},
                {"name": "SHA-3-512", "confidence": "Medium", "reason": "128 hex chars — modern alternative"},
                {"name": "BLAKE2b", "confidence": "Low", "reason": "128 hex chars — valid cryptographic candidate"}
            ])
        else:
            candidates.append({"name": "Unknown Hex", "confidence": "Low", 
                               "reason": f"{length} hex chars — unusual length, possibly partial or custom"})
            
    if not candidates:
        candidates.append({"name": "Unknown", "confidence": "Low", "reason": "Does not match any known signatures or shapes"})

    return candidates

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_table(candidates: List[Dict[str, str]], target: str):
    """Renders a formatted ANSI terminal table."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}Target:{Colors.RESET} {target}\n")
    
    col_hash = max(len("Hash Detected"), max(len(c["name"]) for c in candidates)) + 2
    col_conf = 12
    col_why = max(len("Why"), max(len(c["reason"]) for c in candidates)) + 2
    
    separator = f"├{'─' * col_hash}┼{'─' * col_conf}┼{'─' * col_why}┤"
    
    print(f"┌{'─' * col_hash}┬{'─' * col_conf}┬{'─' * col_why}┐")
    print(f"│ {Colors.BOLD}Hash Detected{' ' * (col_hash - 14)}│ {Colors.BOLD}Confidence{' ' * (col_conf - 11)}│ {Colors.BOLD}Why{' ' * (col_why - 4)}│{Colors.RESET}")
    print(separator)
    
    for c in candidates:
        conf_color = Colors.GREEN if c["confidence"] == "High" else \
                     Colors.YELLOW if c["confidence"] == "Medium" else Colors.RED
                     
        name_pad = " " * (col_hash - len(c["name"]) - 1)
        conf_pad = " " * (col_conf - len(c["confidence"]) - 1)
        why_pad = " " * (col_why - len(c["reason"]) - 1)
        
        print(f"│ {Colors.CYAN}{c['name']}{Colors.RESET}{name_pad}│ "
              f"{conf_color}{c['confidence']}{Colors.RESET}{conf_pad}│ "
              f"{c['reason']}{why_pad}│")
              
    print(f"└{'─' * col_hash}┴{'─' * col_conf}┴{'─' * col_why}┘\n")

def main():
    parser = argparse.ArgumentParser(description="Identify a cryptographic hash format.")
    parser.add_argument("hash", nargs="?", default=None, help="The hash string to identify")
    args = parser.parse_args()
    target_hash = args.hash
    if not target_hash:
        try:
            target_hash = input("Enter the hash for analysis: ").strip()
        except KeyboardInterrupt:
            print("\nExit")
            sys.exit(0)
            
    if not target_hash:
        print("Error: No hash was entered.")
        sys.exit(1)

    results = identify_hash(target_hash)
    print_table(results, target_hash)

    if results[0]["name"] == "Unknown":
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()