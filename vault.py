import os
import json
import base64
import uuid
import secrets
import string
from getpass import getpass

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich import print

VAULT_PATH = os.path.expanduser("~/.local_vault.json")

# ------------------ Crypto ------------------

def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )

def encrypt_vault(vault: dict, key: bytes) -> dict:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(vault).encode()
    ciphertext = aes.encrypt(nonce, plaintext, None)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_vault(data: dict, key: bytes) -> dict:
    aes = AESGCM(key)
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)

# ------------------ Vault ------------------

def init_vault():
    if os.path.exists(VAULT_PATH):
        print("[red]Vault already exists[/red]")
        return

    password = getpass("Create master password: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        print("[red]Passwords do not match[/red]")
        return

    salt = os.urandom(16)
    key = derive_key(password, salt)

    vault = {"version": 1, "entries": []}
    encrypted = encrypt_vault(vault, key)

    data = {
        "kdf": {
            "alg": "argon2id",
            "salt": base64.b64encode(salt).decode(),
            "mem": 65536,
            "iters": 3
        },
        **encrypted
    }

    with open(VAULT_PATH, "w") as f:
        json.dump(data, f)

    print("[green]Vault initialized[/green]")

def unlock_vault():
    if not os.path.exists(VAULT_PATH):
        print("[red]Vault not found[/red]")
        return None, None

    password = getpass("Master password: ")

    with open(VAULT_PATH, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["kdf"]["salt"])
    key = derive_key(password, salt)

    try:
        vault = decrypt_vault(data, key)
        return vault, key
    except Exception:
        print("[red]Invalid password or corrupted vault[/red]")
        return None, None

def save_vault(vault: dict, key: bytes):
    with open(VAULT_PATH, "r") as f:
        data = json.load(f)

    encrypted = encrypt_vault(vault, key)
    data.update(encrypted)

    tmp = VAULT_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp, VAULT_PATH)

# ------------------ Commands ------------------

def list_entries(vault):
    for e in vault["entries"]:
        print(f"{e['id']} | {e['site']} | {e['username']}")

def add_entry(vault):
    site = input("Site: ")
    username = input("Username: ")

    choice = input("Generate password? (y/n): ").lower()
    if choice == "y":
        password = generate_password()
        print(f"[green]Generated password:[/green] {password}")
    else:
        password = getpass("Password: ")

    # New:
    if vault["entries"]:
        new_id = max(e["id"] for e in vault["entries"]) + 1
    else:
        new_id = 1

    entry = {
        "id": new_id,
        "site": site,
        "username": username,
        "password": password
    }

    vault["entries"].append(entry)
    print("[green]Entry added[/green]")

def get_entry(vault, entry_id):
    try:
        entry_id = int(entry_id)
    except ValueError:
        print("[red]Invalid ID[/red]")
        return

    for e in vault["entries"]:
        if e["id"] == entry_id:
            print(e)
            return
    print("[red]Entry not found[/red]")

def delete_entry(vault, entry_id):
    before = len(vault["entries"])
    vault["entries"] = [e for e in vault["entries"] if e["id"] != entry_id]
    if len(vault["entries"]) < before:
        print("[green]Entry deleted[/green]")
    else:
        print("[red]Entry not found[/red]")

def generate_password(length=24):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

# ------------------ CLI ------------------

def main():
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "init":
        init_vault()
        return

    if not os.path.exists(VAULT_PATH):
        print("[red]Vault not found, run 'vault.py init' first[/red]")
        return

    vault, key = unlock_vault()
    if not vault:
        return

    print("[green]Vault unlocked![/green] Type 'help' for commands.")

    while True:
        cmd = input("vault> ").strip().lower()
        if cmd in ["exit", "quit"]:
            print("[green]Goodbye![/green]")
            break
        elif cmd == "help":
            print("Commands: list, add, get <id>, delete <id>, genpass, exit")
        elif cmd == "list":
            list_entries(vault)
        elif cmd == "add":
            add_entry(vault)
            save_vault(vault, key)
        elif cmd.startswith("get "):
            _, eid = cmd.split(maxsplit=1)
            get_entry(vault, eid)
        elif cmd.startswith("delete "):
            _, eid = cmd.split(maxsplit=1)
            delete_entry(vault, eid)
            save_vault(vault, key)
        elif cmd == "genpass":
            print(generate_password())
        else:
            print("[red]Unknown command[/red]")

if __name__ == "__main__":
    main()
