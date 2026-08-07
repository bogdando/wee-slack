#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
from configparser import ConfigParser
from contextlib import contextmanager
from pathlib import Path
from sqlite3 import OperationalError
from typing import TYPE_CHECKING, Literal
from urllib.parse import unquote as uq

if TYPE_CHECKING:
    from typing import assert_never

    from _typeshed import StrPath


class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, text):
        cipher = AES.new(self.key, AES.MODE_CBC, IV=(b" " * 16))
        decrypted = cipher.decrypt(text)
        padding_len = decrypted[-1]
        if (
            0 < padding_len <= 16
            and decrypted.endswith(bytes([padding_len]) * padding_len)
        ):
            decrypted = decrypted[:-padding_len]
        return decrypted


@contextmanager
def sqlite3_connect(path: StrPath):
    con = sqlite3.connect(f"file:{path}?immutable=1", uri=True)
    try:
        yield con
    finally:
        con.close()


def strip_chrome_cookie_prefix(
    decrypted: bytes, expected_markers: tuple[bytes, ...]
) -> bytes:
    for marker in expected_markers:
        pos = decrypted.find(marker)
        if pos >= 0:
            return decrypted[pos:]

    return decrypted


def decode_chrome_cookie(
    decrypted: bytes,
    expected_markers: tuple[bytes, ...],
    expected_prefix: str | None = None,
) -> str:
    value = uq(strip_chrome_cookie_prefix(decrypted, expected_markers).decode("utf-8"))
    if (
        (expected_prefix is not None and not value.startswith(expected_prefix))
        or not value.isascii()
        or not value.isprintable()
    ):
        raise ValueError("Decrypted Chrome cookie did not look valid")

    return value


def get_chrome_passwords() -> list[str | bytes]:
    passwords: list[str | bytes] = []

    def add_password(password: str | bytes | None):
        if password is not None and password not in passwords:
            passwords.append(password)

    try:
        import secretstorage
        from secretstorage.exceptions import SecretStorageException

        bus = secretstorage.dbus_init()

        for application in ("chrome", "Chrome", "chromium", "Chromium"):
            try:
                for item in secretstorage.search_items(
                    bus,
                    {
                        "xdg:schema": "chrome_libsecret_os_crypt_password_v2",
                        "application": application,
                    },
                ):
                    add_password(item.get_secret())
            except SecretStorageException:
                continue

        seen_collections: set[str] = set()
        collection_getters = (
            secretstorage.get_default_collection,
            secretstorage.get_any_collection,
        )
        for getter in collection_getters:
            try:
                collection = getter(bus)
            except SecretStorageException:
                continue

            collection_path = str(getattr(collection, "collection_path", id(collection)))
            if collection_path in seen_collections:
                continue
            seen_collections.add(collection_path)

            try:
                for item in collection.get_all_items():
                    if item.get_label() in (
                        "Chrome Safe Storage",
                        "Chromium Safe Storage",
                    ):
                        add_password(item.get_secret())
            except SecretStorageException:
                continue
    except Exception:
        pass

    add_password("peanuts")
    return passwords


def get_cookies(
    cookies_path: StrPath, cookie_query: str, params: tuple
) -> tuple[str, str | None]:
    with sqlite3_connect(cookies_path) as con:
        cookie_d_value = con.execute(cookie_query.format("d"), params).fetchone()
        cookie_ds_value = con.execute(cookie_query.format("ds"), params).fetchone()
        if cookie_d_value and cookie_ds_value:
            return cookie_d_value[0], cookie_ds_value[0]
        elif cookie_d_value:
            return cookie_d_value[0], None
        else:
            print(
                f"Couldn't find the 'd' cookie value in {cookies_path}", file=sys.stderr
            )
            sys.exit(1)


parser = argparse.ArgumentParser(
    description="Extract Slack tokens from the browser files"
)
parser.add_argument(
    "browser",
    help="Which browser to extract from",
    metavar="<browser>",
    choices=["firefox", "firefox-snap", "chromium", "chrome", "chrome-beta"],
)
parser.add_argument(
    "--profile", help="Profile to look up cookies for", metavar="<profile>", nargs="?"
)
parser.add_argument(
    "--container",
    help="Firefox container to look up cookies for",
    metavar="<id or name>",
    nargs="?",
)
parser.add_argument(
    "--no-secretstorage",
    help=(
        "Disable accessing freedesktop Secret D-Bus service, "
        "use the default password to decrypt Chrome cookies instead"
    ),
    action="store_true",
)
args = parser.parse_args()

browser: Literal["firefox", "chrome"]

if sys.platform.startswith("linux"):
    chrome_key_iterations = 1
    if args.browser == "firefox-snap":
        browser = "firefox"
        browser_data = Path.home().joinpath("snap/firefox/common/.mozilla/firefox")
    elif args.browser == "firefox":
        browser = "firefox"
        browser_data = Path.home().joinpath(".mozilla/firefox")
    elif args.browser == "chromium":
        browser = "chrome"
        browser_data = Path.home().joinpath(".config/chromium")
    elif args.browser in ["chrome", "chrome-beta"]:
        browser = "chrome"
        browser_data = Path.home().joinpath(".config/google-%s" % args.browser)
    else:
        print(
            f'Unsupported browser "{args.browser}" on platform Linux.', file=sys.stderr
        )
        sys.exit(1)
elif sys.platform.startswith("darwin"):
    chrome_key_iterations = 1003
    if args.browser in ["firefox", "firefox-snap"]:
        browser = "firefox"
        browser_data = Path.home().joinpath(
            "Library/Application Support/Firefox/Profiles"
        )
    elif args.browser == "chromium":
        browser = "chrome"
        browser_data = Path.home().joinpath("Library/Application Support/Chromium")
    elif args.browser in ["chrome", "chrome-beta"]:
        browser = "chrome"
        browser_data = Path.home().joinpath("Library/Application Support/Google/Chrome")
    else:
        print(
            f'Unsupported browser "{args.browser}" on platform macOS.', file=sys.stderr
        )
        sys.exit(1)
else:
    print("Currently only Linux and macOS is supported by this script", file=sys.stderr)
    sys.exit(1)

profile = args.profile

if browser == "firefox":
    default_profile_path = None
    if profile is not None:
        rel = browser_data.joinpath(profile)
        for p in [Path(profile), rel]:
            if p.exists():
                default_profile_path = p
                break

        if default_profile_path is None:
            print(f"Path {profile} doesn't exist", file=sys.stderr)
            sys.exit(1)
    else:
        profile_path = browser_data.joinpath("profiles.ini")
        profile_data = ConfigParser()
        profile_data.read(profile_path)

        for key in profile_data.sections():
            if not key.startswith("Install"):
                continue

            value = profile_data[key]
            if "Default" in value:
                default_profile_path = browser_data.joinpath(value["Default"])
                break

        if default_profile_path is None or not default_profile_path.exists():
            print(
                "Default profile detection failed; try specifying --profile",
                file=sys.stderr,
            )
            sys.exit(1)

    cookies_path = default_profile_path.joinpath("cookies.sqlite")

    if args.container:
        try:
            ctx_id = int(args.container)
        except ValueError:
            # non-numeric container ID, try to find by name
            ctx_id = None
            with open(default_profile_path.joinpath("containers.json"), "rb") as fp:
                containers = json.load(fp)
                for i in containers["identities"]:
                    if "name" in i and i["name"] == args.container:
                        ctx_id = i["userContextId"]
                        break
            if ctx_id is None:
                print(
                    f"Couldn't find Firefox container '{args.container}'",
                    file=sys.stderr,
                )
                sys.exit(1)

        userctx = f"^userContextId={ctx_id}"
    else:
        userctx = ""

    cookie_query = (
        "SELECT value FROM moz_cookies WHERE originAttributes = ? "
        "AND host = '.slack.com' AND name = '{}'"
    )
    cookie_d_value, cookie_ds_value = get_cookies(
        cookies_path, cookie_query, (userctx,)
    )

    storage_path = default_profile_path.joinpath(
        f"storage/default/https+++app.slack.com{userctx}/ls/data.sqlite"
    )
    storage_query = "SELECT compression_type, conversion_type, value FROM data WHERE key = 'localConfig_v2'"
    local_config = None

    try:
        with sqlite3_connect(storage_path) as con:
            is_compressed, conversion, payload = con.execute(storage_query).fetchone()

        if is_compressed:
            from snappy import snappy

            payload = snappy.decompress(payload)

        if conversion == 1:
            local_config_str = payload.decode("utf-8")
        else:
            # untested; possibly Windows-only?
            local_config_str = payload.decode("utf-16")

        local_config = json.loads(local_config_str)
    except (OperationalError, TypeError):
        pass

elif browser == "chrome":
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Protocol.KDF import PBKDF2
    except ImportError:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
    from plyvel import DB
    from plyvel._plyvel import IOError as pIOErr

    if not profile:
        profile = "Default"

    default_profile_path = browser_data.joinpath(profile)

    cookies_path = default_profile_path.joinpath("Cookies")
    cookie_query = (
        "SELECT encrypted_value FROM cookies WHERE "
        "host_key = '.slack.com' AND name = '{}'"
    )
    cookie_d_value, cookie_ds_value = get_cookies(cookies_path, cookie_query, ())

    if args.no_secretstorage:
        passwords = ["peanuts"]
    else:
        passwords = get_chrome_passwords()

    salt = b"saltysalt"
    last_error: Exception | None = None
    for passwd in passwords:
        key = PBKDF2(passwd, salt, 16, chrome_key_iterations)
        cipher = AESCipher(key)

        try:
            decrypted_d = cipher.decrypt(cookie_d_value[3:])
            decoded_d = decode_chrome_cookie(
                decrypted_d, (b"xoxd-", b"d="), expected_prefix="xoxd-"
            )
            decoded_ds = None
            if cookie_ds_value:
                decrypted_ds = cipher.decrypt(cookie_ds_value[3:])
                decoded_ds = decode_chrome_cookie(decrypted_ds, (b"d-s=",))
                if decoded_ds.startswith("d-s="):
                    decoded_ds = decoded_ds[4:]
        except (UnicodeDecodeError, ValueError) as error:
            last_error = error
            continue

        cookie_d_value = decoded_d
        cookie_ds_value = decoded_ds
        break
    else:
        if args.no_secretstorage:
            print(
                "Unable to decrypt Chrome cookies with the legacy 'peanuts' "
                "password.",
                file=sys.stderr,
            )
        else:
            print(
                "Unable to decrypt Chrome cookies with any available keyring "
                "password. This can happen after migrating between Linux "
                "desktops or distros; re-unlock or re-save the Chrome Safe "
                "Storage secret and try again.",
                file=sys.stderr,
            )
        if last_error is not None:
            print(last_error, file=sys.stderr)
        sys.exit(1)

    local_storage_path = default_profile_path.joinpath("Local Storage")
    leveldb_path = local_storage_path.joinpath("leveldb")
    leveldb_key = b"_https://app.slack.com\x00\x01localConfig_v2"
    try:
        db = DB(str(leveldb_path))
        local_storage_value = db.get(leveldb_key)
        db.close()
    except pIOErr:
        try:
            with tempfile.TemporaryDirectory(
                dir=local_storage_path, prefix="leveldb-", suffix=".tmp"
            ) as tmp_dir:
                shutil.copytree(leveldb_path, tmp_dir, dirs_exist_ok=True)
                db = DB(tmp_dir)
                local_storage_value = db.get(leveldb_key)
                db.close()
        except OSError:
            pass

    local_config = json.loads(local_storage_value[1:]) if local_storage_value else None

else:
    assert_never(browser)

if cookie_ds_value:
    cookie_value = f"d={cookie_d_value};d-s={cookie_ds_value}"
else:
    cookie_value = cookie_d_value

if local_config:
    teams = [
        team
        for team in local_config["teams"].values()
        if not team["id"].startswith("E")
    ]
else:
    teams = [
        {
            "token": "<token>",
            "name": (
                "Couldn't find any tokens automatically, but you can try to extract "
                "it manually as described in the readme and register the team like this"
            ),
        }
    ]

register_commands = [
    f"{team['name']}:\n/slack register {team['token']}:{cookie_value}" for team in teams
]
print("\n\n".join(register_commands))
