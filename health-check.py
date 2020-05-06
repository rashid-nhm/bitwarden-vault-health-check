#!/usr/bin/env python3

import json
import logging
import hashlib
import argparse
import tempfile
import subprocess
import http.client

logger = logging.getLogger("bw-vault-health-check")
fmt = logging.Formatter("%(message)s")

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(fmt)

logger.setLevel(logging.WARNING)
logger.addHandler(stream_handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A BitWarden vault Health Checker. "
                                                 "Please make sure the vault is unlocked prior to running this check.")
    parser.add_argument("username")
    parser.add_argument("password")

    parser.add_argument("--bitwarden", "-b", help="Path to the bitwarden cli", dest="bitwarden")
    parser.add_argument("--output", "-o", help="File to store all output to")
    parser.add_argument("--server", "-s", help="Point BitWarden-cli at a different instance of BitWarden")
    parser.add_argument("--verbose", "-v", help="Enable verbose output", action="store_true")
    parser.add_argument("--timeout", "-t", help="Max time to wait for requests before raising error", type=int, default=30)

    result = parser.parse_args()

    if result.verbose:
        logger.setLevel(logging.DEBUG)

    if result.output:
        file_h = logging.FileHandler(result.output)
        file_h.setFormatter(fmt)
        logger.addHandler(file_h)

    if not result.bitwarden:
        logger.warning("No path to BitWarden cli specified. Will be using 'bw' assuming it exists in PATH ..")
        exe_path = 'bw'
    else:
        exe_path = result.bitwarden

    if result.server:
        logger.info(f"Setting the BitWarden server config to point to -> {result.server}")
        subprocess.run([exe_path, "config", "server", result.server, "--quiet"])

    logger.info("Attempting to log in ...")
    with subprocess.Popen([exe_path, "login", "--response", result.username, result.password],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        proc.wait(result.timeout)
        s_out = proc.stdout.read().decode("utf-8")
        s_err = proc.stderr.read().decode("utf-8")

        if s_err:
            try:
                err = json.loads(s_err)
                if "already logged in" in err.get("message"):
                    raise RuntimeError("BitWarden cli seems to already be logged in. Please log out and run again ...")
            except json.decoder.JSONDecodeError:
                raise Exception(f"Error: {s_err}")

        response = json.loads(s_out)
    if response["success"] == "false":
        if "already logged in" in response["message"]:
            raise RuntimeError("BitWarden cli seems to already be logged in. Please log out and run again ...")
        else:
            raise Exception(f"Error returned by bw-cli: {response['message']}")

    session_key = response["data"]["raw"]
    logger.info("Successfully logged into BitWarden!")
    
    logger.info("Pulling down latest vault ...")
    subprocess.run([exe_path, "sync", "--session", session_key, "--quiet"])

    logger.info("Fetching folder information ...")
    with tempfile.TemporaryFile() as t:
        with subprocess.Popen([exe_path, "list", "folders", "--session", session_key],
                              stdout=t, stderr=subprocess.PIPE) as proc:
            proc.wait(result.timeout)

            s_err = proc.stderr.read().decode("utf-8")
            if s_err:
                raise Exception(f"Error while trying to get all items: {s_err}")

            t.seek(0)
            s_out = t.read().decode('utf-8')

            response = json.loads(s_out)
    if isinstance(response, dict) and response.get("success") == "false":
        raise Exception(f"bw returned error while trying to list all folders: {response['message']}")

    folders = {}
    for folder in response:
        folders[folder["id"]] = folder["name"]

    logger.info("Fetching all items ...")
    with tempfile.TemporaryFile() as t:
        with subprocess.Popen([exe_path, "list", "items", "--session", session_key],
                              stdout=t, stderr=subprocess.PIPE) as proc:
            proc.wait(result.timeout)

            s_err = proc.stderr.read().decode("utf-8")
            if s_err:
                raise Exception(f"Error while trying to get all items: {s_err}")

            t.seek(0)
            s_out = t.read().decode('utf-8')

            response = json.loads(s_out)
    if isinstance(response, dict) and response.get("success") == "false":
        raise Exception(f"bw returned error while trying to list all items: {response['message']}")

    # SHA256(password) => ["folder/name", "folder2/name2"]
    possible_duplicates = {}
    pwned_passwords = []
    remote_conn = http.client.HTTPSConnection("api.pwnedpasswords.com", timeout=result.timeout)
    for item in response:
        if item["type"] != 1:
            continue
        elif not item["login"]["password"]:
            continue

        sha = hashlib.sha1(item["login"]["password"].encode()).hexdigest()

        item_full_readable_path = f"{folders[item['folderId']]}/{item['name']}"

        if sha not in possible_duplicates:
            possible_duplicates[sha] = []

        possible_duplicates[sha].append(item_full_readable_path)

        head_sha = sha[:5]
        body_sha = sha[5:]

        remote_conn.request("GET", f"/range/{head_sha}")
        response = remote_conn.getresponse()

        ret_shas = ""
        while True:
            chunk = response.read(200)
            if not chunk:
                break
            ret_shas += chunk.decode("utf-8")
        pwned_shas = list(map(lambda x: x.split(":")[0].lower(), ret_shas.split("\n")))

        if body_sha in pwned_shas:
            pwned_passwords.append(item_full_readable_path)
    possible_duplicates = dict(filter(lambda items: len(items[1]) > 1, possible_duplicates.items()))
    logger.info("Generating report ...")
    if possible_duplicates:
        logger.critical("\nThe following password are duplicated: ")
        for sha, names in possible_duplicates.items():
            logger.critical(f"{'*'*5}{sha}{'*'*5}")
            for name in names:
                logger.critical(f' - {name}')
            logger.critical("\n")
    else:
        logger.critical("No duplicate passwords found!")

    if pwned_passwords:
        logger.critical("\nThe following password have been PWNED:")
        for name in pwned_passwords:
            logger.critical(f" - {name}")
    else:
        logger.critical("No leaked password found!")

