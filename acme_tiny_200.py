#!/usr/bin/env python3
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny
import argparse, base64, hashlib, json, logging, os, re, subprocess, sys, textwrap, time  # noqa: E401, I001
from urllib.request import Request, urlopen

DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


def get_crt(account_key, csr, acme_dir, log=LOGGER, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None, check_port=None):
    directory, acct_headers, alg, jwk, nonce = None, None, None, None, None  # global variables

    def _b64_encode_jose(b):
        return base64.urlsafe_b64encode(b).decode("utf8").replace("=", "")

    def _run_external_cmd(cmd_list, cmd_input=None, err_msg="Command Line Error"):
        result = subprocess.run(cmd_list, input=cmd_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise IOError(f"{err_msg}\n{result.stderr.decode('utf8')}")
        return result.stdout

    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data)  # try to parse json results
        except ValueError:
            pass  # ignore json parsing errors
        if depth < 100 and code == 400 and isinstance(resp_data, dict) and resp_data.get("type") == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data)  # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError(f"{err_msg}:\nUrl: {url}\nData: {data}\nResponse Code: {code}\nResponse: {resp_data}")
        return resp_data, code, headers

    def _send_signed_request(url, payload, err_msg, depth=0):
        nonlocal nonce
        if nonce is None:
            nonce = _do_request(directory["newNonce"])[2]["Replay-Nonce"]
        current_nonce, nonce = nonce, None  # consume; will refill from response header
        payload64 = "" if payload is None else _b64_encode_jose(json.dumps(payload).encode("utf8"))
        protected = {"url": url, "alg": alg, "nonce": current_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers["Location"]})
        protected64 = _b64_encode_jose(json.dumps(protected).encode("utf8"))
        protected_input = f"{protected64}.{payload64}".encode("utf8")
        out = _run_external_cmd(["openssl", "dgst", "-sha256", "-sign", account_key], cmd_input=protected_input, err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64_encode_jose(out)})
        try:
            resp_data, code, headers = _do_request(url, data=data.encode("utf8"), err_msg=err_msg, depth=depth)
            nonce = headers.get("Replay-Nonce")  # cache nonce from response for next call
            return resp_data, code, headers
        except IndexError:  # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    def _poll_until_complete(url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result["status"] in pending_statuses:
            assert time.time() - t0 < 3600, "Polling timeout"  # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

    log.info("Parsing account key to get public key.")
    out = _run_external_cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_exp = f"{int(pub_exp):x}"
    pub_exp = f"0{pub_exp}" if len(pub_exp) % 2 else pub_exp
    alg, jwk = (
        "RS256",
        {
            "e": _b64_encode_jose(bytes.fromhex(pub_exp)),
            "kty": "RSA",
            "n": _b64_encode_jose(bytes.fromhex(re.sub(r"(\s|:)", "", pub_hex))),
        },
    )
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    thumbprint = _b64_encode_jose(hashlib.sha256(accountkey_json.encode("utf8")).digest())

    log.info("Parsing CSR to find domains.")
    out = _run_external_cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg=f"Error loading {csr}")
    domains = set()
    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode("utf8"))
    if common_name is not None:
        domains.add(common_name.group(1))
    subject_alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", out.decode("utf8"), re.MULTILINE | re.DOTALL)
    if subject_alt_names is not None:
        for san in subject_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                domains.add(san[4:])
    log.info(f"Found domains: {', '.join(domains)}")

    log.info("Getting ACME directory of urls.")
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found.")

    log.info("Registering account, updating contact details and setting the global key identifier.")
    reg_payload = {"termsOfServiceAgreed": True} if contact is None else {"termsOfServiceAgreed": True, "contact": contact}
    account, code, acct_headers = _send_signed_request(directory["newAccount"], reg_payload, "Error registering")
    log.info(f"{'Registered.' if code == 201 else 'Already registered.'} Account ID: {acct_headers['Location']}")
    if contact is not None:
        if code != 201:
            account, _, _ = _send_signed_request(acct_headers["Location"], {"contact": contact}, "Error updating contact details")
        contact_details = "\n".join(account["contact"])
        log.info(f"Updated contact details:\n{contact_details}")

    log.info("Creating new order.")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory["newOrder"], order_payload, "Error creating new order")
    log.info("Order created.")

    # get the authorizations that need to be completed
    for auth_url in order["authorizations"]:
        authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
        domain = authorization["identifier"]["value"]

        if authorization["status"] == "valid":  # skip if already valid
            log.info(f"Already verified: {domain}, skipping.")
            continue
        log.info(f"Verifying {domain}.")

        # find the http-01 challenge and write the challenge file
        challenge = [c for c in authorization["challenges"] if c["type"] == "http-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
        keyauthorization = f"{token}.{thumbprint}"
        wellknown_path = os.path.join(acme_dir, token)
        with open(wellknown_path, "w") as wellknown_file:
            wellknown_file.write(keyauthorization)

        # check that the file is in place
        wellknown_url = f"http://{domain}{'' if check_port is None else f':{check_port}'}/.well-known/acme-challenge/{token}"
        try:
            assert disable_check or _do_request(wellknown_url)[0] == keyauthorization
        except (AssertionError, ValueError) as e:
            raise ValueError(f"Wrote file to {wellknown_path}, but couldn't download {wellknown_url}: {e}") from e

        # say the challenge is done
        _send_signed_request(challenge["url"], {}, f"Error submitting challenges: {domain}")
        authorization = _poll_until_complete(auth_url, ["pending"], f"Error checking challenge status for {domain}")
        if authorization["status"] != "valid":
            raise ValueError(f"Challenge did not pass for {domain}: {authorization}")
        os.remove(wellknown_path)
        log.info(f"{domain} verified.")

    # finalize the order with the csr
    log.info("Signing certificate.")
    csr_der = _run_external_cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    _send_signed_request(order["finalize"], {"csr": _b64_encode_jose(csr_der)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_complete(order_headers["Location"], ["pending", "processing"], "Error checking order status")
    if order["status"] != "valid":
        raise ValueError(f"Order failed: {order}")

    # download the certificate
    certificate_pem, _, _ = _send_signed_request(order["certificate"], None, "Certificate download failed")
    log.info("Certificate signed.")
    return certificate_pem


def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using the ACME protocol.
            It will need to be run on your server and have access to your private account key, so PLEASE READ THROUGH IT!
            It's only ~200 lines, so it won't take long.

            Example Usage: python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed_chain.crt
            """),
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_true", help="suppress output except for errors")
    parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking if the challenge file is hosted correctly before telling the CA")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt")
    parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")
    parser.add_argument("--check-port", metavar="PORT", default=None, help="what port to use when self-checking the challenge file, default is port 80")
    parser.add_argument("--outfile", metavar="FILE", required=False, default=None, help="write signed cert to this file. default=STDOUT")

    args = parser.parse_args(argv)
    LOGGER.setLevel(logging.ERROR if args.quiet else logging.INFO)
    signed_crt = get_crt(args.account_key, args.csr, args.acme_dir, log=LOGGER, disable_check=args.disable_check, directory_url=args.directory_url, contact=args.contact, check_port=args.check_port)

    if args.outfile:
        LOGGER.info(f"Writing signed certificate to {args.outfile}")
        with open(args.outfile, "w") as fout:
            fout.write(signed_crt)
    else:
        sys.stdout.write(signed_crt)


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
