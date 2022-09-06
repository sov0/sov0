import copy
import getpass
import json
import os
import sys

import nacl.encoding
import nacl.hash
import nacl.pwhash
import nacl.signing

########################################################################################
# 0. CONSTANTS & HELPERS ###############################################################

# there's a fixed 1 billion units of the asset
ASSET_SUPPLY = 1000000000
# the amount transacted must be a multiple of the 'unit', which will monotonically
#  decrease over time, allowing finer and finer grained transaction units
TRANSACTION_UNIT = 1000
# block producer is removed after so many periods
BLOCK_PRODUCER_MAX_TENURE = 100
# how many periods accounts are frozen for if they submit a transaction that's seemingly
#  valid but has an incorrect state hash
TEMPORARY_FREEZE_PDS = 10
# if we're in pretest, then the state's period field will indicate as much
STATE_PERIOD_FIELD = "SoV0_pretest_period"
# security parameters for address derivation
OPSLIM = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
MEMLIM = nacl.pwhash.argon2id.MEMLIMIT_MODERATE


def _log(mystring, log_file, mode="a"):
    """
    Helper for writing a string to a log file.  If log_file is None, does nothing.
        If log_file is "_console", then just prints it to the console.
    Args:
        mystring: be a regular string to be written
        log_file: the path to the log file, a string
    """
    if log_file == "_console":
        print(mystring)
    elif log_file is not None:
        with open(log_file, mode) as f:
            f.write(mystring + "\n")


def _json_dumps(data_dict):
    """
    A helper function that ensures consistent json.dumps parameters across different
    sections of code that save to JSON.
    """
    return json.dumps(data_dict, ensure_ascii=True, indent=1, allow_nan=False).encode(
        "ascii"
    )


def _json_load(bytestring):
    """
    Interprets an ascii-encoded bytestring as a json
    """
    return json.loads(bytestring.decode(encoding="ascii"))


def _is_64len_hex_string(mystr):
    """
    Helper for checking if something is a valid 64 length hex string.
    Args:
        mystr: a regular string
    """
    return (
        type(mystr) is str
        and len(mystr) == 64
        and all(c in "0123456789abcdef" for c in mystr)
    )


def _default_hash(thing_to_hash):
    """
    The default hash function used throughout: blake2b with a 32-byte digest, other
    parameters default, output as a hex string
    Args:
        thing_to_hash: a bytes object to hash
    Returns:
        the hash of the object, as a 64-length ascii-encoded hex bytestring
    """
    return nacl.hash.blake2b(
        thing_to_hash, digest_size=32, encoder=nacl.encoding.HexEncoder
    )


def _load_and_hash(file):
    """
    Helper that reads a file in binary, hashes it, and returns the binary & hash
    Returns:
        file_raw: the raw binary of the file, a bytestring
        file_hash: the blake2b hash of the raw file as a hexadecimal normal string
    """
    with open(file, "rb") as f:
        file_raw = f.read()
    file_hash = _default_hash(file_raw).decode("ascii")
    return file_raw, file_hash


def is_the_same_string(*args):
    if len(args) < 2:
        print("enter 2 more or strings to check if they're all the same")
    a = args[0]
    for b in args[1:]:
        if not b == a:
            raise ValueError("These strings are different.")
    print("Success! These strings are the same.")


def check_hash(file, expected_hash=None):
    """
    Gets the hash of a file, optionally checks that this hash is what we expect.
    Args:
        file: some file
        expected_hash: A normal string of what the hash of the file should be.  Leave
            argument empty to just print the hash of the file.
    Example command line usage:
        python sov0.py check_hash my_hashed_file.txt \
            45531c70dc95cbcc1146c06ffe9a99d24141d55777e7bdeb9f429d5bc9299902
    """
    file_raw, file_hash = _load_and_hash(file)
    print("HASH OF FILE:", file_hash)
    if expected_hash is not None:
        if not _is_64len_hex_string(expected_hash):
            raise ValueError("Expected hash must be None, or a 64-length hex string")
        if file_hash != expected_hash:
            raise ValueError("Error: hash of file doesn't match input")
        print("SUCCESS: hash of file matches input")


def _sign_bytestring(bytestring_to_sign, private_key):
    """
    Hashes a file and the signs the hash using a private key
    Args:
        bytestring_to_sign: the bytestring we want to sign
        private_key: the private key object, returned by _derive_private_key()
    Returns:
        signed_bytestring: the signed message, a bytestring
    """
    # sign the hash of the file.  the hash is a normal string, need to
    #  encode it as ascii before we can sign it.
    signed_bytestring = private_key.sign(
        bytestring_to_sign, encoder=nacl.encoding.HexEncoder
    )
    return signed_bytestring


def _check_msg_sig(msg, signed_message, address):
    """
    Checks that a signature corresponds to a given hash
    Args:
        msg: a message to sign, ascii-encoded hex bytestring
        signed_message: the signed message, an ascii-encoded hex bytestring, from
            signing the with the private key corresponding to address
        address: signer's address, an ascii-encoded hex bytestring
    Output:
        will throw an error if signature is bad, or doesn't correspond to
        the message
    """
    signer_pubkey = nacl.signing.VerifyKey(address, encoder=nacl.encoding.HexEncoder)
    signed_msg = signer_pubkey.verify(signed_message, encoder=nacl.encoding.HexEncoder)
    if not msg == signed_msg:
        raise ValueError(
            "The message doesn't match the signature.\n"
            "input message :\n {}\n"
            "signature message :\n {}\n".format(
                msg.decode("ascii"), signed_msg.decode("ascii")
            )
        )


########################################################################################
# I. WALLET FUNCTIONS ##################################################################


def _derive_private_key(username_prompt=None, password_prompt=None):
    """
    Helper for getting a private key, will prompt for username & password.
    Args:
        username_prompt, password_prompt: normal strings that will be shown when
            prompting the user for a private key
    Returns:
        the private key, a nacl.signing.SigningKey object.
    """
    if username_prompt is None:
        username_prompt = "Enter the username of your account: "
    if password_prompt is None:
        password_prompt = "Enter the password for your account: "
    username = input(username_prompt).encode("ascii")
    password = getpass.getpass(password_prompt).encode("ascii")
    # username is hashed into a 16-byte seed
    salt = nacl.hash.blake2b(username, digest_size=16, encoder=nacl.encoding.RawEncoder)
    # derive private key directly from the password and salt
    seed = nacl.pwhash.argon2id.kdf(
        size=32, password=password, salt=salt, opslimit=OPSLIM, memlimit=MEMLIM
    )
    private_key = nacl.signing.SigningKey(seed)
    return private_key


def check_account_access(address_file):
    """
    Check that you can access your account: i.e. that your username & password correctly
        reconstruct the address.
    Args:
        address_file: a file holding a 64-len hex string, as created by
            create_account_address()
    Example command line usage:
        python sov0.py check_account_access my_address.txt
    """
    address_derived = _derive_private_key().verify_key.encode(
        encoder=nacl.encoding.HexEncoder
    )
    with open(address_file, "rb") as f:
        address_loaded = f.read()
    if not address_derived == address_loaded:
        print(
            "ERROR: the address in '{}'".format(address_file),
            "is not associated with the input username & password.",
        )
        return False
    print(
        "SUCCESS: the address in '{}'".format(address_file),
        "is associated with the input username & password.",
    )
    return True


def create_account_address(address_file):
    """
    Prompts a user for an account username & password, and uses it to derive an address
        to use for sending & receiving transactions.
    Args:
        address_file: the file to store the address in
    Example command line usage:
        python sov0.py create_account_address my_address.txt
    """
    if os.path.exists(address_file):
        raise FileExistsError("address file already exists.")
    # construct the private key
    username_prompt = (
        "Create a username for your account, something you can easily remember and "
        "not too common.  Something like your email address might be a good choice. "
        "This username is only used by you in accessing your account, and will not be "
        "shared with anyone or uploaded to any server or saved to any file:\n"
    )
    password_prompt = (
        "Create a password for your account, ideally a 20+character randomly generated "
        "one.  Avoid using passwords that you've used before for anything else, as "
        "anyone who knows your username and password will be able to access the "
        "balance in your account.  This password will not be shared with anyone or "
        "uploaded to any server or saved to any file.\n"
    )
    private_key = _derive_private_key(username_prompt, password_prompt)
    address = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    # write the address
    with open(address_file, "wb") as f:
        f.write(address)
    # check that things worked
    print("Now let's check that everything worked.")
    if check_account_access(address_file):
        print(
            "Your address is: {}\nDumped to '{}',".format(
                address.decode(), address_file
            )
        )
        print(
            "\n1. MEMORIZE YOUR PASSWORD AND USERNAME. These aren't stored anywhere in "
            "any server or any file on your computer. If you forget either, there's no "
            "way to recover it and you'll lose access to any funds in your account.\n"
            "2. KEEP YOUR PASSWORD A SECRET! If someone else knows your password & "
            "username, they will have access to all the funds in your account.\n"
            "3. If you lose this address file, you can just recreate it by re-running "
            "this function and inputting the same username & password."
        )
    # if not, delete the key
    else:
        os.remove(address_file)
        print("Account creation failed, please try again.")


def create_sign_transaction(txn_file, sig_file):
    """
    Creates a transaction, will prompt users for all the various inputs.
    Args:
        txn_file: a filepath to dump the resulting transaction to
        sig_file: a filepath to dump the signature to
    Example command line usage:
        python sov0.py create_sign_transaction my_txn.txt my_sig.txt\

    """
    if os.path.exists(txn_file) or os.path.exists(sig_file):
        raise FileExistsError("transaction or signature file already exists")
    prompts = {
        "#SoV0": "Enter a positive integer amount of assets to send:\n  ",
        "from": "Enter your address, a 64-length hexadecimal string:\n  ",
        "to": "Enter the receiver's address, a 64-length hexadecimal string:\n  ",
        "period": "Enter the current SoV0 period, a non-negative integer:\n  ",
        "state": "Enter the SoV0 state hash, a 64-length hexadecimal string:\n  ",
    }
    transformers = {
        "#SoV0": lambda x: int(x),
        "from": lambda x: x,
        "to": lambda x: x,
        "period": lambda x: int(x),
        "state": lambda x: x,
    }
    # create transaction
    txn_dict = {}
    for field in prompts.keys():
        transformer = transformers[field]
        prompt = prompts[field]
        txn_dict[field] = transformer(input(prompt))
    # check it
    _check_txn_format(txn_dict)
    # get it into a 'canonical form' and save it
    txn_canonical_bytes = _json_dumps(txn_dict)
    with open(txn_file, "wb") as f:
        f.write(txn_canonical_bytes)
    # sign the hash of this canonical form
    txn_canonical_hash = _default_hash(txn_canonical_bytes)
    private_key = _derive_private_key()
    signed_hash = _sign_bytestring(txn_canonical_hash, private_key)
    txn_sig_json = {"#SoV0_txn_sig": signed_hash.decode("ascii")}
    with open(sig_file, "wb") as f:
        f.write(_json_dumps(txn_sig_json))
    print(
        "Transaction written to '{}',".format(txn_file),
        "signature written to '{}'.".format(sig_file),
    )
    print(
        "Please check that these are valid by running:\n  "
        "python sov0.py check_transaction {} {}".format(txn_file, sig_file)
    )


def _check_txn_format(txn_dict):
    """
    Check that a transaction is well formatted based on information available in the
        transaction itself.
    Args:
        txn_dict: a dict of a transaction, as output by _json_load applied to the
            transaction file created by create_sign_transaction()
    Returns:
        Nothing if it succeeds, throws an error if not.
    """
    txn_fields = {"#SoV0", "from", "to", "period", "state"}
    if not set(txn_dict.keys()) == txn_fields:
        raise ValueError("transaction fields must be: {}".format(txn_fields))
    if not ((type(txn_dict["#SoV0"]) is int) and txn_dict["#SoV0"] > 0):
        raise ValueError("transaction amount must be a positive integer")
    if not (txn_dict["#SoV0"] % TRANSACTION_UNIT) == 0:
        raise ValueError(
            "transaction amount must be a multiple of {}".format(TRANSACTION_UNIT)
        )
    if not ((type(txn_dict["period"]) is int) and txn_dict["period"] >= 0):
        raise ValueError("current period must be a nonnegative integer")
    if not _is_64len_hex_string(txn_dict["from"]):
        raise ValueError("sender is not a valid 64-length hex string")
    if not _is_64len_hex_string(txn_dict["to"]):
        raise ValueError("receiver is not a valid 64-length hex string")
    if not _is_64len_hex_string(txn_dict["state"]):
        raise ValueError("state hash is not a valid 64-length hex string")


def check_transaction(txn_file, sig_file):
    """
    Checks that a transaction is well formatted and the signature is valid.
    Args:
        txn_file: file with the transaction, produced by create_transaction()
        sig_file: file with the signature, produced by sign_file()
    Returns nothing, throws an error if the transaction doesn't check out
    Example command line usage:
        python sov0.py check_transaction my_txn.txt my_sig.txt
    """
    # check that transaction is good:
    try:
        with open(txn_file, "rb") as f:
            txn = f.read()
        txn_dict = _json_load(txn)
        _check_txn_format(txn_dict)
    except Exception as e:
        print("ERROR: can't parse transaction: {}".format(e))
        raise
    # check that it's properly signed
    with open(sig_file, "rb") as f:
        sig = _json_load(f.read())["#SoV0_txn_sig"].encode("ascii")
    txn_canonical_bytes = _json_dumps(txn_dict)
    txn_canonical_hash = _default_hash(txn_canonical_bytes)
    sender_address = txn_dict["from"]
    _check_msg_sig(txn_canonical_hash, sig, sender_address)
    # if no error then we good
    print(
        "SUCCESS: transaction appears to be well-formatted and signature checks out. "
        "Note: this doesn't check if your account has sufficient balance, or if you've "
        "included the correct period & state hash."
    )


def check_transaction_receiver(txn_file):
    """
    Checks that the recipient of a transaction corresponds to the input username and
        password.  This is useful for checking that the receiver address is actually
        accessible by you.
    Args:
        txn_file: file with the transaction, created by create_transaction()
    Example command line usage:
        python sov0.py check_transaction_receiver my_txn.txt
    """
    # get the transaction's receiver's address
    with open(txn_file, "rb") as f:
        txn = f.read()
    txn_dict = _json_load(txn)
    print(json.dumps(txn_dict, indent=1))
    txn_receiver_address = txn_dict["to"]
    # check that it matches the one derived from a prompted username & password
    username_prompt = "Enter the username for this transaction's receiver: "
    password_prompt = "Enter the password for this transaction's receiver: "
    private_key = _derive_private_key(username_prompt, password_prompt)
    address_hex = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    # compare\
    if not txn_receiver_address == address_hex.decode("ascii"):
        msg = (
            "transaction recipient doesn't match input username & password\n"
            "address of transaction receiver:\n\t{}\n"
            "address corresponding to username and password:\n\t{}".format(
                txn_receiver_address, address_hex.decode("ascii")
            )
        )
        raise ValueError(msg)
    print("SUCCESS: transaction recipient corresponds to the input username & password")


########################################################################################
# II. Functions for state ##############################################################
def _check_state_validity(state_dict):
    """
    Helper for check if a state is properly formatted.
    Args:
        state_dict: a dict representing the state, as loaded by _json_load()
    Returns:
        Nothing if valid, raises an error if invalid
    """
    top_level_fields = {
        STATE_PERIOD_FIELD,
        "prev_state",
        "prev_block",
        "block_producer",
        "block_producer_tenure",
        "accounts",
    }
    if not (
        (type(state_dict) is dict) and (set(state_dict.keys()) == top_level_fields)
    ):
        raise ValueError(
            "state_dict is not a dict with these fields {}".format(top_level_fields)
        )
    # 1. validity checks for the headers
    if (not type(state_dict[STATE_PERIOD_FIELD]) is int) or (
        state_dict[STATE_PERIOD_FIELD] < 0
    ):
        raise ValueError("current period invalid, must be nonnegative integer")
    # prev state should "NONE" IFF it's the zeroth period
    if not (
        (
            _is_64len_hex_string(state_dict["prev_state"])
            and state_dict[STATE_PERIOD_FIELD] > 0
        )
        or (state_dict["prev_state"] == "NONE" and state_dict[STATE_PERIOD_FIELD] == 0)
    ):
        raise ValueError("previous state hash is not valid")
    if not (
        _is_64len_hex_string(state_dict["prev_block"])
        or (state_dict["prev_block"] == "NONE")
    ):
        raise ValueError("previous block hash is not valid")
    if not _is_64len_hex_string(state_dict["block_producer"]):
        raise ValueError("block producer is not valid")
    if not type(state_dict["block_producer_tenure"]) is int:
        raise ValueError("block producer's tenure is not an int")
    if not (0 <= state_dict["block_producer_tenure"] <= state_dict[STATE_PERIOD_FIELD]):
        raise ValueError("block producer's tenure is negative or too big")
    if (state_dict["prev_block"] == "NONE") and state_dict[
        "block_producer_tenure"
    ] != 0:
        raise ValueError("previous block is NONE, yet block producer tenure > 0")
    # 2. validity checks for the accounts
    # will keep track of total balance to make sure it's conserved
    total_balance = 0
    # will need some variables to ensure that accounts are sorted in the right order
    prev_balance, prev_addr = None, None
    for i, acct_dict in enumerate(state_dict["accounts"]):
        account_info_fields = {
            "address",
            "balance",
            "temporary_freeze_pds",
            "frozen_until_valid_block",
        }
        # account info has the right fields
        if not (
            (type(acct_dict) is dict) and set(acct_dict.keys()) == account_info_fields
        ):
            raise ValueError(
                "account invalid, doesn't have the right fields: position {}".format(i)
            )
        # check public key format is correct
        address = acct_dict["address"]
        if not _is_64len_hex_string(address):
            raise ValueError(
                "address {} is not a valid 64-digit hexadecimal".format(address)
            )
        # balance needs to be an int between 0 and the max possible
        if not type(acct_dict["balance"]) is int:
            raise ValueError("balance is not an integer for {}".format(address))
        if not (0 < acct_dict["balance"] <= ASSET_SUPPLY):
            raise ValueError("balance not in bounds for {}".format(address))
        # accounts should be listed in descending order of balance, then address
        if i > 0:
            if not (acct_dict["balance"] <= prev_balance):
                raise ValueError(
                    "addresses aren't sorted in descending balance order: {}".format(
                        address
                    )
                )
            if (acct_dict["balance"] == prev_balance) and (not address < prev_addr):
                raise ValueError(
                    "addresses with tied balances aren't sorted in descending address "
                    "order: {}".format(address)
                )
        prev_balance = acct_dict["balance"]
        prev_addr = address
        # account frozen periods should be a nonnegative int
        if not type(acct_dict["temporary_freeze_pds"]) is int:
            raise ValueError(
                "temporary_freeze_pds is not an integer for {}".format(address)
            )
        if not acct_dict["temporary_freeze_pds"] >= 0:
            raise ValueError("temporary freeze periods < 0 for {}".format(address))
        # account may be frozen until next valid block
        if not type(acct_dict["frozen_until_valid_block"]) is bool:
            raise ValueError(
                "frozen_until_valid_block is not a bool for {}".format(address)
            )
        # track the total balance as well
        total_balance = total_balance + acct_dict["balance"]
    # 3. check total balance
    if not total_balance == ASSET_SUPPLY:
        raise ValueError(
            "sum of balances doesn't match asset supply: {} vs {}".format(
                total_balance, ASSET_SUPPLY
            )
        )


def _load_parse_state(state_file):
    """
    Helper function to parse the SoV0 state file into some dicts
    Returns:
        state_hash: blake2b hash of the file binary
        headers: a dict, containing attributes of the state itself
            (e.g. current period, block producer)
        accounts_info: a dict of dicts.  outer dict is indexed on public keys
            of accounts, with each value being  a dict of statuses and values
    """
    state_raw, state_hash = _load_and_hash(state_file)
    state_dict = _json_load(state_raw)
    _check_state_validity(state_dict)
    headers = {k: state_dict[k] for k in state_dict.keys() if k != "accounts"}
    accounts_info = {}
    for acct_dict in state_dict["accounts"]:
        # now we can construct the info for this account
        accounts_info[acct_dict["address"]] = {
            "balance": acct_dict["balance"],
            "temporary_freeze_pds": acct_dict["temporary_freeze_pds"],
            "frozen_until_valid_block": acct_dict["frozen_until_valid_block"],
            # we also have a 'sendable_balance', which we initialize to the balance.
            # this is needed as an account can only send as much balance as they have at
            # the end of the previous period, so that balance received in a block  can't
            # be sent in another transaction in that same block. this 'sendable_balance'
            # quantity will track this as we update the state, see _apply_txn_to_state()
            # below for details
            "sendable_balance": acct_dict["balance"],
        }
    return state_hash, headers, accounts_info


########################################################################################
# III. Functions for updating state with a regular block (of transactions) #############


def _parse_block(block_raw):
    """
    Reads a block of transactions and signatures
    Args:
        block_file: the raw bytes of a block, an ascii-format bytestring that is a list,
            where each entry in the list is a dict with two entries: "txn", which is
            a dict of the transaction itself, and "sig", which is a string of the
            signature of the transaction.
    Returns:
        txn_sigs_list: a list of tuples corresponding to the transactions
            and signatures in the block. each tuple is (transaction, signature),
            both as ascii-encoded bytestrings.
    """
    block_txns = _json_load(block_raw)
    if not type(block_txns) is list:
        raise TypeError("block must be a list of (txn, sig) pairs")
    txn_sigs_list = []
    for txn_and_sig in block_txns:
        if type(txn_and_sig) is not dict:
            raise TypeError("each entry in block should be a dict")
        txn_sig_fields = {"txn", "sig"}
        if not set(txn_and_sig.keys()) == txn_sig_fields:
            raise ValueError(
                "each entry in block should have exactly these fields {}".format(
                    txn_sig_fields
                )
            )
        txn = _json_dumps(txn_and_sig["txn"])
        sig = txn_and_sig["sig"].encode("ascii")
        txn_sigs_list.append((txn, sig))
    return txn_sigs_list


def _update_accounts_pre_block(accounts_info, tmp_freeze_accounts=None):
    """
    Helper for how to update the state at start of period, prior to applying any
        transactions from a block. Basically, need to increment/decrement counters (i.e.
        how long an account is frozen from sending transactions), and temporarily freeze
        senders that submitted some ban-worthy transaction in this most recent block.
    Args:
        account_info: corresponding output of _load_parse_state()
        tmp_freeze_accounts: an iterable, of new addresses to temporarily freeze because
            they sent a transaction with correct period but bad state hash in the
            current block
    Returns:
        a copy of accounts_info, with all the counters updated
    """
    # need to deepcopy since it's a dict of dicts
    new_accounts_info = copy.deepcopy(accounts_info)
    # decrement the freeze periods of existing frozen accounts
    for k in new_accounts_info.keys():
        # decrement the ban length if it's positive
        if new_accounts_info[k]["temporary_freeze_pds"] > 0:
            new_accounts_info[k]["temporary_freeze_pds"] = (
                new_accounts_info[k]["temporary_freeze_pds"] - 1
            )
    # freeze accounts that need to be frozen
    if tmp_freeze_accounts is not None:
        for addr in tmp_freeze_accounts:
            if addr in new_accounts_info:
                new_accounts_info[addr]["temporary_freeze_pds"] = TEMPORARY_FREEZE_PDS
    return new_accounts_info


def _txn_pre_check(txn, sig, state_hash, state_headers, accounts_info, log_file=None):
    """
    Given a transaction & corresponding signature, figure out if it's obviously
        incorrect before even applying it to the state.
    Args:
        txn, sig: a transaction and a signature, both ascii bytestrings,
            as produced by _parse_block()
        state_hash, headers, accounts_info: outputs of _load_parse_state() as applied to
            the state file in the most recent period:
            `state_hash` is the blake2b hash of the current ledger state binary
            `state_headers` contains the current period, block producer, etc.
            `accounts_info` info on each account, i.e. balance & how long banned from
                sending transactions.  This is the status at the end of the prev period.
    Returns: a tuple with 4 entries, in order:
        passed_pre_check: bool, False if we've determined the transaction is invalid at
            this point, otherwise True.  Note that a transaction with the correct period
            but incorrect state hash will return False.
        freeze_sender: bool, true if the txn sender needs to be frozen for a bit
        txn_dict: the parsed transaction in dict form is either passed_pre_check or
            passed_pre_check is True, else None.
        pre_check_info: a string describing why the precheck passed or failed
    """
    # 0. if transaction is malformed => reject
    try:
        txn_dict = json.loads(txn.decode("ascii"))
        txn_hash = _default_hash(_json_dumps(txn_dict))
        _check_txn_format(txn_dict)
        txn_sender = txn_dict["from"]
        txn_period = txn_dict["period"]
        txn_state_hash = txn_dict["state"]
    except Exception as e:
        msg = "transaction is malformed: {}".format(str(e))
        return (False, False, None, msg)
    # 1. if signature doesn't match => reject
    try:
        _check_msg_sig(txn_hash, sig, txn_sender)
    except Exception as e:
        msg = "signature check failed: {}".format(str(e))
        return (False, False, None, msg)
    # 2. if sender didn't exist at the end of the previous period => reject
    if txn_sender not in accounts_info.keys():
        return (False, False, None, "sender doesn't exist")
    # 3. if the period is incorrect => reject
    if not txn_period == state_headers[STATE_PERIOD_FIELD]:
        return (False, False, None, "transaction has incorrect period")
    # 4. If the period is correct but state hash is wrong
    if not txn_state_hash == state_hash:
        msg = (
            "transaction has incorrect state hash, but is properly formatted & "
            "has the correct period & is properly signed"
        )
        return (False, True, txn_dict, msg)
    # 5. alright, passed the checks so far
    return (True, False, txn_dict, "transaction passed pre-check")


def _apply_txn_to_state(txn_dict, accounts_info):
    """
    Apply a transaction to update the balances & other info of each account, as we
        transition from the previous  period to the next.  This function assumes that
        the transaction has passed _txn_pre_check already.
    Args:
        txn_dict: a dict of a transaction, as produced by _json_load()
        accounts_info: the info of every account 'currently'.  As produced by
            load_parse_state() applied to previous period, but with
            _update_accounts_pre_block() applied to it already, and may have some
            transactions from the current block applied also.
    Returns:
        txn_applied: bool, True if transaction has been applied to state, else False
        txn_apply_info: a string describing any issues encountered with applying txn to
            state.  if no issues, returns a json of the txn.
    Side effects:
        updates accounts_info in place if txn_applied returns True, else no changes.
    """
    txn_amount = txn_dict["#SoV0"]
    txn_sender = txn_dict["from"]
    txn_receiver = txn_dict["to"]
    # 1. sender must not be frozen
    if (accounts_info[txn_sender]["temporary_freeze_pds"] > 0) or accounts_info[
        txn_sender
    ]["frozen_until_valid_block"]:
        return (False, "sender currently frozen, can't send transactions")
    # 2. sender can't send more balance per period than what they owned at the
    #   end of the previous period, even if other users are sending them balance
    #   in the current block. 'sendable_balance' tracks this.
    if txn_amount > accounts_info[txn_sender]["sendable_balance"]:
        txn_apply_info = (
            "transaction would require sender to send balance "
            + "they didn't have at the end of the last period"
        )
        return (False, txn_apply_info)
    # 3. OK, everything should check out by this point => safe to move balance
    #    as transaction dictates
    accounts_info[txn_sender]["balance"] -= txn_amount
    accounts_info[txn_sender]["sendable_balance"] -= txn_amount
    if txn_receiver in accounts_info:
        accounts_info[txn_receiver]["balance"] += txn_amount
    else:
        accounts_info[txn_receiver] = {
            "balance": txn_amount,
            "temporary_freeze_pds": 0,
            "frozen_until_valid_block": False,
            "sendable_balance": 0,
        }
    return (
        True,
        "transaction successfully applied:\n{}".format(
            _json_dumps(txn_dict).decode("ascii")
        ),
    )


def _produce_block_from_txn_sigs(txn_sigs_list, state_file, block_file, log_file=None):
    """
    Function for creating a block given a list of transactions & signatures. This is
        only needed if you need to produce a block (it's not needed to submit
        transactions or verify a block / update state). Should generally not need to be
        run, included here for completeness/testing.
    Args:
        txn_sigs_list: corresponding output of _parse_block(), a list of
            transactions and signatures, both of which are ascii bytestrings
        state_file: a file with the state in the most recent period
        block_file: the file to put the block produced from these transactions & sigs
        log_file: a file to log the run to, for debugging purposes.
    """
    # load up the state
    prev_state_hash, prev_state_headers, prev_accounts_info = _load_parse_state(
        state_file
    )
    # I. dedupe transactions
    _log(
        "============================================\ndeduplicating transactions:",
        log_file,
    )
    deduped_txn_sigs = {}
    seen_hashes = set()
    for i, (txn, sig) in enumerate(txn_sigs_list):
        tmp_hash = _default_hash(txn + sig)
        if tmp_hash in seen_hashes:
            _log("txn & sig {} is a duplicate".format(i), log_file)
        else:
            deduped_txn_sigs[i] = (txn, sig)
            seen_hashes.add(tmp_hash)
    # II. precheck transactions, freeze senders who sent transactions with correct
    #   period but incorrect state hash
    _log(
        "============================================\npre-checking transactions:",
        log_file,
    )
    freeze_address_txn_sigs = {}
    valid_txn_sigs = {}
    for i in deduped_txn_sigs:
        txn, sig = deduped_txn_sigs[i]
        sig_str = sig.decode("ascii")
        passed_pre_check, freeze_sender, txn_dict, pre_check_info = _txn_pre_check(
            txn, sig, prev_state_hash, prev_state_headers, prev_accounts_info, log_file
        )
        _log("txn {}: {}".format(i, pre_check_info), log_file)
        # if address needs to be frozen, add this transaction to the freeze dict
        if freeze_sender and (not txn_dict["from"] in freeze_address_txn_sigs):
            freeze_address_txn_sigs[txn_dict["from"]] = (txn_dict, sig_str)
            _log(_json_dumps(txn_dict).decode(), log_file)
        # if pass precheck, add it to the valid set for now
        elif passed_pre_check:
            valid_txn_sigs[i] = (txn_dict, sig_str)
    # III. before we apply the block, update the freeze periods and freeze newly
    #   to-be-frozen accounts
    curr_accounts_info = _update_accounts_pre_block(
        prev_accounts_info, freeze_address_txn_sigs.keys()
    )
    # IV. apply remaining transactions one at a time, throw out the failures
    _log(
        "==================================================\n"
        "FIGURING OUT WHICH TRANSACTIONS TO INCLUDE IN BLOCK",
        log_file,
    )
    for i in list(valid_txn_sigs.keys()):
        txn, sig = valid_txn_sigs[i]
        _log("----------------------------------------", log_file)
        _log("txn {}:".format(i), log_file)
        # apply transaction to state, txn_applied is True IFF applied
        txn_applied, txn_apply_info = _apply_txn_to_state(txn, curr_accounts_info)
        _log(txn_apply_info, log_file)
        if not txn_applied:
            del valid_txn_sigs[i]
    # IV. Now we have a dict of transactions from users who need to frozen, and a dict
    #   of transactions that are valid. These two will form the block.
    block_txn_list = [
        {"txn": txn_dict, "sig": sig_str}
        for (txn_dict, sig_str) in valid_txn_sigs.values()
    ] + [
        {"txn": txn_dict, "sig": sig_str}
        for (txn_dict, sig_str) in freeze_address_txn_sigs.values()
    ]
    with open(block_file, "wb") as f:
        f.write(_json_dumps(block_txn_list))
    _log("==========================================", log_file)
    _log("block created: {}".format(block_file), log_file)


# descriptions whether the state update was successful & how it failed if not, for use
#  in update_state_with_block() below
_state_update_statuses = [
    "STATE UPDATE SUCCEEDED with block",
    "STATE UPDATE SUCCEEDED without block",
    "STATE UPDATE FAILED: could not parse block",
    "STATE UPDATE FAILED: block has duplicate transactions",
    "STATE UPDATE FAILED: block is empty",
    "STATE UPDATE FAILED: bad block, a sender has multiple bad-state-hash transactions",
    "STATE UPDATE FAILED: bad block, has a malformed transaction",
    "STATE UPDATE FAILED: bad block, a transaction could not be applied",
]


def update_state_with_block(state_file, block_file, new_state_file, log_file=None):
    """
    Given the SoV0 state and a block, use the block to update the state.
    Args:
        state_file: a string file path, representing current SoV0 state (i.e. balances
            of each account + other info) interpretable by _load_parse_state().
        block_file: either None, or a filepath containing a block (i.e. list of
            transactions and signatures for updating the SoV0 state) of format
            interpretable by _parse_block().  By the point, the block is assumed to
            have been identified as the correct one via check_state_update_proposal().
        new_state_file: a file to dump the new state to
        log_file: if not None, then log the update process to this text file.
    Returns: update_status, a string of how the update went:
        "State update succeeded with block" if the state updated with a valid block
        "State update succeeded without block" if the state updated without a block
        Various other error messages if the STATE UPDATE FAILED.
    """
    update_status = _state_update_statuses[0]
    prev_state_hash, prev_state_headers, prev_accounts_info = _load_parse_state(
        state_file
    )
    # initialize log file
    _log("====== STARTING STATE UPDATE PROCESS ======", log_file, mode="w")
    # I. figure out if we have an obviously invalid block
    # block is assumed valid, until we violate something
    block_is_valid = True
    # 1. if the block is NONE, then it's invalid
    if block_is_valid and block_file is None:
        block_is_valid = False
        update_status = _state_update_statuses[1]
        _log(update_status, log_file)
    # 2. if the block can't be parsed, then it's invalid.
    if block_is_valid:
        try:
            block_raw, block_hash = _load_and_hash(block_file)
            txn_sigs_list = _parse_block(block_raw)
        except Exception as e:
            block_is_valid = False
            update_status = _state_update_statuses[2]
            _log("{}: {}".format(update_status, e), log_file)
    # 3. see if block has any duplicate transactions.  if so, then invalid
    if block_is_valid:
        _log(
            "============================================\n"
            "deduplicating transactions",
            log_file,
        )
        seen_hashes = set()
        for i, (txn, sig) in enumerate(txn_sigs_list):
            tmp_hash = _default_hash(txn)
            if tmp_hash in seen_hashes:
                block_is_valid = False
                update_status = _state_update_statuses[3]
                _log(update_status, log_file)
                break
            else:
                seen_hashes.add(tmp_hash)
    # 4. if block has no transactions, it's invalid.
    if block_is_valid and (len(txn_sigs_list) == 0):
        block_is_valid = False
        update_status = _state_update_statuses[4]
        _log(update_status, log_file)
    # II. precheck transactions, separate the good ones from the ones that have correct
    #   period but incorrect state hash.  if any transactions don't fit into one of
    #   these categories, the block is invalid.
    freeze_addresses = set()
    if block_is_valid:
        _log(
            "============================================\n"
            "pre-checking transactions",
            log_file,
        )
        valid_txn_sigs = {}
        for i, (txn, sig) in enumerate(txn_sigs_list):
            sig_str = sig.decode("ascii")
            passed_pre_check, freeze_sender, txn_dict, pre_check_info = _txn_pre_check(
                txn,
                sig,
                prev_state_hash,
                prev_state_headers,
                prev_accounts_info,
                log_file,
            )
            _log("txn {}: {}".format(i, pre_check_info), log_file)
            # if address needs to be frozen, add it to the list
            if freeze_sender:
                # block should include exactly one txn for each sender to be
                # frozen, otherwise block invalid
                if txn_dict["from"] in freeze_addresses:
                    block_is_valid = False
                    update_status = _state_update_statuses[5]
                    _log(update_status + " : " + txn_dict["from"], log_file)
                    break
                freeze_addresses.add(txn_dict["from"])
            # if pass precheck, add it to the valid set for now
            elif passed_pre_check:
                valid_txn_sigs[i] = (txn_dict, sig_str)
            # if it fails pre_check but isn't a freeze-sender transaction, then
            # block is invalid
            else:
                block_is_valid = False
                update_status = _state_update_statuses[6]
                _log(update_status + " the txn " + txn.decode("ascii"), log_file)
                break
    # III. before applying the block, update the freeze periods, include freezing the
    #  senders that had a freeze-worthy transaction in the current block
    if block_is_valid:
        new_accounts_info = _update_accounts_pre_block(
            prev_accounts_info, freeze_addresses
        )
    # IV. apply remaining transactions one at a time
    if block_is_valid:
        _log(
            "==================================================\n"
            "USING VALID TRANSACTIONS TO UPDATE STATE",
            log_file,
        )
        for i in list(valid_txn_sigs.keys()):
            txn, sig = valid_txn_sigs[i]
            # apply transaction to state, txn_applied is True IFF applied
            txn_applied, txn_apply_info = _apply_txn_to_state(txn, new_accounts_info)
            if not txn_applied:
                block_is_valid = False
                update_status = _state_update_statuses[7]
                _log(update_status + " info : " + txn_apply_info, log_file)
                break
    # V. at this point, we've either successfully applied all transactions or
    #    encountered something that makes the block invalid, so update the
    #    state headers and account info in accordance.
    if not block_is_valid:
        # 0. if the block is bad, tell the user to run update_state_without_block()
        if block_file is not None:
            print(
                "The block appears to be invalid.  Please check with the community to "
                "see if others are having this issue & coordinate on next steps."
            )
            return update_status
        # 1. if the block is None, then we're updating without a block, so just
        #  keep balances fixed and decrement freeze periods by 1, except also put
        #  current block producer on freeze until we have a valid block
        else:
            new_accounts_info = _update_accounts_pre_block(prev_accounts_info)
            curr_blockprod = prev_state_headers["block_producer"]
            if curr_blockprod in new_accounts_info.keys():
                new_accounts_info[curr_blockprod]["frozen_until_valid_block"] = True
            block_hash = "NONE"
    # if block is valid, everyone who's frozen until a valid block can now be unfrozen
    else:
        for k in new_accounts_info.keys():
            new_accounts_info[k]["frozen_until_valid_block"] = False
    # 2. We should be done processing accounts at this point, so we can now drop all
    #  zero-balance accounts and sort.  Sort it descending by balance, then address.
    for k in list(new_accounts_info.keys()):
        if new_accounts_info[k]["balance"] <= 0:
            del new_accounts_info[k]
    sorted_new_accounts_info = dict(
        sorted(
            new_accounts_info.items(),
            key=lambda x: (x[1]["balance"], x[0]),
            reverse=True,
        )
    )
    # 3. the new block producer: same guy if block is ok & they're not at limit.
    # otherwise, block producer is the biggest guy not currently frozen if literally
    # everyone is frozen... then, well, SoV0 fails and a fork will be necessary
    if block_is_valid and (
        prev_state_headers["block_producer_tenure"] < BLOCK_PRODUCER_MAX_TENURE
    ):
        new_block_producer = prev_state_headers["block_producer"]
    else:
        for address, account_info in sorted_new_accounts_info.items():
            if (
                (not address == prev_state_headers["block_producer"])
                and (account_info["temporary_freeze_pds"] == 0)
                and (not account_info["frozen_until_valid_block"])
            ):
                new_block_producer = address
                break
    # 4. the tenure of the new block producer
    if new_block_producer == prev_state_headers["block_producer"]:
        new_block_producer_tenure = prev_state_headers["block_producer_tenure"] + 1
    else:
        new_block_producer_tenure = 0
    # Finally, construct the state JSON that we'll dump
    state_json = {
        STATE_PERIOD_FIELD: prev_state_headers[STATE_PERIOD_FIELD] + 1,
        "prev_state": prev_state_hash,
        "prev_block": block_hash,
        "block_producer": new_block_producer,
        "block_producer_tenure": new_block_producer_tenure,
        "accounts": [],
    }
    for address, account_info in sorted_new_accounts_info.items():
        state_json["accounts"].append(
            {
                "address": address,
                "balance": account_info["balance"],
                "temporary_freeze_pds": account_info["temporary_freeze_pds"],
                "frozen_until_valid_block": account_info["frozen_until_valid_block"],
            }
        )
    # check it, and then write it
    _check_state_validity(state_json)
    with open(new_state_file, "wb") as f:
        f.write(_json_dumps(state_json))
    # log the outcome
    _log("===========================================", log_file)
    if block_is_valid:
        _log("block is VALID, used to update state", log_file)
        print("block is VALID, used to update state")
    else:
        _log("updating state without block", log_file)
        print("updating state without block")
    _log("new state in '{}'".format(new_state_file), log_file)
    print("new state in '{}'".format(new_state_file))
    return update_status


def _produce_state_update_proposal(block_file, new_state_file, proposal_file, sig_file):
    """
    Constructs a state update proposal, which contains information on the block & new
        state. This function only needs to be run if you're the block producer.
        Function assumes block & new state are valid, does no checks.
    Args:
        block_file: the block that you're proposing to update to the next period
        new_state_file: the new state, after applying the block
        proposal_file: a file to dump the proposal to
        sig_file: a file to dump the signature to
    Returns nothing.
    """
    if os.path.exists(proposal_file) or os.path.exists(sig_file):
        raise FileExistsError("proposal or signature file already exists.")
    # get state info
    new_state_hash, new_state_headers, _ = _load_parse_state(new_state_file)
    # construct proposal
    _, block_hash = _load_and_hash(block_file)
    proposal_dict = {
        "#SoV0_new_period": new_state_headers[STATE_PERIOD_FIELD],
        "new_state": new_state_hash,
        "block": block_hash,
        "current_state": new_state_headers["prev_state"],
    }
    proposal_canonical_json = _json_dumps(proposal_dict)
    proposal_canonical_hash = _default_hash(proposal_canonical_json)
    # sign it
    private_key = _derive_private_key()
    signed_hash = _sign_bytestring(proposal_canonical_hash, private_key)
    sig_dict = {"proposal_sig": signed_hash.decode("ascii")}
    # store these
    with open(proposal_file, "wb") as f:
        f.write(proposal_canonical_json)
    with open(sig_file, "wb") as f:
        f.write(_json_dumps(sig_dict))
    print("Run check_state_update_proposal to check this before you circulate")


def check_state_update_proposal(
    proposal_file,
    sig_file,
    current_state_file,
    block_file,
    new_state_file,
    log_file=None,
):
    """
    Checks that a state update proposal is correct, in that:
        - the proposal is signed by the current block producer
        - the block file has the hash listed in the proposal
        - the new state file matches the hash listed in the proposal
        - the current state file matches the hash listed in the proposal
    Args:
        proposal_file, sig_file: files holding the proposal and the block producer's
            signature of this proposal, as produced by _produce_state_update_proposal()
        current_state_file: the file with the current SoV0 state
        block_file: the file with the block that's used to update the current state to
            the new state
        new_state_file: a file to dump the new state into, after updating the state
            with the block
    Returns nothing, throws an error if anything doesn't check out.
    """
    # I. checking block proposal format
    with open(proposal_file, "rb") as f:
        proposal_raw = f.read()
    proposal_dict = _json_load(proposal_raw)
    proposal_canonical_hash = _default_hash(_json_dumps(proposal_dict))
    # I.1. checking if the proposal has the right fields
    proposal_fields = {"#SoV0_new_period", "new_state", "block", "current_state"}
    if not set(proposal_dict.keys()) == proposal_fields:
        raise ValueError(
            "proposal file improperly formatted, "
            "fields must be : {}".format(proposal_fields)
        )
    # I.2. checking if the proposal period is an int
    if not type(proposal_dict["#SoV0_new_period"]) == int:
        raise ValueError("proposal's new period is not a ")
    # I.3. checking if the various hashes the right format
    for k in ["new_state", "block", "current_state"]:
        if not _is_64len_hex_string(proposal_dict[k]):
            raise ValueError(
                "proposal field '{}' is not a 64-length hex string".format(k)
            )
    # II. checking if the block file matches the proposal
    _, block_hash = _load_and_hash(block_file)
    if not proposal_dict["block"] == block_hash:
        raise ValueError(
            "block file doesn't match block hash in proposal:\n"
            "block hash in proposal:\n'{}'\nhash of input block file:\n'{}'\n"
            "path to block file:\n'{}'".format(
                proposal_dict["block"], block_hash, block_file
            )
        )
    # III. checking if the state file matches the proposal
    state_hash, state_headers, _ = _load_parse_state(current_state_file)
    block_producer_address = state_headers["block_producer"]
    # III.2. does the proposal have the right state hash?
    if not proposal_dict["current_state"] == state_hash:
        raise ValueError(
            "proposal's 'current_state' doesn't match input current state file {}:"
            "proposal: {}\ncurrent file: {}".format(
                current_state_file, proposal_dict["current_state"], state_hash
            )
        )
    # III.1. is this proposal for the right period?
    if not proposal_dict["#SoV0_new_period"] == state_headers[STATE_PERIOD_FIELD] + 1:
        raise ValueError(
            "proposal period doesn't match: proposal says new periods is {}, "
            "but state file indicates it should be {}".format(
                proposal_dict["#SoV0_new_period"], state_headers[STATE_PERIOD_FIELD] + 1
            )
        )
    # IV. checking if the proposal is valid & signed by the block producer
    sig_fields = {"proposal_sig"}
    with open(sig_file, "rb") as f:
        sig_dict = _json_load(f.read())
        if not set(sig_dict.keys()) == sig_fields:
            raise ValueError(
                "signature file misformatted, field must be: {}".format(sig_fields)
            )
    _check_msg_sig(
        proposal_canonical_hash,
        sig_dict["proposal_sig"].encode("ascii"),
        block_producer_address.encode("ascii"),
    )
    # V. Update the state, and check if the new state hash matches the proposal
    state_update_status = update_state_with_block(
        state_file=current_state_file,
        block_file=block_file,
        new_state_file=new_state_file,
        log_file=log_file,
    )
    if state_update_status != _state_update_statuses[0]:
        raise ValueError(state_update_status)
    _, new_state_hash = _load_and_hash(new_state_file)
    if not proposal_dict["new_state"] == new_state_hash:
        raise ValueError(
            "new state doesn't match the proposal:\n"
            "new state hash listed in proposal: \n{}\n"
            "hash of the state file derived from updating the current state"
            "with the block:\n {}".format(proposal_dict["new_state"], new_state_hash)
        )
    # if we get here, then everything checks out
    print(
        "STATE UPDATE PROPOSAL IS VALID.  The state hash is the one listed in the"
        " the proposal:\n {}".format(new_state_hash)
    )


def update_state_without_block(state_file, new_state_file, log_file=None):
    """
    When the block producer fails to produce exactly one block proposal & block, or if
    there's general confusion about what the proposed block is, run this. This just runs
    update_state_with_block(), but with None as the block file.
    """
    return update_state_with_block(
        state_file=state_file,
        block_file=None,
        new_state_file=new_state_file,
        log_file=log_file,
    )


########################################################################################
# IV. Functions for freezing the current block producer if they're being bad ###########


def _check_block_producer_removal_petititon(petition_dict, sig_str, period):
    """
    Checks that a petition to remove a block producer & its associated signature
        are valid.
    Args:
        petition_dict: a dict containing the petition, as written by
            petition_to_remove_block_producer
        sig_str: a string, the signature of the petition, as produced by
            petition_to_remove_block_producer
        period: the current SoV0 period
    Returns nothing, throws an error if petition & sig doesn't check out
    """
    fields = {"#SoV0_remove_block_producer", "period", "sender"}
    if not set(petition_dict.keys()) == fields:
        raise ValueError("petition has incorrect fields")
    if not _is_64len_hex_string(petition_dict["sender"]):
        raise ValueError("sender address is invalid")
    if not type(petition_dict["#SoV0_remove_block_producer"]) is bool:
        raise ValueError("#SoV0_remove_block_producer is not a bool")
    if not petition_dict["#SoV0_remove_block_producer"]:
        raise ValueError("this sender doesn't want to remove block producer")
    if not (
        (type(petition_dict["period"]) is int)
        and (period >= 0)
        and (petition_dict["period"] == period)
    ):
        raise ValueError("petition period invalid or doesn't match input period")
    petition_canonical_hash = _default_hash(_json_dumps(petition_dict))
    _check_msg_sig(
        petition_canonical_hash,
        sig_str.encode("ascii"),
        petition_dict["sender"].encode("ascii"),
    )


def petition_to_remove_block_producer(period, petition_file, sig_file):
    """
    Helper for expressing interest in removing a block producer.  This is necessary if
        the block producer is misbehaving in a way other than producing invalid blocks,
        e.g. censoring transactions.  In at case, you should run this function and
        circulate the output.
    Args:
        period: the current SoV0 period, so we know which block producer it is.
        petition_file: a file to write the petition to
        sig_file: a file to write your signature of this petition to
    Example command line usage:
        python sov0.py petition_to_remove_block_producer \
            197 my_petition.txt my_petition_sig.txt
    """
    if os.path.exists(petition_file) or os.path.exists(sig_file):
        raise FileExistsError("Petition file or signature file exists already.")
    # get your private & public key
    private_key = _derive_private_key()
    address_hex = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    # the petition json
    petition_dict = {
        "#SoV0_remove_block_producer": True,
        "period": period,
        "sender": address_hex.decode("ascii"),
    }
    petition_canonical_bytes = _json_dumps(petition_dict)
    petition_canonical_hash = _default_hash(petition_canonical_bytes)
    # sign the petition
    sig_str = _sign_bytestring(petition_canonical_hash, private_key).decode("ascii")
    # construct a signature object and dump it
    sig_dict = {"removal_sig": sig_str}
    # check it
    _check_block_producer_removal_petititon(petition_dict, sig_str, period)
    # write them
    with open(petition_file, "wb") as f:
        f.write(petition_canonical_bytes)
    with open(sig_file, "wb") as f:
        f.write(_json_dumps(sig_dict))
    print(
        "SUCCESS: petition and signature written to '{}', '{}'".format(
            petition_file, sig_file
        )
    )


def _do_more_than_half_want_to_remove_block_producer(pro_removal_balance):
    """
    Helper for checking if a number is more than half of asset supply & printing some
        messages for how users should behave accordingly.
    Args:
        pro_removal_balance: an int, the total holdings of the pro-removal users
    """
    petition_passes = pro_removal_balance >= ASSET_SUPPLY // 2 + 1
    if petition_passes:
        print(
            "Petition to remove bock producer has enough support to pass: "
            "pro-removal users constitute {}/{} > 1/2 of holdings. "
            "Please circulate this broadly so the community can "
            "coordinate on removing the block producer.".format(
                pro_removal_balance, ASSET_SUPPLY
            )
        )
    else:
        print(
            "Pro-removal users constitute {}/{}<=1/2 of total asset supply. "
            "More support is needed before the community can coordinate "
            "on removing the current block producer.".format(
                pro_removal_balance, ASSET_SUPPLY
            )
        )
    return petition_passes


def _aggregate_block_producer_petitions(
    state_file, list_of_petition_sig_files, petitions_sigs_file
):
    """
    Helper for collecting the new block producer proposal & a bunch of signatures into a
        single list, so that once more than half of stake agree that the block producer
        should be removed, this fact can be more easily known by everyone without
        requiring everyone to download all of the petitions themselves.  Some
        particularly enthusiastic members of the SoV0 community will do this, so most
        users probably won't need to run this.
    Args:
        state_file: the state in this period
        list_of_petition_sig_files: list of tuples (petition_file, sig_file), each of
            format as dumped by petition_to_remove_block_producer()
        petitions_sigs_file: a file to dump the resulting list of valid
            petitions and signatures to
    """
    # need state info to check if we have 1/2 balance approving
    state_hash, state_headers, accounts_info = _load_parse_state(state_file)
    period = state_headers[STATE_PERIOD_FIELD]
    # get all the valid petitions to remove current block producer
    pro_removal_balance = 0
    list_of_valid_petitions_sigs = []
    petitioners_so_far = set()
    for petition_file, sig_file in list_of_petition_sig_files:
        with open(petition_file, "rb") as f:
            petition_dict = _json_load(f.read())
        with open(sig_file, "rb") as f:
            sig_str = _json_load(f.read())["removal_sig"]
        # check the petition and update the balance of pro-removers
        try:
            _check_block_producer_removal_petititon(petition_dict, sig_str, period)
            if petition_dict["sender"] in petitioners_so_far:
                raise ValueError("petitioner has already been counted")
            if not petition_dict["sender"] in accounts_info:
                raise ValueError("petitioner has no assets")
            petitioners_so_far.add(petition_dict["sender"])
            pro_removal_balance += accounts_info[petition_dict["sender"]]["balance"]
            list_of_valid_petitions_sigs.append((petition_dict, sig_str))
        except Exception as e:
            print("Issue with petition & signature: ", e)
        print(pro_removal_balance)
    _do_more_than_half_want_to_remove_block_producer(pro_removal_balance)
    with open(petitions_sigs_file, "wb") as f:
        f.write(_json_dumps(list_of_valid_petitions_sigs))
    print(
        "list of valid block producer removal petitions & signatures "
        "written to '{}'".format(petitions_sigs_file)
    )


def check_block_producer_removal_majority(petitions_sigs_file, state_file):
    """
    Checks that a majority of balance wants to remove the current block producer
    """
    state_hash, state_headers, accounts_info = _load_parse_state(state_file)
    period = state_headers[STATE_PERIOD_FIELD]
    with open(petitions_sigs_file, "rb") as f:
        list_of_petitions_sigs = _json_load(f.read())
    pro_removal_balance = 0
    petitioners_so_far = set()
    for petition_dict, sig_str in list_of_petitions_sigs:
        # check the petition and update the balance of pro-removers
        try:
            _check_block_producer_removal_petititon(petition_dict, sig_str, period)
            if petition_dict["sender"] in petitioners_so_far:
                raise ValueError("petitioner has already been counted")
            if petition_dict["sender"] in accounts_info:
                petitioners_so_far.add(petition_dict["sender"])
                pro_removal_balance += accounts_info[petition_dict["sender"]]["balance"]
        except Exception as e:
            print("Issue with petition & signature: ", e)
        print(pro_removal_balance)
    return _do_more_than_half_want_to_remove_block_producer(pro_removal_balance)


if __name__ == "__main__":
    func_to_run = globals()[sys.argv[1]]
    func_args = sys.argv[2:]
    func_to_run(*func_args)
