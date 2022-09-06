import copy
import os
import shutil
import time

import sov0

##### MONKEY PATCH HELPERS FOR TESTING #################################################

# monkeypatch the argon2id opslimit/memlimit parameters directly so tests run fast
sov0.OPSLIM = sov0.nacl.pwhash.argon2id.OPSLIMIT_MIN
sov0.MEMLIM = sov0.nacl.pwhash.argon2id.MEMLIMIT_MIN

#
sov0.STATE_PERIOD_FIELD = "SoV0_period"


def _monkeypatch_input(input_or_tuple_of_inputs):
    """
    Helper to override the default input() to return a specific input or iterate through
         a tuple of inputs.
    Args:
        input_or_list_of_inputs: should be a tuple if the goal is to iterate through it.
            If it's a tuple, then sov0.input() when it's first invoked will return the
                first entry of the tuple, then when it's invoked again it will return
                the second, then the third, etc. until it runs out of entries, at which
                point it will throw an IndexError.
            If it's not a tuple, sov0.input() should always just return this object no
                matter how many times it's invoked.
    """
    i = 0
    if not type(input_or_tuple_of_inputs) == tuple:
        sov0.input = lambda optiona_arg=None: input_or_tuple_of_inputs
    else:

        def tuple_iterator(optional_arg=None):
            nonlocal i
            if i >= len(input_or_tuple_of_inputs):
                raise IndexError("Monkeypatched input() tuple has run out of entries")
            output = input_or_tuple_of_inputs[i]
            i += 1
            return output

        sov0.input = tuple_iterator


def _monkeypatch_getpass(password):
    """
    Helper to override the default getpass.getpass to return something specific
    """
    sov0.getpass.getpass = lambda x: password


#### OTHER HELPERS #####################################################################
def _remove_and_recreate_dir(dir_path):
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    time.sleep(0.01)
    try:
        os.makedirs(dir_path)
    except FileExistsError:
        pass


# prepopulate a bunch of private keys to use in our tests here
_privkeys = {}
for i in range(10):
    _monkeypatch_input("nickname{}".format(i))
    _monkeypatch_getpass("pwd{}".format(i))
    _privkey = sov0._derive_private_key()
    _address = _privkey.verify_key.encode(encoder=sov0.nacl.encoding.HexEncoder)
    _privkeys[_address.decode("ascii")] = _privkey


def _get_id_of_address(addr):
    """
    helper for returning the 'i' used in constructing an address
    """
    i = 0
    for k in _privkeys:
        if k == addr:
            return i
        i += 1


def _sign_bytestring_pubkey(bytestring_to_sign, signer_public_key):
    """
    Helper for signing transactions.  using the pre-populated list of public and
    private keys we'll use in the tests here.
    """

    # sign the transaction with the sender's private key
    signed_hash = sov0._sign_bytestring(
        bytestring_to_sign, _privkeys[signer_public_key]
    )
    return signed_hash


def _construct_state():
    """
    A state dict that will be used in many tests here
    """
    state_dict = {
        "SoV0_period": 197,
        "prev_state": "528b36022f3bc7b1de66f30bbd011bb84fce3067c5eb593400d1b39055c32891",
        "prev_block": "bf2eb61254bcae09dca7bf4d81e83f16309a625a0dce599523fcc06c4d6198cd",
        "block_producer": "4597d2cd90c40d951a8d5def8509e7c0a63c77f3fabbdf93e858effbda623965",
        "block_producer_tenure": 0,
        "accounts": [
            {
                "address": "9a656ea050ef7f478d5c482701c10d46961fb511cf781be5af63a2f9a7251aae",
                "balance": int(0.4 * sov0.ASSET_SUPPLY),
                "temporary_freeze_pds": 0,
                "frozen_until_valid_block": True,
            },
            {
                "address": "4597d2cd90c40d951a8d5def8509e7c0a63c77f3fabbdf93e858effbda623965",
                "balance": int(0.25 * sov0.ASSET_SUPPLY),
                "temporary_freeze_pds": 1,
                "frozen_until_valid_block": False,
            },
            {
                "address": "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115",
                "balance": int(0.15 * sov0.ASSET_SUPPLY),
                "temporary_freeze_pds": 10,
                "frozen_until_valid_block": False,
            },
            {
                "address": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
                "balance": int(0.1 * sov0.ASSET_SUPPLY),
                "temporary_freeze_pds": 0,
                "frozen_until_valid_block": False,
            },
            {
                "address": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
                "balance": int(0.05 * sov0.ASSET_SUPPLY),
                "temporary_freeze_pds": 0,
                "frozen_until_valid_block": False,
            },
            {
                "address": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
                "balance": int(0.05 * sov0.ASSET_SUPPLY),
                "temporary_freeze_pds": 0,
                "frozen_until_valid_block": False,
            },
        ],
    }
    return state_dict


def _check_error_prefix(func_to_run, errortype, expected_error_prefix):
    """
    Helper for running a function and checking that we get an expected error.
    Args:
        funct_to_run: a function with no arguments to execute.
        errortype: e.g. ValueError, the type of error we expect
        expected_error_prefix: a string that should correspond to the first
            so many characters in the error message
    Returns:
        Nothing if it succeeds, otherwise throws an error
    """
    try:
        func_to_run()
        raise Exception(
            "expected error did not occur: {}:{}".format(
                errortype, expected_error_prefix
            )
        )
    except errortype as e:
        error_prefix = e.__str__()[: len(expected_error_prefix)]
        if error_prefix == expected_error_prefix:
            print("caught expected {}:".format(errortype), e)
        else:
            raise Exception(
                "wrong error prefix:\nexpected:\n'{}'\ngot:\n'{}'".format(
                    error_prefix, expected_error_prefix
                )
            )


##### TEST SOME OF THE HELPERS FROM ABOVE ##############################################
def test_monkeypatch_input_tuple():
    """
    Check that _monkeypatch_input() above works as intended with a tuple input
    """
    my_tuple = (1, "2", [3])
    _monkeypatch_input(my_tuple)
    for i in my_tuple:
        if not sov0.input() == i:
            raise ValueError("monkeypatched input() doesn't have enough entries")
    try:
        sov0.input()
        raise ValueError("there should be an IndexError here")
    except IndexError as e:
        print("Caught expected IndexError:", e)


def test_monkeypatch_input_nontuple():
    """
    Check that _monkeypatch_input() above works as intended with non-tuple input
    """
    my_input = "not a tuple"
    _monkeypatch_input(my_input)
    for _ in range(5):
        assert sov0.input() == my_input


##### SINGLE TEST OF THE ENTIRE PROCESS ################################################


def test_full_run(clean=True):
    # directory to put example data
    test_dir = "test_output/full_run"
    if clean:
        _remove_and_recreate_dir(test_dir)

    # I. SIMULATE SOME USERS
    # create a bunch of test users.  each user has a private key derived
    # from a password and a username.  password is just "pwd1" etc., and
    # username is just "nickname1" etc.

    for i in range(10):
        address_file = os.path.join(test_dir, "addr{}.txt".format(i))
        print("creating account", i)
        _monkeypatch_input("nickname{}".format(i))
        _monkeypatch_getpass("pwd{}".format(i))
        sov0.create_account_address(address_file)

    # II. CONSTRUCT THE INITIAL STATE
    curr_pd = 197
    state_file = os.path.join(test_dir, "state_period{}.txt".format(curr_pd))
    state_dict = _construct_state()
    print(state_dict)
    sov0._check_state_validity(state_dict)
    if not os.path.exists(state_file):
        # check it, and then write it
        with open(state_file, "wb") as f:
            f.write(sov0._json_dumps(state_dict))
    time.sleep(0.01)

    # III. PEOPLE CREATE TRANSACTIONS
    # extract state info from file
    state_fp = os.path.join(test_dir, "state_period197.txt")
    state_hash, headers, accounts_info = sov0._load_parse_state(state_fp)
    # all addresses
    # address_list = list(accounts_info.keys())
    # 0. send from 3 to 9, should be valid
    txn_id = 0
    sender_id = 3
    send_amt = 50000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71"
    to_addr = "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 1. send from 4 to 3, should be valid
    txn_id = 1
    sender_id = 4
    send_amt = 40000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca"
    to_addr = "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 2. send from 3 to 2, invalid b/c it would cause total sends from 3
    #    to exceed the balance 3 had at start of period even though 3 has enough
    #    balance currently as it received some in txn 1
    txn_id = 2
    sender_id = 3
    send_amt = 80000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71"
    to_addr = "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 3. send from 0 to 2, invalid b/c 1 is frozen until we have a valid block
    txn_id = 3
    sender_id = 0
    send_amt = 100000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "9a656ea050ef7f478d5c482701c10d46961fb511cf781be5af63a2f9a7251aae"
    to_addr = "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 4. send from 2 to 5, invalid b/c 2 is frozen temporarily
    txn_id = 4
    sender_id = 2
    send_amt = 10000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115"
    to_addr = "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 5. send from 9 to 7, invalid b/c 9 had zero balance at start of period
    #    even though it got some sent to it in txn 0
    txn_id = 5
    sender_id = 9
    send_amt = 10000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0"
    to_addr = "7cc0c50c872ff38e0830be69919117d92dc89f073a35662105b179d0d580e7d9"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 6. send from 4 to 3, invalid signature
    txn_id = 6
    sender_id = 0
    send_amt = 20000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca"
    to_addr = "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    try:
        sov0.check_transaction(txn_file, sig_file)
    except sov0.nacl.exceptions.BadSignatureError as e:
        print("caught an expected bad signature error:", e)
    # 7. send from 5 to 4, but with a bad state hash => invalid but included in block
    txn_id = 7
    sender_id = 5
    send_amt = 10000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    bad_state_hash = "4ef724dc022ff130a973afea6a9f713ad74c5d77efc71a237a03c338355d2f8d"
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6"
    to_addr = "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input(
        (send_amt, from_addr, to_addr, curr_pd, bad_state_hash, username)
    )
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 8. repeat of txn 0, invalid because it's a copy of an already applied txn
    txn_id = 8
    sender_id = 3
    send_amt = 50000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71"
    to_addr = "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 9. transaction for someone with a freeze period of 1 at end of past period, should
    #     go through since that freeze will be removed before any transactions
    txn_id = 9
    sender_id = 1
    send_amt = 80000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "4597d2cd90c40d951a8d5def8509e7c0a63c77f3fabbdf93e858effbda623965"
    to_addr = "ce8c5f415d6b5407a0d1c4e57426388c2d258da23731b21d75b95343b206af2a"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 10. transaction with an amount that's not a multiple of the transaction unit
    txn_id = 10
    sender_id = 2
    send_amt = 1
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    from_addr = "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115"
    to_addr = "ce8c5f415d6b5407a0d1c4e57426388c2d258da23731b21d75b95343b206af2a"
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    try:
        sov0.create_sign_transaction(txn_file, sig_file)
        sov0.check_transaction(txn_file, sig_file)
    except ValueError as e:
        print("Expected ValueError caught:", e)

    # IV. BLOCK PRODUCER PRODUCES THE BLOCK FROM THESE TRANSACTIONS
    block_file = os.path.join(test_dir, "block.txt")
    if not os.path.exists(block_file):
        state_file = os.path.join(test_dir, "state_period197.txt")
        log_file = os.path.join(test_dir, "block_production_log.txt")
        # load up the created transactions
        num_txns = len([x for x in os.listdir(test_dir) if x.startswith("txn")]) // 2
        list_of_txns_sigs = []
        for i in range(num_txns):
            with open(os.path.join(test_dir, "txn{}.txt".format(i)), "rb") as f:
                txn = f.read()
            with open(os.path.join(test_dir, "txn{}_sig.txt".format(i)), "rb") as f:
                sig_raw = f.read()
            sig_json = sov0._json_load(sig_raw)
            sig = sig_json["#SoV0_txn_sig"].encode("ascii")
            list_of_txns_sigs.append((txn, sig))
        # run the code that creates the block
        sov0._produce_block_from_txn_sigs(
            list_of_txns_sigs, state_file, block_file, log_file
        )
    time.sleep(0.01)

    # V. BLOCK PRODUCER USES BLOCK TO UPDATE STATE
    new_state_file = os.path.join(test_dir, "state_period198.txt")
    if not os.path.exists(new_state_file):
        sov0.update_state_with_block(
            state_file,
            block_file,
            new_state_file,
            os.path.join(test_dir, "state_update_period197_log.txt"),
        )
    time.sleep(0.01)

    # VI. BLOCK PRODUCER PRODUCES A STATE UPDATE PROPOSAL
    proposal_file = os.path.join(test_dir, "proposal.txt")
    proposal_sig_file = os.path.join(test_dir, "proposal_sig.txt")
    block_file = os.path.join(test_dir, "block.txt")
    block_producer_id = 1
    _monkeypatch_input("nickname{}".format(block_producer_id))
    _monkeypatch_getpass("pwd{}".format(block_producer_id))
    sov0._produce_state_update_proposal(
        block_file, new_state_file, proposal_file, proposal_sig_file
    )
    time.sleep(0.01)

    # VI. COMMUNITY CHECKS THE STATE UPDATE PROPOSAL PROPOSAL
    current_state_file = os.path.join(test_dir, "state_period197.txt")
    new_state_file_check = os.path.join(test_dir, "state_period198_check.txt")
    sov0.check_state_update_proposal(
        proposal_file,
        proposal_sig_file,
        current_state_file,
        block_file,
        new_state_file_check,
    )

    # it's now the next period
    curr_pd = 198

    # VIII. COMMUNITY MEMBERS PROPOSE TO REMOVE THE CURRENT BLOCK PRODUCER
    remove_block_producer_petitioners = [2, 1, 5, 3, 9]
    list_of_petition_sig_files = []
    for i in remove_block_producer_petitioners:
        _monkeypatch_input("nickname{}".format(i))
        _monkeypatch_getpass("pwd{}".format(i))
        petition_file = os.path.join(test_dir, "remove_blockprod{}.txt".format(i))
        sig_file = os.path.join(test_dir, "remove_blockprod_sig{}.txt".format(i))
        sov0.petition_to_remove_block_producer(curr_pd, petition_file, sig_file)
        list_of_petition_sig_files.append((petition_file, sig_file))
    time.sleep(0.01)

    # IX. ONE COMMUNITY MEMBER GATHERS THESE SIGNATURES UP
    aggregated_petitions_sigs_file = os.path.join(
        test_dir, "aggregated_petitions_sigs_file.txt"
    )
    state_file = os.path.join(test_dir, "state_period198.txt")
    sov0._aggregate_block_producer_petitions(
        state_file, list_of_petition_sig_files, aggregated_petitions_sigs_file
    )
    time.sleep(0.01)

    # X. COMMUNITY CHECKS THERE'S A MAJORITY
    majority_want_to_remove_block_producer = sov0.check_block_producer_removal_majority(
        aggregated_petitions_sigs_file, state_file
    )
    if majority_want_to_remove_block_producer:
        new_state_file = os.path.join(test_dir, "state_period199.txt")
        sov0.update_state_without_block(state_file, new_state_file)
    else:
        raise ValueError("ok, the majority should want to remove...")
    time.sleep(0.01)

    # hard code how the final state file should look.
    sov0.check_hash(
        os.path.join(test_dir, "state_period199.txt"),
        "e1269f8ae2b201b90a1281044dbea5fadc6aa558a8d6d9310a1134f2aead4cd1",
    )


def test_simple_example(clean=True):
    """
    A simpler version of test_full_run for expository purposes
    """
    # directory to put example data
    test_dir = "test_output/simple_example"
    if clean:
        _remove_and_recreate_dir(test_dir)

    # I. SIMULATE SOME USERS
    # create a bunch of test users.  each user has a private key derived
    # from a password and a username.  password is just "pwd1" etc., and
    # username is just "nickname1" etc.

    for i in range(10):
        address_file = os.path.join(test_dir, "addr{}.txt".format(i))
        print("creating account", i)
        _monkeypatch_input("nickname{}".format(i))
        _monkeypatch_getpass("pwd{}".format(i))
        sov0.create_account_address(address_file)

    # II. CONSTRUCT THE INITIAL STATE
    curr_pd = 197
    state_file = os.path.join(test_dir, "state_period{}.txt".format(curr_pd))
    if not os.path.exists(state_file):
        # get the public keys
        address_files = [x for x in os.listdir(test_dir) if x.startswith("addr")]
        addresses = []
        for fp in sorted(address_files):
            with open(os.path.join(test_dir, fp), "rb") as f:
                tmp_address = f.read()
            addresses.append(tmp_address.decode("ascii"))
        # balances of each account
        balance = [int(x * sov0.ASSET_SUPPLY) for x in [0.2, 0.4, 0.1, 0.05, 0.25]]
        # frozen for a fixed # of periods
        temporary_freeze_pds = [8, 0, 0, 0, 0]
        # frozen until have a valid block
        frozen_until_valid_block = [False, True, False, False, False]
        # put into the necessary format
        accounts_info = {}
        for i in range(len(balance)):
            print(addresses[i])
            accounts_info[addresses[i]] = {
                "balance": balance[i],
                "temporary_freeze_pds": temporary_freeze_pds[i],
                "frozen_until_valid_block": frozen_until_valid_block[i],
            }
        # sort the accounts
        sorted_accounts_info = dict(
            sorted(
                accounts_info.items(),
                key=lambda x: (x[1]["balance"], x[0]),
                reverse=True,
            )
        )
        # header info for the state
        prev_state = "528b36022f3bc7b1de66f30bbd011bb84fce3067c5eb593400d1b39055c32891"
        prev_block = "bf2eb61254bcae09dca7bf4d81e83f16309a625a0dce599523fcc06c4d6198cd"
        producer = "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca"
        state_json = {
            "SoV0_period": curr_pd,
            "prev_state": prev_state,
            "prev_block": prev_block,
            "block_producer": producer,
            "block_producer_tenure": 0,
            "accounts": [],
        }
        for address, account_info in sorted_accounts_info.items():
            state_json["accounts"].append(
                {
                    "address": address,
                    "balance": account_info["balance"],
                    "temporary_freeze_pds": account_info["temporary_freeze_pds"],
                    "frozen_until_valid_block": account_info[
                        "frozen_until_valid_block"
                    ],
                }
            )
    # check it, and then write it
    sov0._check_state_validity(state_json)
    with open(state_file, "wb") as f:
        f.write(sov0._json_dumps(state_json))
    time.sleep(0.01)

    # III. PEOPLE CREATE TRANSACTIONS
    # extract state info from file
    state_fp = os.path.join(test_dir, "state_period197.txt")
    state_hash, headers, accounts_info = sov0._load_parse_state(state_fp)
    # 0. a valid transaction
    txn_id = 0
    send_amt = 300000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    from_addr = "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca"
    to_addr = "7cc0c50c872ff38e0830be69919117d92dc89f073a35662105b179d0d580e7d9"
    sender_id = _get_id_of_address(from_addr)
    username = "nickname{}".format(sender_id)
    _monkeypatch_input((send_amt, from_addr, to_addr, curr_pd, state_hash, username))
    _monkeypatch_getpass("pwd{}".format(sender_id))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    # 0. a transaction with a bad state hash
    txn_id = 1
    send_amt = 1000000
    txn_file = os.path.join(test_dir, "txn{}.txt".format(txn_id))
    sig_file = os.path.join(test_dir, "txn{}_sig.txt".format(txn_id))
    from_addr = "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115"
    to_addr = "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71"
    bad_state_hash = "012345" + state_hash[6:]
    sender_id = _get_id_of_address(from_addr)
    username = "nickname{}".format(sender_id)
    _monkeypatch_input(
        (send_amt, from_addr, to_addr, curr_pd, bad_state_hash, username)
    )
    _monkeypatch_getpass("pwd{}".format(sender_id))
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)

    # IV. BLOCK PRODUCER PRODUCES THE BLOCK FROM THESE TRANSACTIONS
    block_file = os.path.join(test_dir, "block.txt")
    if not os.path.exists(block_file):
        state_file = os.path.join(test_dir, "state_period197.txt")
        log_file = os.path.join(test_dir, "block_production_log.txt")
        # load up the created transactions
        num_txns = len([x for x in os.listdir(test_dir) if x.startswith("txn")]) // 2
        list_of_txns_sigs = []
        for i in range(num_txns):
            with open(os.path.join(test_dir, "txn{}.txt".format(i)), "rb") as f:
                txn = f.read()
            with open(os.path.join(test_dir, "txn{}_sig.txt".format(i)), "rb") as f:
                sig_raw = f.read()
            sig_json = sov0._json_load(sig_raw)
            sig = sig_json["#SoV0_txn_sig"].encode("ascii")
            list_of_txns_sigs.append((txn, sig))
        # run the code that creates the block
        sov0._produce_block_from_txn_sigs(
            list_of_txns_sigs, state_file, block_file, log_file
        )
    time.sleep(0.01)

    # V. BLOCK PRODUCER USES BLOCK TO UPDATE STATE
    new_state_file = os.path.join(test_dir, "state_period198.txt")
    if not os.path.exists(new_state_file):
        sov0.update_state_with_block(
            state_file,
            block_file,
            new_state_file,
            os.path.join(test_dir, "state_update_period197_log.txt"),
        )
    time.sleep(0.01)

    # VI. BLOCK PRODUCER PRODUCES A STATE UPDATE PROPOSAL
    proposal_file = os.path.join(test_dir, "proposal.txt")
    proposal_sig_file = os.path.join(test_dir, "proposal_sig.txt")
    block_file = os.path.join(test_dir, "block.txt")
    block_producer_id = 4
    _monkeypatch_input("nickname{}".format(block_producer_id))
    _monkeypatch_getpass("pwd{}".format(block_producer_id))
    sov0._produce_state_update_proposal(
        block_file, new_state_file, proposal_file, proposal_sig_file
    )
    time.sleep(0.01)

    # VI. COMMUNITY CHECKS THE STATE UPDATE PROPOSAL PROPOSAL
    current_state_file = os.path.join(test_dir, "state_period197.txt")
    new_state_file_check = os.path.join(test_dir, "state_period198_check.txt")
    sov0.check_state_update_proposal(
        proposal_file,
        proposal_sig_file,
        current_state_file,
        block_file,
        new_state_file_check,
    )

    # it's now the next period
    curr_pd = 198

    # VIII. COMMUNITY MEMBERS PROPOSE TO REMOVE THE CURRENT BLOCK PRODUCER
    print("\n".join(_privkeys.keys()))
    pro_removal_addresses = [
        "4597d2cd90c40d951a8d5def8509e7c0a63c77f3fabbdf93e858effbda623965",
        "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115",
        "7cc0c50c872ff38e0830be69919117d92dc89f073a35662105b179d0d580e7d9",
    ]
    list_of_petition_sig_files = []
    for addr in pro_removal_addresses:
        i = _get_id_of_address(addr)
        _monkeypatch_input("nickname{}".format(i))
        _monkeypatch_getpass("pwd{}".format(i))
        petition_file = os.path.join(test_dir, "remove_blockprod{}.txt".format(i))
        sig_file = os.path.join(test_dir, "remove_blockprod_sig{}.txt".format(i))
        sov0.petition_to_remove_block_producer(curr_pd, petition_file, sig_file)
        list_of_petition_sig_files.append((petition_file, sig_file))
    time.sleep(0.01)

    # IX. ONE COMMUNITY MEMBER GATHERS THESE SIGNATURES UP
    aggregated_petitions_sigs_file = os.path.join(
        test_dir, "aggregated_petitions_sigs_file.txt"
    )
    state_file = os.path.join(test_dir, "state_period198.txt")
    sov0._aggregate_block_producer_petitions(
        state_file, list_of_petition_sig_files, aggregated_petitions_sigs_file
    )
    time.sleep(0.01)

    # X. COMMUNITY CHECKS THERE'S A MAJORITY
    majority_want_to_remove_block_producer = sov0.check_block_producer_removal_majority(
        aggregated_petitions_sigs_file, state_file
    )
    if majority_want_to_remove_block_producer:
        new_state_file = os.path.join(test_dir, "state_period199.txt")
        sov0.update_state_without_block(state_file, new_state_file)
    else:
        raise ValueError("ok, the majority should want to remove...")


##### TESTS FOR HELPER FUNCTIONS #######################################################
def test_message_signing():
    """
    Basic tests that _sign_bytestring() and _check_msg_sig() work as expected
    """
    msg_to_sign = b"this is my message"
    private_key = sov0.nacl.signing.SigningKey(("0" * 32).encode("ascii"))
    address = private_key.verify_key.encode(encoder=sov0.nacl.encoding.HexEncoder)
    # check that signing and checking works when using a public-private key pair
    signed_msg = sov0._sign_bytestring(msg_to_sign, private_key)
    sov0._check_msg_sig(msg_to_sign, signed_msg, address)
    # check that it fails when using an a different private key
    private_key2 = sov0.nacl.signing.SigningKey(("0" * 31 + "1").encode("ascii"))
    signed_msg2 = sov0._sign_bytestring(msg_to_sign, private_key2)
    try:
        sov0._check_msg_sig(msg_to_sign, signed_msg2, address)
        raise Exception("signature check succeeded when it should have failed")
    except sov0.nacl.exceptions.BadSignatureError as e:
        print("caught expected error:", e)
    # check that it fails when using an a different private key
    msg2 = b"this is a different message"
    try:
        sov0._check_msg_sig(msg2, signed_msg, address)
        raise Exception("signature check succeeded when it should have failed")
    except ValueError as e:
        print("caught expected error:", e)


def test_64len_hex_string():
    """
    Basic tests that _is_64len_hex_string() works as expected
    """
    print("0. a valid hex string")
    tmp_str = "0123456789abcdef" * 4
    if not sov0._is_64len_hex_string(tmp_str):
        raise ValueError("0. valid 64-length hex string not identified as such")
    print("valid as expected")
    print("1.an invalid string: letters are caps")
    tmp_str = "0" * 63 + "A"
    if sov0._is_64len_hex_string(tmp_str):
        raise ValueError("capital letters should not pass validity check")
    print("invalid as expected")
    print("2. an invalid string: non-hex characters")
    tmp_str = "0" * 63 + "g"
    if sov0._is_64len_hex_string(tmp_str):
        raise ValueError("non-hex characters should not pass validity check")
    print("invalid as expected")
    print("3. an invalid string: non-hex characters")
    tmp_str = "0" * 63 + "."
    if sov0._is_64len_hex_string(tmp_str):
        raise ValueError("non-hex characters should not pass validity check")
    print("invalid as expected")
    print("4. an invalid string: not length 64")
    tmp_str = "0" * 50
    if sov0._is_64len_hex_string(tmp_str):
        raise ValueError("non-64 length strings should not pass validity check")
    print("invalid as expected")
    print("5. an invalid string: bytestring")
    tmp_str = ("0" * 64).encode("ascii")
    if sov0._is_64len_hex_string(tmp_str):
        raise ValueError("bytestrings should not pass validity check")
    print("invalid as expected")
    print("6. an invalid string: an array")
    tmp_str = ["0"] * 64
    if sov0._is_64len_hex_string(tmp_str):
        raise ValueError("arrays should not pass validity check")
    print("invalid as expected")
    print("7. an invalid string: an int")
    tmp_str = 1111111111111111111111111111111111111111111111111111111111111111
    if sov0._is_64len_hex_string(tmp_str):
        raise ValueError("ints should not pass validity check")
    print("invalid as expected")


##### TESTS FOR WALLET FUNCTIONS #######################################################


def test_address_derivation():
    """
    Some hardcoded has comparisons to ensure that the derivation of username + password
        yields expected results.
    """
    # This test will use the production opslim/memlim values, which will make it take
    #  a bit longer.  But necessary to ensure consistency with the Javascript version.
    sov0.OPSLIM = sov0.nacl.pwhash.argon2id.OPSLIMIT_MODERATE
    sov0.MEMLIM = sov0.nacl.pwhash.argon2id.MEMLIMIT_MODERATE
    username_password_address_triplets = [
        (
            "myusername",
            "mypassword",
            "47f15d70ca2ee9f28ad94257883f57c63fce879eb675d058066ce72d1684c85d",
        ),
        (
            "my user name",
            "my pass word",
            "7537362ba17a9871d846857673cc650971ee4dcef5aaef6d23cdc16ca8e7e303",
        ),
        (
            "my@user.name",
            "my-pass-W@r!!!,0",
            "4e4e41a54ed8800ab44eb36530b98c9f8f0f565fb6301c5d96ccd037b2b5274d",
        ),
    ]
    for username, password, address in username_password_address_triplets:
        _monkeypatch_input(username)
        _monkeypatch_getpass(password)
        derived_address = sov0._derive_private_key().verify_key.encode(
            encoder=sov0.nacl.encoding.HexEncoder
        )
        if not derived_address.decode() == address:
            raise ValueError(
                "addresses fail to match for username='{}'  &  password='{}'\n"
                "generated address: '{}'\n"
                "expected address : '{}'\n".format(
                    username, password, derived_address.decode(), address
                )
            )
        print(
            "addresses match for username='{}' & password='{}'".format(
                username, password
            )
        )
    # reset the opslimit/memlimit
    sov0.OPSLIM = sov0.nacl.pwhash.argon2id.OPSLIMIT_MIN
    sov0.MEMLIM = sov0.nacl.pwhash.argon2id.MEMLIMIT_MIN


def test_account_access(clean=True):
    """
    Basic tests that account access via create_account_address() and checking
        access via check_account_access() work as expected.
    """
    test_dir = "test_output/account_access"
    if clean:
        _remove_and_recreate_dir(test_dir)
    # username and pwd for account
    correct_username = "my_test_account_username"
    correct_password = "my_account_password_1/-'~]"
    _monkeypatch_input(correct_username)
    _monkeypatch_getpass(correct_password)
    # dump the address
    address_filepath = os.path.join(test_dir, "my_pubkey.txt")
    sov0.create_account_address(address_filepath)
    print()
    print("0. check account access works with correct username and pwd")
    _monkeypatch_input(correct_username)
    _monkeypatch_getpass(correct_password)
    if not sov0.check_account_access(address_filepath):
        raise ValueError("account access failed with correct username & password")
    print("access succeeded, as expected")
    print("1. check that it fails with bad password")
    _monkeypatch_input(correct_username)
    _monkeypatch_getpass("my_incorrect_account_password")
    if sov0.check_account_access(address_filepath):
        raise ValueError(
            "account access succeeded with correct username but incorrect password"
        )
    print("access failed, as expected")
    print("2. check that it fails with bad username")
    _monkeypatch_input("my_incorrect_account_username")
    _monkeypatch_getpass(correct_password)
    if sov0.check_account_access(address_filepath):
        raise ValueError(
            "account access succeeded with correct password but incorrect username"
        )
    print("access failed, as expected")
    print("3. check that it fails with bad username & password")
    _monkeypatch_input("my_incorrect_account_username")
    _monkeypatch_getpass(correct_password)
    if sov0.check_account_access(address_filepath):
        raise ValueError(
            "account access succeeded with incorrect username and password"
        )
    print("access failed, as expected")


def test_txn_format_check():
    """
    Basic tests that our validity check for transaction format _check_txn_format()
        works as expected
    """
    print("0. a validly formatted transaction")
    txn_dict_original = {
        "#SoV0": 50000000,
        "from": "d18c5258474b7617b63a66da157b8f897ded2c5c38d21a84fc7e4663d60dab1f",
        "to": "87a2e806a9d044c24f44fea9d82c118d43dac5adee68033c11c1a7bb99d91913",
        "period": 197,
        "state": "1de94717cbf32f3ae4fbcd89745962b016473a52d65fa0228312882b7c312d8d",
    }
    sov0._check_txn_format(txn_dict_original)
    print("check passed, as expected")
    print("1. amount to send is not an int, invalid")
    txn_dict = txn_dict_original.copy()
    txn_dict["#SoV0"] = txn_dict["#SoV0"] + 0.1
    _check_error_prefix(
        lambda: sov0._check_txn_format(txn_dict),
        ValueError,
        "transaction amount must be a positive integer",
    )
    print("2. period is not an int, invalid")
    txn_dict = txn_dict_original.copy()
    txn_dict["period"] = "197"
    _check_error_prefix(
        lambda: sov0._check_txn_format(txn_dict),
        ValueError,
        "current period must be a nonnegative integer",
    )
    print("3. sender address not valid 64 len hex string")
    txn_dict = txn_dict_original.copy()
    txn_dict["from"] = txn_dict["from"][:55]
    _check_error_prefix(
        lambda: sov0._check_txn_format(txn_dict),
        ValueError,
        "sender is not a valid 64-length hex string",
    )
    print("4. receiver address not valid 64 len hex string")
    txn_dict = txn_dict_original.copy()
    txn_dict["to"] = txn_dict["to"][:60] + "-/*g"
    _check_error_prefix(
        lambda: sov0._check_txn_format(txn_dict),
        ValueError,
        "receiver is not a valid 64-length hex string",
    )
    print("5. state hash not valid 64 len hex string")
    txn_dict = txn_dict_original.copy()
    txn_dict["state"] = list(txn_dict["state"])
    _check_error_prefix(
        lambda: sov0._check_txn_format(txn_dict),
        ValueError,
        "state hash is not a valid 64-length hex string",
    )
    print("6. amount to send is not a multiple of the minimum transaction unit")
    #   we eventually reach sov0.TRANSACTION_UNIT = 1, this test will fail
    txn_dict = txn_dict_original.copy()
    txn_dict["#SoV0"] = 1
    _check_error_prefix(
        lambda: sov0._check_txn_format(txn_dict),
        ValueError,
        "transaction amount must be a multiple of",
    )


def test_transaction_sig(clean=True):
    """
    Basic tests for validity of transaction creation & signing via
        create_sign_transaction() and check_transaction(), as well as for checking
        if a transaction receiver corresponds to a given username and password
        via check_transaction_receiver()
    """
    test_dir = "test_output/transactions"
    if clean:
        _remove_and_recreate_dir(test_dir)
    # I. create_sign_transaction() and check_transaction()
    # username and pwd for transactions sender
    correct_sender_username = "my_sender_username"
    correct_sender_password = "my_sender_password"
    _monkeypatch_input(correct_sender_username)
    _monkeypatch_getpass(correct_sender_password)
    sender_public_key = sov0._derive_private_key().verify_key
    from_addr = sender_public_key.encode(encoder=sov0.nacl.encoding.HexEncoder)
    # username and pwd for transactions receiver
    correct_receiver_username = "my_receiver_username"
    correct_receiver_password = "my_receiver_password"
    _monkeypatch_input(correct_receiver_username)
    _monkeypatch_getpass(correct_receiver_password)
    receiver_public_key = sov0._derive_private_key().verify_key
    to_addr = receiver_public_key.encode(encoder=sov0.nacl.encoding.HexEncoder)
    # construct a transaction
    amount = 50000000
    sender_addr = from_addr.decode("ascii")
    receiver_addr = to_addr.decode("ascii")
    period = 197
    state_hash = "1de94717cbf32f3ae4fbcd89745962b016473a52d65fa0228312882b7c312d8d"
    print("0. create and sign this transaction, should be valid")
    _monkeypatch_getpass(correct_sender_password)
    txn_file = os.path.join(test_dir, "my_txn0.txt")
    sig_file = os.path.join(test_dir, "my_sig0.txt")
    username = correct_sender_username
    _monkeypatch_input(
        (amount, sender_addr, receiver_addr, period, state_hash, username)
    )
    sov0.create_sign_transaction(txn_file, sig_file)
    sov0.check_transaction(txn_file, sig_file)
    print("is valid, as expected")
    print("1. create and check a txn with a bad signature, should throw bad sig error")
    _monkeypatch_getpass("my_incorrect_sender_password")
    txn_file = os.path.join(test_dir, "my_txn1.txt")
    sig_file = os.path.join(test_dir, "my_sig1.txt")
    username = correct_sender_username
    _monkeypatch_input(
        (amount, sender_addr, receiver_addr, period, state_hash, username)
    )
    sov0.create_sign_transaction(txn_file, sig_file)
    _check_error_prefix(
        lambda: sov0.check_transaction(txn_file, sig_file),
        sov0.nacl.exceptions.BadSignatureError,
        "Signature was forged or corrupt",
    )
    ## II. check_transaction_receiver()
    print("2. check that the transaction receiver checks out")
    _monkeypatch_input(correct_receiver_username)
    _monkeypatch_getpass(correct_receiver_password)
    txn_file = os.path.join(test_dir, "my_txn0.txt")
    sov0.check_transaction_receiver(txn_file)
    print("transaction receiver checks out, as expected")
    print("3. check that the transaction receiver fails with a bad username")
    _monkeypatch_input("my_incorrect_sender_username")
    _monkeypatch_getpass(correct_receiver_password)
    txn_file = os.path.join(test_dir, "my_txn0.txt")
    _check_error_prefix(
        lambda: sov0.check_transaction_receiver(txn_file),
        ValueError,
        "transaction recipient doesn't match input username & password",
    )
    print("4. check that the transaction receiver fails with a bad password")
    _monkeypatch_input(correct_receiver_username)
    _monkeypatch_getpass("my_incorrect_sender_password")
    txn_file = os.path.join(test_dir, "my_txn0.txt")
    _check_error_prefix(
        lambda: sov0.check_transaction_receiver(txn_file),
        ValueError,
        "transaction recipient doesn't match input username & password",
    )
    print("4. check that the transaction receiver fails with a bad username & password")
    _monkeypatch_input(correct_receiver_username)
    _monkeypatch_getpass("my_incorrect_sender_password")
    txn_file = os.path.join(test_dir, "my_txn0.txt")
    _check_error_prefix(
        lambda: sov0.check_transaction_receiver(txn_file),
        ValueError,
        "transaction recipient doesn't match input username & password",
    )


##### TESTS FOR STATE FUNCTIONS #######################################################


def test_check_state_validity():
    """
    Tests for _check_state_validity()
    """

    # construct a valid state dict
    correct_state_dict = _construct_state()
    # 0. check it, should check out
    print("0. valid state, should be fine:")
    sov0._check_state_validity(correct_state_dict)
    print("state checks out, as expected")
    print("1. the period is not an int, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["SoV0_period"] = "1234"
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "current period invalid, must be nonnegative integer",
    )
    print("2. the period is negative, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["SoV0_period"] = -12
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "current period invalid, must be nonnegative integer",
    )
    # _check_error_prefix("current period invalid, must be nonnegative integer")
    print("3. the prev state hash is not 64 len, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["prev_state"] = state_dict["prev_state"][:45]
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "previous state hash is not valid",
    )
    print("4. the prev block hash contain invalid characters, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["prev_block"] = state_dict["prev_block"][:63] + "g"
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "previous block hash is not valid",
    )
    print("5. block producer is a tuple rather than a string, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["block_producer"] = ("this is a", "tuple", "not a string")
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "block producer is not valid",
    )
    print("6. block producer tenure is negative, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["block_producer_tenure"] = -35
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "block producer's tenure is negative or too big",
    )
    print("7. block producer tenure is not an int, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["block_producer_tenure"] = False
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "block producer's tenure is not an int",
    )
    print("8. state dict is not a dict, should fail")
    state_dict = list(state_dict.values())
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "state_dict is not a dict with these fields",
    )
    print("9. the state dict has extraneous fields, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["extra_field"] = 1234
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "state_dict is not a dict with these fields",
    )
    print("10. the state dict has missing fields, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    del state_dict["block_producer_tenure"]
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "state_dict is not a dict with these fields",
    )
    print("11. balances don't add up, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][1]["balance"] -= 1
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "sum of balances doesn't match asset supply",
    )
    print("12. account balance not positive, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][0]["balance"] += state_dict["accounts"][-1]["balance"]
    state_dict["accounts"][-1]["balance"] = 0
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "balance not in bounds for",
    )
    print("13. account balance too big, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][0]["balance"] = sov0.ASSET_SUPPLY + 1
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "balance not in bounds for",
    )
    print("14. account balance not an int, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][0]["balance"] = True
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "balance is not an integer for",
    )
    print("15. account balances not in decreasing order, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    tmp_acct1 = state_dict["accounts"][0]
    state_dict["accounts"] = state_dict["accounts"][1:] + [tmp_acct1]
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "addresses aren't sorted in descending balance order",
    )
    print("16. accounts with same balance not in descending addr order, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    tmp_acct1 = state_dict["accounts"][-1]
    tmp_acct2 = state_dict["accounts"][-2]
    state_dict["accounts"] = state_dict["accounts"][:-2] + [tmp_acct1, tmp_acct2]
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "addresses with tied balances aren't sorted in descending address order",
    )
    print("17. an account doesn't have the correct fields, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][1]["unnecessary_field"] = "this field is not needed"
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "account invalid, doesn't have the right fields",
    )
    print("18. an account's freeze period is not an int, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][1]["temporary_freeze_pds"] = True
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "temporary_freeze_pds is not an integer for",
    )
    print("19. an account's frozen-until-valid is not a bool, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][1]["frozen_until_valid_block"] = "True"
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "frozen_until_valid_block is not a bool for",
    )
    print("20. an account is not a dict, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["accounts"][1] = ("this is", "not a", "dict")
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "account invalid, doesn't have the right fields",
    )
    print("21. block producer has zero balance / is not in accounts, should be valid:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["block_producer"] = "0" * 64
    sov0._check_state_validity(state_dict)
    print("state is valid, as expected")
    print("22. previous state is NONE but period is more than zero, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["prev_state"] = "NONE"
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "previous state hash is not valid",
    )
    print("23. previous state is not None but period is zero, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["SoV0_period"] = 0
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "previous state hash is not valid",
    )
    print("23. previous block is None but block producer tenure not zero, should fail:")
    state_dict = copy.deepcopy(correct_state_dict)
    state_dict["prev_block"] = "NONE"
    state_dict["block_producer_tenure"] = 3
    _check_error_prefix(
        lambda: sov0._check_state_validity(state_dict),
        ValueError,
        "previous block is NONE, yet block producer tenure > 0",
    )


def test_load_parse_state(clean=True):
    """
    Basic test for _load_parse_state().  This just tests that the loading works as
        expected, as the validity check is handled by _check_state_validity()
    """
    test_dir = "test_output/load_parse_state"
    if clean:
        _remove_and_recreate_dir(test_dir)
    state_dict = _construct_state()
    state_file = os.path.join(test_dir, "state.txt")
    state_ascii = sov0._json_dumps(state_dict)
    with open(state_file, "wb") as f:
        f.write(state_ascii)
    time.sleep(0.01)
    # define the correct hash, headers, and accounts info
    state_hash = sov0._default_hash(state_ascii)
    correct_headers = {k: state_dict[k] for k in state_dict if not k == "accounts"}
    headers_hash = sov0._default_hash(sov0._json_dumps(correct_headers))
    correct_accounts_info = {}
    for account in state_dict["accounts"]:
        addr = account["address"]
        correct_accounts_info[addr] = {
            k: account[k] for k in account.keys() if k != "address"
        }
        correct_accounts_info[addr]["sendable_balance"] = correct_accounts_info[addr][
            "balance"
        ]
    accounts_hash = sov0._default_hash(sov0._json_dumps(correct_accounts_info))

    print("state_hash:", state_hash)
    print("headers_hash:", headers_hash)
    print("accounts_hash:", accounts_hash)

    # compare these hard-coded hashes to output of the function
    loaded_state_hash, loaded_headers, loaded_accounts_info = sov0._load_parse_state(
        state_file
    )
    if not state_hash == loaded_state_hash.encode("ascii"):
        print(state_hash)
        print(loaded_state_hash)
        raise ValueError("hash of state is incorrect")
    if not headers_hash == sov0._default_hash(sov0._json_dumps(loaded_headers)):
        raise ValueError("hash of the headers doesn't match")
    if not accounts_hash == sov0._default_hash(sov0._json_dumps(loaded_accounts_info)):
        print
        raise ValueError("hash of the accounts info doesn't match")


##### TESTS FOR BLOCK FUNCTIONS ########################################################


def test_parse_block(clean=True):
    """
    Tests for _parse_block()
    """
    test_dir = "test_output/parse_block"
    if clean:
        _remove_and_recreate_dir(test_dir)
    # construct a block
    state_hash = "1de94717cbf32f3ae4fbcd89745962b016473a52d65fa0228312882b7c312d8d"
    bad_state_hash = state_hash[:63] + "0"
    block_txn_sigs = [
        {
            "txn": {
                "#SoV0": 5000,
                "from": "d18c5258474b7617b63a66da157b8f897ded2c5c38d21a84fc7e4663d60dab1f",
                "to": "87a2e806a9d044c24f44fea9d82c118d43dac5adee68033c11c1a7bb99d91913",
                "period": 197,
                "state": state_hash,
            },
            "sig": (
                "36a5f7d4e08a913d2e8596f559db1ad87f7f1331393411d40c015d96510244bb"
                "ac51c4a5d861e85271fe12607a758bc3bc632b2f27a219903533b82f9d3ec207"
                "36656235393434303065613934306261303465353737333336306132323134393"
                "863646461393639356638336638356436326164646631343364393163646561"
            ),
        },
        {
            "txn": {
                "#SoV0": 10000,
                "from": "1bcd4a479bb64d0a396a748f9a234932a13c6fb721c4096fe20c6101c3a40518",
                "to": "d18c5258474b7617b63a66da157b8f897ded2c5c38d21a84fc7e4663d60dab1f",
                "period": 197,
                "state": state_hash,
            },
            "sig": (
                "66672a955e7f26a787a91215b1eeb570bec7139864b058cb22f34a052422855f"
                "4fa168531a25c9b8b7fba94b8ac2723e0d42f2b69d6d45220ccd539af324ac0f"
                "61613834363134303636333165303036663332336261656163636130386538326"
                "436376238343337343362333266386466363365383930663338386664626261"
            ),
        },
        {
            "txn": {
                "#SoV0": 1000,
                "from": "ad7254fbc2934ff0c324aace1fb7e747770f671778b9a4e3fc2c48d9e317e589",
                "to": "1bcd4a479bb64d0a396a748f9a234932a13c6fb721c4096fe20c6101c3a40518",
                "period": 197,
                "state": bad_state_hash,
            },
            "sig": (
                "2f47c1c3215cfb05750f539bce1f74158d96913bc6846e58e74e56508a93ad15"
                "f3ff4d2fbe398bfd9b7bb31525e047001095b5c41c7217a6258ba4a2b0b44505"
                "3438336535376233653964366262336537643763356432323765303766653835"
                "6261653764653234623430626435363738333264313463346538623634633532"
            ),
        },
    ]
    print("0. correct block, it should parse properly")
    block_file = os.path.join(test_dir, "block0.txt")
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block_txn_sigs))
    time.sleep(0.01)
    with open(block_file, "rb") as f:
        _ = sov0._parse_block(f.read())
    print("parsed")
    print("1. the block is a dict rather than a list, then invalid")
    txn_sigs = copy.deepcopy(block_txn_sigs)
    txn_sigs = {i: x for (i, x) in enumerate(txn_sigs)}
    block_file = os.path.join(test_dir, "block1.txt")
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(txn_sigs))
    time.sleep(0.01)
    with open(block_file, "rb") as f:
        block_raw = f.read()
    _check_error_prefix(
        lambda: sov0._parse_block(block_raw),
        TypeError,
        "block must be a list of (txn, sig) pairs",
    )
    print("2. one of the entries in the block is not a dict, invalid")
    txn_sigs = copy.deepcopy(block_txn_sigs)
    txn_sigs[1] = list(txn_sigs[1].values())
    block_file = os.path.join(test_dir, "block2.txt")
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(txn_sigs))
    time.sleep(0.01)
    with open(block_file, "rb") as f:
        block_raw = f.read()
    _check_error_prefix(
        lambda: sov0._parse_block(block_raw),
        TypeError,
        "each entry in block should be a dict",
    )
    print("3. if one of the block entries doesn't have the right fields, invalid")
    txn_sigs = copy.deepcopy(block_txn_sigs)
    txn_sigs[1]["extraneous_field"] = "this field is not needed"
    block_file = os.path.join(test_dir, "block3.txt")
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(txn_sigs))
    time.sleep(0.01)
    with open(block_file, "rb") as f:
        block_raw = f.read()
    _check_error_prefix(
        lambda: sov0._parse_block(block_raw),
        ValueError,
        "each entry in block should have exactly these fields",
    )


def test_update_accounts_pre_block():
    """
    Tests for _update_accounts_pre_block(), which just freezes some accounts and
        otherwise decrements counters for how long accounts are frozen.
    """
    state_dict = _construct_state()
    # the initial accounts info
    accounts_info = {}
    for acc in state_dict["accounts"]:
        accounts_info[acc["address"]] = {k: acc[k] for k in acc if k != "address"}
        accounts_info[acc["address"]]["sendable_balance"] = acc["balance"]
    # new accounts to freeze
    tmp_freeze_accounts = [
        "4597d2cd90c40d951a8d5def8509e7c0a63c77f3fabbdf93e858effbda623965"
    ]
    # manually decrement counter in the new accounts info
    correct_new_accounts_info = {}
    for addr in accounts_info:
        correct_new_accounts_info[addr] = accounts_info[addr].copy()
        if correct_new_accounts_info[addr]["temporary_freeze_pds"] >= 1:
            correct_new_accounts_info[addr]["temporary_freeze_pds"] -= 1
    # manually freeze the new accounts
    for addr in tmp_freeze_accounts:
        if addr in correct_new_accounts_info:
            correct_new_accounts_info[addr][
                "temporary_freeze_pds"
            ] = sov0.TEMPORARY_FREEZE_PDS
    correct_hash = sov0._default_hash(sov0._json_dumps(correct_new_accounts_info))
    print("correct new accounts info")
    print(sov0._json_dumps(correct_new_accounts_info).decode())
    print("new accounts info from using _update_accounts_pre_block()")
    print(sov0._json_dumps(accounts_info).decode())
    # check that apply this function matches the above
    new_accounts_info = sov0._update_accounts_pre_block(
        accounts_info, tmp_freeze_accounts
    )
    new_hash = sov0._default_hash(sov0._json_dumps(new_accounts_info))
    if not correct_hash == new_hash:
        raise ValueError("new accounts_info doesn't match expected one")
    print("expected and actual new accounts info match")


def test_txn_pre_check():
    """
    Tests for _txn_pre_check()
    """
    state_dict = _construct_state()
    state_hash = sov0._default_hash(sov0._json_dumps(state_dict)).decode()
    state_headers = {k: state_dict[k] for k in state_dict if not k == "accounts"}
    accounts_info = {}
    for acc in state_dict["accounts"]:
        accounts_info[acc["address"]] = {k: acc[k] for k in acc if not k == "address"}
        accounts_info[acc["address"]]["sendable_balance"] = acc["balance"]

    print(state_hash)
    print(sov0._json_dumps(state_headers).decode())
    print(sov0._json_dumps(accounts_info).decode())

    # info for constructing transactions
    _monkeypatch_input("nickname1")
    _monkeypatch_getpass("pwd1")
    privkey = sov0._derive_private_key()
    from_addr = "4597d2cd90c40d951a8d5def8509e7c0a63c77f3fabbdf93e858effbda623965"
    assert from_addr.encode("ascii") == privkey.verify_key.encode(
        encoder=sov0.nacl.encoding.HexEncoder
    )
    # a baseline valid transaction
    valid_txn_dict = {
        "#SoV0": 50000000,
        "from": from_addr,
        "to": "87a2e806a9d044c24f44fea9d82c118d43dac5adee68033c11c1a7bb99d91913",
        "period": 197,
        "state": state_hash,
    }
    print("0. a valid transaction, should return (True, False, txn_dict, some string)")
    original_txn_dict = valid_txn_dict
    txn = sov0._json_dumps(original_txn_dict)
    sig = sov0._sign_bytestring(sov0._default_hash(txn), privkey)
    passed_pre_check, freeze_sender, txn_dict, pre_check_info = sov0._txn_pre_check(
        txn, sig, state_hash, state_headers, accounts_info
    )
    print(passed_pre_check, freeze_sender, txn_dict, pre_check_info)
    if not (
        (passed_pre_check) and (not freeze_sender) and (txn_dict == original_txn_dict)
    ):
        raise ValueError("output doesn't match expectations")
    print("1. malformed transaction, should reutrn (False, False, None, some string)")
    original_txn_dict = {
        "#not_SoV0": 50000000,
        "from": "aae709b56ef04485764f91d2525136589191135a16cc0b9b976eb63723b90b46",
        "to": "87a2e806a9d044c24f44fea9d82c118d43dac5adee68033c11c1a7bb99d91913",
        "period": 197,
        "state": state_hash,
    }
    txn = sov0._json_dumps(original_txn_dict)
    sig = sov0._sign_bytestring(sov0._default_hash(txn), privkey)
    passed_pre_check, freeze_sender, txn_dict, pre_check_info = sov0._txn_pre_check(
        txn, sig, state_hash, state_headers, accounts_info
    )
    print(passed_pre_check, freeze_sender, txn_dict, pre_check_info)
    if not ((not passed_pre_check) and (not freeze_sender) and (txn_dict is None)):
        raise ValueError("output doesn't match expectations")
    print(
        "2. well-formed transaction with bad state hash, return should be"
        "(False, True, txn_dict, some string)"
    )
    original_txn_dict = valid_txn_dict.copy()
    original_txn_dict["state"] = "0" * 64
    txn = sov0._json_dumps(original_txn_dict)
    sig = sov0._sign_bytestring(sov0._default_hash(txn), privkey)
    passed_pre_check, freeze_sender, txn_dict, pre_check_info = sov0._txn_pre_check(
        txn, sig, state_hash, state_headers, accounts_info
    )
    print(passed_pre_check, freeze_sender, txn_dict, pre_check_info)
    if not (
        (not passed_pre_check) and (freeze_sender) and (txn_dict == original_txn_dict)
    ):
        raise ValueError("output doesn't match expectations")
    print(
        "3. well-formed transaction with a state hash that's incorrect, but also"
        "not well formatted: this should fail the format check and not result in"
        "freezing the sender"
    )
    original_txn_dict = valid_txn_dict.copy()
    original_txn_dict["state"] = state_hash[:63] + "|"
    txn = sov0._json_dumps(original_txn_dict)
    sig = sov0._sign_bytestring(sov0._default_hash(txn), privkey)
    passed_pre_check, freeze_sender, txn_dict, pre_check_info = sov0._txn_pre_check(
        txn, sig, state_hash, state_headers, accounts_info
    )
    print(passed_pre_check, freeze_sender, txn_dict, pre_check_info)
    if not ((not passed_pre_check) and (not freeze_sender) and (txn_dict is None)):
        raise ValueError("output doesn't match expectations")
    print("4. transaction with the incorrect period")
    original_txn_dict = valid_txn_dict.copy()
    original_txn_dict["period"] = 196
    txn = sov0._json_dumps(original_txn_dict)
    sig = sov0._sign_bytestring(sov0._default_hash(txn), privkey)
    passed_pre_check, freeze_sender, txn_dict, pre_check_info = sov0._txn_pre_check(
        txn, sig, state_hash, state_headers, accounts_info
    )
    print(passed_pre_check, freeze_sender, txn_dict, pre_check_info)
    if not ((not passed_pre_check) and (not freeze_sender) and (txn_dict is None)):
        raise ValueError("output doesn't match expectations")
    print("5. transaction where sender doesn't exist")
    original_txn_dict = valid_txn_dict
    tmp_accounts_info = accounts_info.copy()
    del tmp_accounts_info[from_addr]
    txn = sov0._json_dumps(original_txn_dict)
    sig = sov0._sign_bytestring(sov0._default_hash(txn), privkey)
    passed_pre_check, freeze_sender, txn_dict, pre_check_info = sov0._txn_pre_check(
        txn, sig, state_hash, state_headers, tmp_accounts_info
    )
    print(passed_pre_check, freeze_sender, txn_dict, pre_check_info)
    if not ((not passed_pre_check) and (not freeze_sender) and (txn_dict is None)):
        raise ValueError("output doesn't match expectations")


def test_apply_txn_to_state():
    """
    Tests for _apply_txn_to_state()
    """
    state_dict = _construct_state()
    original_accounts_info = {}
    for acc in state_dict["accounts"]:
        original_accounts_info[acc["address"]] = {
            k: acc[k] for k in acc if not k == "address"
        }
        original_accounts_info[acc["address"]]["sendable_balance"] = acc["balance"]
    # set sendable balance for a couple accounts to less than its balance, as if
    #  a txn has occurred
    addr3 = "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71"
    addr5 = "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6"
    original_accounts_info[addr3]["balance"] -= 10000000
    original_accounts_info[addr3]["sendable_balance"] -= 10000000
    original_accounts_info[addr5]["balance"] += 10000000
    print(sov0._json_dumps(original_accounts_info).decode())

    # a baseline transaction
    to_addr = "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0"
    base_txn_dict = {
        "#SoV0": 10000000,
        "from": addr3,
        "to": to_addr,
        "period": 197,
        "state": "state_hash_is_not_checked_in_this_test",
    }
    print("0. apply the baseline transaction, creates a new account")
    accounts_info = copy.deepcopy(original_accounts_info)
    txn_dict = base_txn_dict
    txn_applied, txn_apply_info = sov0._apply_txn_to_state(txn_dict, accounts_info)
    print(txn_applied, txn_apply_info)
    correct_post_accounts_info = copy.deepcopy(original_accounts_info)
    correct_post_accounts_info[addr3]["balance"] -= base_txn_dict["#SoV0"]
    correct_post_accounts_info[addr3]["sendable_balance"] -= base_txn_dict["#SoV0"]
    correct_post_accounts_info[to_addr] = {
        "balance": base_txn_dict["#SoV0"],
        "temporary_freeze_pds": 0,
        "frozen_until_valid_block": False,
        "sendable_balance": 0,
    }
    if not (
        txn_applied
        and (
            sov0._default_hash(sov0._json_dumps(accounts_info))
            == sov0._default_hash(sov0._json_dumps(correct_post_accounts_info))
        )
    ):
        raise ValueError("accounts_info after applying txn doesn't look right")
    print("1. apply a different valid transaction where receiver exists")
    accounts_info = copy.deepcopy(original_accounts_info)
    txn_dict = base_txn_dict.copy()
    txn_dict["to"] = "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115"
    txn_applied, txn_apply_info = sov0._apply_txn_to_state(txn_dict, accounts_info)
    print(txn_applied, txn_apply_info)
    correct_post_accounts_info = copy.deepcopy(original_accounts_info)
    correct_post_accounts_info[addr3]["balance"] -= base_txn_dict["#SoV0"]
    correct_post_accounts_info[addr3]["sendable_balance"] -= base_txn_dict["#SoV0"]
    correct_post_accounts_info[txn_dict["to"]]["balance"] += base_txn_dict["#SoV0"]
    if not (
        txn_applied
        and (
            sov0._default_hash(sov0._json_dumps(accounts_info))
            == sov0._default_hash(sov0._json_dumps(correct_post_accounts_info))
        )
    ):
        raise ValueError("accounts_info after applying txn doesn't look right")
    print("2. invalid transaction where the sender is frozen until a valid block")
    accounts_info = copy.deepcopy(original_accounts_info)
    txn_dict = base_txn_dict.copy()
    from_addr = "9a656ea050ef7f478d5c482701c10d46961fb511cf781be5af63a2f9a7251aae"
    txn_dict["from"] = from_addr
    txn_applied, txn_apply_info = sov0._apply_txn_to_state(txn_dict, accounts_info)
    print(txn_applied, txn_apply_info)
    if not (
        (not txn_applied)
        and (
            sov0._default_hash(sov0._json_dumps(accounts_info))
            == sov0._default_hash(sov0._json_dumps(original_accounts_info))
        )
    ):
        raise ValueError("txn seems to have been applied despite sender frozen.")
    print("3. invalid transaction where the sender is frozen temporarily")
    accounts_info = copy.deepcopy(original_accounts_info)
    txn_dict = base_txn_dict.copy()
    from_addr = "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115"
    txn_dict["from"] = from_addr
    txn_applied, txn_apply_info = sov0._apply_txn_to_state(txn_dict, accounts_info)
    print(txn_applied, txn_apply_info)
    if not (
        (not txn_applied)
        and (
            sov0._default_hash(sov0._json_dumps(accounts_info))
            == sov0._default_hash(sov0._json_dumps(original_accounts_info))
        )
    ):
        raise ValueError("txn seems to have been applied despite sender frozen.")
    print("4. invalid transaction where the sender has insufficient sendable balance")
    accounts_info = copy.deepcopy(original_accounts_info)
    txn_dict = base_txn_dict.copy()
    txn_dict["#SoV0"] = 91000000
    txn_applied, txn_apply_info = sov0._apply_txn_to_state(txn_dict, accounts_info)
    print(txn_applied, txn_apply_info)
    if not (
        (not txn_applied)
        and (
            sov0._default_hash(sov0._json_dumps(accounts_info))
            == sov0._default_hash(sov0._json_dumps(original_accounts_info))
        )
    ):
        raise ValueError(
            "txn seems to have been applied despite insufficient" "sendable balance"
        )


def test_produce_block_from_txn_sigs(clean=True):
    """
    Tests for _produce_block_from_txn_sigs()
    """
    test_dir = "test_output/block_production"
    if clean:
        _remove_and_recreate_dir(test_dir)
    # the state we'll use
    state_dict = _construct_state()
    state_file = os.path.join(test_dir, "state_period197.txt")
    with open(state_file, "wb") as f:
        f.write(sov0._json_dumps(state_dict))
    time.sleep(0.01)
    _, state_hash = sov0._load_and_hash(state_file)

    print("0. no transactions, block should be an empty list")
    txn_sigs_list = []
    block_file = os.path.join(test_dir, "block0.txt")
    sov0._produce_block_from_txn_sigs(txn_sigs_list, state_file, block_file)
    time.sleep(0.01)
    with open(block_file, "rb") as f:
        block_loaded = sov0._json_load(f.read())
    if not ((type(block_loaded) is list) and len(block_loaded) == 0):
        raise ValueError("should have loaded an empty block")
    print("1. all transactions here are invalid. block should be an empty list")
    # not enough sendable balance
    txn0_dict = {
        "#SoV0": 1000000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0",
        "period": 197,
        "state": state_hash,
    }
    txn0 = sov0._json_dumps(txn0_dict)
    sig0 = _sign_bytestring_pubkey(sov0._default_hash(txn0), txn0_dict["from"])
    # sender is frozen
    txn1_dict = {
        "#SoV0": 10000000,
        "from": "9a656ea050ef7f478d5c482701c10d46961fb511cf781be5af63a2f9a7251aae",
        "to": "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0",
        "period": 197,
        "state": state_hash,
    }
    txn1 = sov0._json_dumps(txn1_dict)
    sig1 = _sign_bytestring_pubkey(sov0._default_hash(txn1), txn1_dict["from"])
    # signature is invalid
    txn2_dict = {
        "#SoV0": 10000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0",
        "period": 197,
        "state": state_hash,
    }
    txn2 = sov0._json_dumps(txn2_dict)
    sig2 = b"this is not a valid signature"
    # transaction is improperly formatted
    txn3_dict = {
        "#SoV0": 10000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "BAD_FIELD": "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0",
        "period": 197,
        "state": state_hash,
    }
    txn3 = sov0._json_dumps(txn3_dict)
    sig3 = _sign_bytestring_pubkey(sov0._default_hash(txn3), txn3_dict["from"])
    # ok, construct the block
    txn_sigs_list = [(txn0, sig0), (txn1, sig1), (txn2, sig2), (txn3, sig3)]
    block_file = os.path.join(test_dir, "block1.txt")
    sov0._produce_block_from_txn_sigs(txn_sigs_list, state_file, block_file)
    time.sleep(0.01)
    with open(block_file, "rb") as f:
        block_loaded = sov0._json_load(f.read())
    if not ((type(block_loaded) is list) and len(block_loaded) == 0):
        raise ValueError("should have loaded an empty block")
    print("2. add a valid transaction,  block should just be this transaction")
    txn4_dict = {
        "#SoV0": 1000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0",
        "period": 197,
        "state": state_hash,
    }
    txn4 = sov0._json_dumps(txn4_dict)
    sig4 = _sign_bytestring_pubkey(sov0._default_hash(txn4), txn4_dict["from"])
    txn_sigs_list.append((txn4, sig4))
    block_file = os.path.join(test_dir, "block2.txt")
    sov0._produce_block_from_txn_sigs(txn_sigs_list, state_file, block_file)
    time.sleep(0.01)
    # correct block should just be this
    correct_block = [{"txn": sov0._json_load(txn4), "sig": sig4.decode("ascii")}]
    correct_block_hash = sov0._default_hash(sov0._json_dumps(correct_block)).decode()
    _, block_hash = sov0._load_and_hash(block_file)
    if not block_hash == correct_block_hash:
        raise ValueError("block hash doesn't match expectations")
    print("3. duplicate transaction, should be ignored")
    txn_sigs_list.append((txn4, sig4))
    block_file = os.path.join(test_dir, "block3.txt")
    sov0._produce_block_from_txn_sigs(txn_sigs_list, state_file, block_file)
    time.sleep(0.01)
    # correct block should just be this
    correct_block = [{"txn": sov0._json_load(txn4), "sig": sig4.decode("ascii")}]
    correct_block_hash = sov0._default_hash(sov0._json_dumps(correct_block)).decode()
    _, block_hash = sov0._load_and_hash(block_file)
    if not block_hash == correct_block_hash:
        raise ValueError("block hash doesn't match expectations")
    print("4. add a transaction with an incorrect block hash")
    txn5_dict = {
        "#SoV0": 1000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "c9f5c1c25be0982a1c148cc07160f0a6dc533c1c8d619ffb118459876e5235e0",
        "period": 197,
        "state": "0" * 64,
    }
    txn5 = sov0._json_dumps(txn5_dict)
    sig5 = _sign_bytestring_pubkey(sov0._default_hash(txn5), txn5_dict["from"])
    txn_sigs_list.append((txn5, sig5))
    block_file = os.path.join(test_dir, "block4.txt")
    sov0._produce_block_from_txn_sigs(txn_sigs_list, state_file, block_file)
    time.sleep(0.01)
    # this should lead to the sender being frozen, so that txn4 will be removed,
    #  and the block will just be txn5
    correct_block = [{"txn": sov0._json_load(txn5), "sig": sig5.decode("ascii")}]
    correct_block_hash = sov0._default_hash(sov0._json_dumps(correct_block)).decode()
    _, block_hash = sov0._load_and_hash(block_file)
    if not block_hash == correct_block_hash:
        raise ValueError("block hash doesn't match expectations")
    print("5. another txn with invalid state from the same sender => block same as 4")
    txn6_dict = {
        "#SoV0": 100000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
        "period": 197,
        "state": "1" * 64,
    }
    txn6 = sov0._json_dumps(txn6_dict)
    sig6 = _sign_bytestring_pubkey(sov0._default_hash(txn6), txn6_dict["from"])
    txn_sigs_list.append((txn6, sig6))
    block_file = os.path.join(test_dir, "block5.txt")
    sov0._produce_block_from_txn_sigs(txn_sigs_list, state_file, block_file)
    time.sleep(0.01)
    correct_block = [{"txn": sov0._json_load(txn5), "sig": sig5.decode("ascii")}]
    correct_block_hash = sov0._default_hash(sov0._json_dumps(correct_block)).decode()
    _, block_hash = sov0._load_and_hash(block_file)
    if not block_hash == correct_block_hash:
        raise ValueError("block hash doesn't match expectations")


def test_state_update_proposal(clean=True):
    """
    Tests for check_block_proposal() and _produce_state_update_proposal()
    """
    test_dir = "test_output/state_update_proposal"
    if clean:
        _remove_and_recreate_dir(test_dir)
    # the state we'll use
    state_dict = _construct_state()
    state_file = os.path.join(test_dir, "state_period197.txt")
    with open(state_file, "wb") as f:
        f.write(sov0._json_dumps(state_dict))
    # store the block producer id for further use
    block_producer_id = _get_id_of_address(state_dict["block_producer"])
    print("block producer is account #:", block_producer_id)
    # a block to use, with a single bad state hash transaction
    txn_dict = {
        "#SoV0": 10000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "87a2e806a9d044c24f44fea9d82c118d43dac5adee68033c11c1a7bb99d91913",
        "period": 197,
        "state": "0" * 64,
    }
    txn_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn_dict)), txn_dict["from"]
    )
    block = [{"txn": txn_dict, "sig": txn_sig.decode("ascii")}]
    block_file = os.path.join(test_dir, "block0.txt")
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    # construct the new state
    new_state_file = os.path.join(test_dir, "state_period198.txt")
    sov0.update_state_with_block(
        state_file=state_file, block_file=block_file, new_state_file=new_state_file
    )
    new_state_hash, new_state_headers, _ = sov0._load_parse_state(new_state_file)
    curr_state_hash = new_state_headers["prev_state"]
    block_hash = new_state_headers["prev_block"]
    # construct state update proposal
    _monkeypatch_input("nickname{}".format(block_producer_id))
    _monkeypatch_getpass("pwd{}".format(block_producer_id))
    proposal_file = os.path.join(test_dir, "proposal0.txt")
    sig_file = os.path.join(test_dir, "sig0.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test0.txt")
    sov0._produce_state_update_proposal(
        block_file, new_state_file, proposal_file, sig_file
    )
    time.sleep(0.01)
    # check the proposal, should be valid
    print("0. a correct proposal")
    log_file = os.path.join(test_dir, "state_update_period198_test0.txt")
    sov0.check_state_update_proposal(
        proposal_file, sig_file, state_file, block_file, new_state_file_test, log_file
    )
    print("check passed")
    print("1. incorrect block file")
    proposal_file = os.path.join(test_dir, "proposal0.txt")
    sig_file = os.path.join(test_dir, "sig0.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test2.txt")
    bad_block_file = state_file
    new_state_file_test = os.path.join(test_dir, "state_period198_test1.txt")
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, bad_block_file, new_state_file_test
        ),
        ValueError,
        "block file doesn't match block hash in proposal",
    )
    print("2. signature has a bad field")
    proposal_file = os.path.join(test_dir, "proposal0.txt")
    sig_file = os.path.join(test_dir, "sig2.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test2.txt")
    with open(os.path.join(test_dir, "sig0.txt"), "rb") as f:
        correct_sig_dict = sov0._json_load(f.read())
    malformed_sig_dict = {"bad_sig_field": correct_sig_dict["proposal_sig"]}
    with open(sig_file, "wb") as f:
        f.write(sov0._json_dumps(malformed_sig_dict))
    time.sleep(0.01)
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        ValueError,
        "signature file misformatted, field must be",
    )
    print("3. signature itself is bad")
    proposal_file = os.path.join(test_dir, "proposal0.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test3.txt")
    sig_file = os.path.join(test_dir, "sig3.txt")
    sig_dict = {"proposal_sig": "this is not a valid signature."}
    with open(sig_file, "wb") as f:
        f.write(sov0._json_dumps(sig_dict))
    time.sleep(0.01)
    import binascii

    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        binascii.Error,
        "",
    )
    print("4. signature signed by not the block producer")
    new_state_file_test = os.path.join(test_dir, "state_period198_test4.txt")
    proposal_file = os.path.join(test_dir, "proposal0.txt")
    _, proposal_hash = sov0._load_and_hash(proposal_file)
    sig_dict = {
        "proposal_sig": _sign_bytestring_pubkey(
            proposal_hash.encode("ascii"),
            "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
        ).decode("ascii")
    }
    sig_file = os.path.join(test_dir, "sig4.txt")
    with open(sig_file, "wb") as f:
        f.write(sov0._json_dumps(sig_dict))
    time.sleep(0.01)
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        sov0.nacl.exceptions.BadSignatureError,
        "Signature was forged or corrupt",
    )
    print("5. proposal has weird fields")
    proposal_file = os.path.join(test_dir, "proposal5.txt")
    sig_file = os.path.join(test_dir, "sig5.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test5.txt")
    proposal_dict = {
        "#SoV0_new_period": 198,
        "new_state": new_state_hash,
        "block": block_hash,
        "current_state": curr_state_hash,
        "extraneous_field": "this field should not be here",
    }
    sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(proposal_dict)),
        state_dict["block_producer"],
    )
    with open(proposal_file, "wb") as f:
        f.write(sov0._json_dumps(proposal_dict))
    with open(sig_file, "wb") as f:
        f.write(sov0._json_dumps({"sig": sig.decode("ascii")}))
    time.sleep(0.01)
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        ValueError,
        "proposal file improperly formatted",
    )
    print("6. proposal is for the wrong period")
    proposal_file = os.path.join(test_dir, "proposal6.txt")
    sig_file = os.path.join(test_dir, "sig6.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test6.txt")
    proposal_dict = {
        "#SoV0_new_period": 300,
        "new_state": new_state_hash,
        "block": block_hash,
        "current_state": curr_state_hash,
    }
    sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(proposal_dict)),
        state_dict["block_producer"],
    )
    with open(proposal_file, "wb") as f:
        f.write(sov0._json_dumps(proposal_dict))
    with open(sig_file, "wb") as f:
        f.write(sov0._json_dumps({"sig": sig.decode("ascii")}))
    time.sleep(0.01)
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        ValueError,
        "proposal period doesn't match",
    )
    print("7. proposal block hash is not valid")
    proposal_file = os.path.join(test_dir, "proposal7.txt")
    sig_file = os.path.join(test_dir, "sig7.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test7.txt")
    proposal_dict = {
        "#SoV0_new_period": 198,
        "new_state": new_state_hash,
        "block": "this is not a valid block hash",
        "current_state": curr_state_hash,
    }
    sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(proposal_dict)),
        state_dict["block_producer"],
    )
    with open(proposal_file, "wb") as f:
        f.write(sov0._json_dumps(proposal_dict))
    with open(sig_file, "wb") as f:
        f.write(sov0._json_dumps({"sig": sig.decode("ascii")}))
    time.sleep(0.01)
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        ValueError,
        "proposal field 'block' is not a 64-length hex string",
    )
    print("8. proposal signature is for a different proposal")
    proposal_file = os.path.join(test_dir, "proposal0.txt")
    sig_file = os.path.join(test_dir, "sig8.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test8.txt")
    wrong_proposal_hash = sov0._default_hash(b"")
    sig = _sign_bytestring_pubkey(wrong_proposal_hash, state_dict["block_producer"])
    with open(sig_file, "wb") as f:
        f.write(sov0._json_dumps({"proposal_sig": sig.decode("ascii")}))
    time.sleep(0.01)
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        ValueError,
        "The message doesn't match the signature",
    )
    print("9. proposal is fine, but block has some issues")
    block_file = os.path.join(test_dir, "block9.txt")
    proposal_file = os.path.join(test_dir, "proposal9.txt")
    sig_file = os.path.join(test_dir, "sig9.txt")
    new_state_file_test = os.path.join(test_dir, "state_period198_test9.txt")
    log_file = os.path.join(test_dir, "state_update_period198_test9.txt")
    # block is just one malformed transaction
    txn_dict = {
        "#SoV0": "this is not a valid amount of sov0 to send",
        "from": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
        "to": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
        "period": 197,
        "state": "0" * 64,
    }
    txn_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn_dict)),
        txn_dict["from"],
    )
    block = [{"txn": txn_dict, "sig": txn_sig.decode("ascii")}]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    _, block_hash = sov0._load_and_hash(block_file)
    # construct state update proposal
    _monkeypatch_input("nickname{}".format(block_producer_id))
    _monkeypatch_getpass("pwd{}".format(block_producer_id))
    sov0._produce_state_update_proposal(
        block_file, new_state_file, proposal_file, sig_file
    )
    time.sleep(0.01)
    _check_error_prefix(
        lambda: sov0.check_state_update_proposal(
            proposal_file, sig_file, state_file, block_file, new_state_file_test
        ),
        ValueError,
        "STATE UPDATE FAILED: bad block",
    )


def test_update_state(clean=True):
    """
    Tests for update_state_with_block() and update_state_without_block()
    """
    test_dir = "test_output/update_state"
    if clean:
        _remove_and_recreate_dir(test_dir)

    # state for use here
    old_state_dict = _construct_state()
    old_state_file = os.path.join(test_dir, "state_old.txt")
    with open(old_state_file, "wb") as f:
        f.write(sov0._json_dumps(old_state_dict))
    _, old_state_hash = sov0._load_and_hash(old_state_file)
    print("0. block is empty: invalid, no new state file should be produced")
    block_file = os.path.join(test_dir, "block0.txt")
    new_state_file = os.path.join(test_dir, "state_new0.txt")
    block = []
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[4]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad "
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("1. block is malformed: invalid, no new state file should be produced")
    block_file = os.path.join(test_dir, "block1.txt")
    new_state_file = os.path.join(test_dir, "state_new1.txt")
    block = {"this is not a": "valid block"}
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[2]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("2. valid block, a single good transaction")
    block_file = os.path.join(test_dir, "block2.txt")
    new_state_file = os.path.join(test_dir, "state_new2.txt")
    txn0_dict = {
        "#SoV0": 5000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
        "period": 197,
        "state": old_state_hash,
    }
    txn0_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn0_dict)),
        txn0_dict["from"],
    )
    block = [{"txn": txn0_dict, "sig": txn0_sig.decode("ascii")}]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    # compare it to the hardcoded hash for a state file we manually checked
    _, block_hash = sov0._load_and_hash(block_file)
    _, new_state_hash = sov0._load_and_hash(new_state_file)
    print(old_state_hash, block_hash, new_state_hash, sep="\n")
    expected_update_status = sov0._state_update_statuses[0]
    if not update_status == expected_update_status:
        raise ValueError(
            "update status should be '{}', is actually "
            "'{}'".format(expected_update_status, update_status)
        )
    if not (
        new_state_hash
        == "3635d6bb5588e92599cc58e9a8b5505d078bddf91d252f0d5705675cf2b76908"
    ):
        raise ValueError("newly created state file doesn't match expectations")
    print("state update successful, matches expected hash")
    print("3. invalid block, the above transaction is duplicated")
    block_file = os.path.join(test_dir, "block3.txt")
    new_state_file = os.path.join(test_dir, "state_new3.txt")
    block = [
        {"txn": txn0_dict, "sig": txn0_sig.decode("ascii")},
        {"txn": txn0_dict, "sig": txn0_sig.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[3]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("4. invalid block, malformed transaction")
    block_file = os.path.join(test_dir, "block4.txt")
    new_state_file = os.path.join(test_dir, "state_new4.txt")
    txn1_dict = {
        "#SoV0": -1000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
        "period": 197,
        "state": old_state_hash,
    }
    txn1_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn1_dict)),
        txn1_dict["from"],
    )
    block = [
        {"txn": txn1_dict, "sig": txn1_sig.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[6]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state updated when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("5. invalid block, bad signature transaction")
    block_file = os.path.join(test_dir, "block5.txt")
    new_state_file = os.path.join(test_dir, "state_new5.txt")
    txn0_sig_bad = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn0_dict)),
        txn0_dict["to"],
    )
    block = [
        {"txn": txn0_dict, "sig": txn0_sig_bad.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[6]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("6. multiple invalid state hash transactions from a single sender")
    block_file = os.path.join(test_dir, "block6.txt")
    new_state_file = os.path.join(test_dir, "state_new6.txt")
    txn2_dict = {
        "#SoV0": 1000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
        "period": 197,
        "state": "0" * 64,
    }
    txn2_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn2_dict)),
        txn2_dict["from"],
    )
    txn3_dict = {
        "#SoV0": 2000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
        "period": 197,
        "state": "1" * 64,
    }
    txn3_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn3_dict)),
        txn3_dict["from"],
    )
    block = [
        {"txn": txn2_dict, "sig": txn2_sig.decode("ascii")},
        {"txn": txn3_dict, "sig": txn3_sig.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[5]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("7. a valid transaction from someone who also a txn with a bad state hash")
    block_file = os.path.join(test_dir, "block7.txt")
    new_state_file = os.path.join(test_dir, "state_new7.txt")
    txn4_dict = {
        "#SoV0": 1000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
        "period": 197,
        "state": old_state_hash,
    }
    txn4_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn4_dict)),
        txn4_dict["from"],
    )
    block = [
        {"txn": txn4_dict, "sig": txn4_sig.decode("ascii")},
        {"txn": txn3_dict, "sig": txn3_sig.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[7]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("8. total sends for a sender exceeds what they had at end of previous period")
    block_file = os.path.join(test_dir, "block8.txt")
    new_state_file = os.path.join(test_dir, "state_new8.txt")
    txn5_dict = {
        "#SoV0": 80000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
        "period": 197,
        "state": old_state_hash,
    }
    txn5_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn5_dict)),
        txn5_dict["from"],
    )
    txn6_dict = {
        "#SoV0": 40000000,
        "from": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
        "to": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
        "period": 197,
        "state": old_state_hash,
    }
    txn6_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn6_dict)),
        txn6_dict["from"],
    )
    block = [
        {"txn": txn4_dict, "sig": txn4_sig.decode("ascii")},
        {"txn": txn5_dict, "sig": txn5_sig.decode("ascii")},
        {"txn": txn6_dict, "sig": txn6_sig.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[7]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("9. transaction from a frozen user => block invalid")
    block_file = os.path.join(test_dir, "block9.txt")
    new_state_file = os.path.join(test_dir, "state_new9.txt")
    txn7_dict = {
        "#SoV0": 1000000,
        "from": "9a656ea050ef7f478d5c482701c10d46961fb511cf781be5af63a2f9a7251aae",
        "to": "53e03ce9a19f4311e1ade8885980ca1cb0475aaf9bcde859df64d91a60517cbb",
        "period": 197,
        "state": old_state_hash,
    }
    txn7_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn7_dict)),
        txn7_dict["from"],
    )
    block = [
        {"txn": txn4_dict, "sig": txn4_sig.decode("ascii")},
        {"txn": txn6_dict, "sig": txn6_sig.decode("ascii")},
        {"txn": txn7_dict, "sig": txn7_sig.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[7]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("10. transaction from another frozen user => block invalid")
    block_file = os.path.join(test_dir, "block10.txt")
    new_state_file = os.path.join(test_dir, "state_new10.txt")
    txn8_dict = {
        "#SoV0": 1000000,
        "from": "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115",
        "to": "53e03ce9a19f4311e1ade8885980ca1cb0475aaf9bcde859df64d91a60517cbb",
        "period": 197,
        "state": old_state_hash,
    }
    txn8_sig = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(txn8_dict)),
        txn8_dict["from"],
    )
    block = [
        {"txn": txn4_dict, "sig": txn4_sig.decode("ascii")},
        {"txn": txn6_dict, "sig": txn6_sig.decode("ascii")},
        {"txn": txn8_dict, "sig": txn8_sig.decode("ascii")},
    ]
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_with_block(
        old_state_file, block_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    expected_update_status = sov0._state_update_statuses[7]
    if os.path.exists(new_state_file) or update_status != expected_update_status:
        raise ValueError(
            "either state update when it shouldn't have, or update status is bad"
            "should be: {}, is actually {}".format(
                expected_update_status, update_status
            )
        )
    else:
        print("new state file not created & update status is as expected")
    print("11. updating without a block")
    block_file = os.path.join(test_dir, "block11.txt")
    new_state_file = os.path.join(test_dir, "state_new11.txt")
    with open(block_file, "wb") as f:
        f.write(sov0._json_dumps(block))
    time.sleep(0.01)
    update_status = sov0.update_state_without_block(
        old_state_file, new_state_file, "_console"
    )
    time.sleep(0.01)
    # compare it to the hardcoded hash for a state file we manually checked
    _, new_state_hash = sov0._load_and_hash(new_state_file)
    print(old_state_hash, new_state_hash, sep="\n")
    expected_update_status = sov0._state_update_statuses[1]
    if not update_status == expected_update_status:
        raise ValueError(
            "update status should be '{}', is actually '{}'".format(
                expected_update_status, update_status
            )
        )
    if not (
        new_state_hash
        == "45fadc999f3c133145162c45ade1034257f44678a50085dd803b3e309ad4d092"
    ):
        raise ValueError("Newly created state file doesn't match expectations")
    print("new state file created & matches expected hash")


def test_block_producer_removal_petition(clean=True):
    """
    Tests for petition_to_remove_block_producer() and
        _check_block_producer_removal_petititon()
    """
    test_dir = "test_output/block_producer_removal_petition"
    if clean:
        _remove_and_recreate_dir(test_dir)
    print("0. a valid petition")
    i = 0
    signer = 3
    period = 197
    petition_file = os.path.join(test_dir, "petition{}.txt".format(i))
    sig_file = os.path.join(test_dir, "sig{}.txt".format(i))
    _monkeypatch_input("nickname{}".format(signer))
    _monkeypatch_getpass("pwd{}".format(signer))
    sov0.petition_to_remove_block_producer(period, petition_file, sig_file)
    time.sleep(0.01)
    with open(petition_file, "rb") as f:
        petition_dict = sov0._json_load(f.read())
    with open(sig_file, "rb") as f:
        sig_str = sov0._json_load(f.read())["removal_sig"]
    sov0._check_block_producer_removal_petititon(petition_dict, sig_str, 197)
    print("checks out")
    print("1. a petition with a bad period")
    i = 1
    signer = 3
    period = -50
    petition_file = os.path.join(test_dir, "petition{}.txt".format(i))
    sig_file = os.path.join(test_dir, "sig{}.txt".format(i))
    _monkeypatch_input("nickname{}".format(signer))
    _monkeypatch_getpass("pwd{}".format(signer))
    _check_error_prefix(
        lambda: sov0.petition_to_remove_block_producer(period, petition_file, sig_file),
        ValueError,
        "petition period invalid or doesn't match input period",
    )
    print("2. petition has invalid sender, fails")
    petition_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "this is not a valid sender",
    }
    petition_canonical_hash = sov0._default_hash(sov0._json_dumps(petition_dict))
    _monkeypatch_input("nickname{}".format(signer))
    _monkeypatch_getpass("pwd{}".format(signer))
    sig_str = sov0._sign_bytestring(
        petition_canonical_hash, sov0._derive_private_key()
    ).decode("ascii")
    _check_error_prefix(
        lambda: sov0._check_block_producer_removal_petititon(
            petition_dict, sig_str, 197
        ),
        ValueError,
        "sender address is invalid",
    )
    print("3. petition has bad fields, fails")
    petition_dict = {
        "#SoV0_remove_block_producer": True,
        "misspelled_field": 197,
        "sender": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
    }
    petition_canonical_hash = sov0._default_hash(sov0._json_dumps(petition_dict))
    sig_str = _sign_bytestring_pubkey(
        petition_canonical_hash, petition_dict["sender"]
    ).decode("ascii")
    _check_error_prefix(
        lambda: sov0._check_block_producer_removal_petititon(
            petition_dict, sig_str, 197
        ),
        ValueError,
        "petition has incorrect fields",
    )
    print("4. petition isn't signed by the sender, invalid")
    petition_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
    }
    petition_canonical_hash = sov0._default_hash(sov0._json_dumps(petition_dict))
    bad_signer = "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca"
    sig_str = _sign_bytestring_pubkey(petition_canonical_hash, bad_signer).decode(
        "ascii"
    )
    _check_error_prefix(
        lambda: sov0._check_block_producer_removal_petititon(
            petition_dict, sig_str, 197
        ),
        sov0.nacl.exceptions.BadSignatureError,
        "Signature was forged or corrupt",
    )
    print("5. correct sender, but signed the wrong thing, invalid")
    petition_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
    }
    sig_str = _sign_bytestring_pubkey(
        b"this is not the hash of the petition dict", petition_dict["sender"]
    ).decode("ascii")
    _check_error_prefix(
        lambda: sov0._check_block_producer_removal_petititon(
            petition_dict, sig_str, 197
        ),
        ValueError,
        "The message doesn't match the signature",
    )
    print("6. the #SoV0_remove_block_producer field is not a bool")
    petition_dict = {
        "#SoV0_remove_block_producer": "this is not a bool value",
        "period": 197,
        "sender": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
    }
    sig_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition_dict)), petition_dict["sender"]
    ).decode("ascii")
    _check_error_prefix(
        lambda: sov0._check_block_producer_removal_petititon(
            petition_dict, sig_str, 197
        ),
        ValueError,
        "#SoV0_remove_block_producer is not a bool",
    )
    print("7. the #SoV0_remove_block_producer field is False, invalid")
    petition_dict = {
        "#SoV0_remove_block_producer": False,
        "period": 197,
        "sender": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
    }
    sig_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition_dict)), petition_dict["sender"]
    ).decode("ascii")
    _check_error_prefix(
        lambda: sov0._check_block_producer_removal_petititon(
            petition_dict, sig_str, 197
        ),
        ValueError,
        "this sender doesn't want to remove block producer",
    )
    print("8. period is wrong, invalid")
    petition_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 195,
        "sender": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
    }
    sig_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition_dict)), petition_dict["sender"]
    ).decode("ascii")
    _check_error_prefix(
        lambda: sov0._check_block_producer_removal_petititon(
            petition_dict, sig_str, 197
        ),
        ValueError,
        "petition period invalid or doesn't match input period",
    )


def test_block_producer_removal_majority(clean=True):
    """
    Tests for check_block_producer_removal_majority
    """
    test_dir = "test_output/check_block_producer_removal_majority"
    if clean:
        _remove_and_recreate_dir(test_dir)
    # the state we'll use
    state_dict = _construct_state()
    state_file = os.path.join(test_dir, "state.txt")
    with open(state_file, "wb") as f:
        f.write(sov0._json_dumps(state_dict))
    print("0. petitions accounting for > 1/2 of balance, passes")
    petitions_sigs_file = os.path.join(test_dir, "petitions_sigs0.txt")
    petition0_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "4597d2cd90c40d951a8d5def8509e7c0a63c77f3fabbdf93e858effbda623965",
    }
    sig0_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition0_dict)),
        petition0_dict["sender"],
    ).decode("ascii")
    petition1_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "7db209c27cf388febe0d6d8abb40c5fd9e33bd365543b1c0cf6077c5e32c3115",
    }
    sig1_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition1_dict)),
        petition1_dict["sender"],
    ).decode("ascii")
    petition2_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "d0d66889b5e1f2aa5b29255cac22bc5b7bc0aa2370ef03f3f9e358e69e550f71",
    }
    sig2_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition2_dict)),
        petition2_dict["sender"],
    ).decode("ascii")
    petition3_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "417b76c71ccf58560e36ef8249ab5e67737bc780a38616e1149766c26fa70cca",
    }
    sig3_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition3_dict)),
        petition3_dict["sender"],
    ).decode("ascii")
    petitions_sigs_list = [
        (petition0_dict, sig0_str),
        (petition1_dict, sig1_str),
        (petition2_dict, sig2_str),
        (petition3_dict, sig3_str),
    ]
    with open(petitions_sigs_file, "wb") as f:
        f.write(sov0._json_dumps(petitions_sigs_list))
    time.sleep(0.01)
    removal_is_majority = sov0.check_block_producer_removal_majority(
        petitions_sigs_file, state_file
    )
    if not removal_is_majority:
        raise ValueError("more than half of wealth should be pro removal")
    print("petition passes, as expected")
    print(
        "1. petition includes one of the petitions multiple times, just barely"
        "not enough to pass"
    )
    petitions_sigs_file = os.path.join(test_dir, "petitions_sigs1.txt")
    petitions_sigs_list = [
        (petition0_dict, sig0_str),
        (petition1_dict, sig1_str),
        (petition2_dict, sig2_str),
        (petition2_dict, sig2_str),
    ]
    with open(petitions_sigs_file, "wb") as f:
        f.write(sov0._json_dumps(petitions_sigs_list))
    time.sleep(0.01)
    removal_is_majority = sov0.check_block_producer_removal_majority(
        petitions_sigs_file, state_file
    )
    if removal_is_majority:
        raise ValueError("not more than half of wealth should be pro removal")
    print("petition not passed, as expected")
    print("2. petition includes someone with no balance, still doesn't pass")
    petitions_sigs_file = os.path.join(test_dir, "petitions_sigs2.txt")
    petition4_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 197,
        "sender": "7cc0c50c872ff38e0830be69919117d92dc89f073a35662105b179d0d580e7d9",
    }
    sig4_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition4_dict)),
        petition4_dict["sender"],
    ).decode("ascii")
    petitions_sigs_list = [
        (petition0_dict, sig0_str),
        (petition1_dict, sig1_str),
        (petition2_dict, sig2_str),
        (petition4_dict, sig4_str),
    ]
    with open(petitions_sigs_file, "wb") as f:
        f.write(sov0._json_dumps(petitions_sigs_list))
    time.sleep(0.01)
    removal_is_majority = sov0.check_block_producer_removal_majority(
        petitions_sigs_file, state_file
    )
    if removal_is_majority:
        raise ValueError("not more than half of wealth should be pro removal")
    print("petition not passed, as expected")
    print("3. one of the petitions is malformed (wrong period), still doesn't pass")
    petitions_sigs_file = os.path.join(test_dir, "petitions_sigs3.txt")
    petition5_dict = {
        "#SoV0_remove_block_producer": True,
        "period": 196,
        "sender": "f7410586f3d51335e84334f5ad1ba053e8ca62220c2418d66e16cd9664f867d6",
    }
    sig5_str = _sign_bytestring_pubkey(
        sov0._default_hash(sov0._json_dumps(petition5_dict)),
        petition5_dict["sender"],
    ).decode("ascii")
    petitions_sigs_list = [
        (petition0_dict, sig0_str),
        (petition1_dict, sig1_str),
        (petition2_dict, sig2_str),
        (petition5_dict, sig5_str),
    ]
    with open(petitions_sigs_file, "wb") as f:
        f.write(sov0._json_dumps(petitions_sigs_list))
    time.sleep(0.01)
    removal_is_majority = sov0.check_block_producer_removal_majority(
        petitions_sigs_file, state_file
    )
    if removal_is_majority:
        raise ValueError("not more than half of wealth should be pro removal")
    print("petition not passed, as expected")
