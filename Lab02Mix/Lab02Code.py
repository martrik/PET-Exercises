#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.

###########################
# Group Members: Marti Serra
###########################


from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from binascii import hexlify
from os import urandom

def aes_ctr_enc_dec(key, iv, input):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption.
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in
    fact the same operations.
    """

    aes = Cipher("AES-128-CTR")

    enc = aes.enc(key, iv)
    output = enc.update(input)
    output += enc.finalize()

    return output

#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
#


## This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key',
                                                   'hmac',
                                                   'address',
                                                   'message'])

from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher

def mix_server_one_hop(private_key, message_list):
    """ Implements the decoding for a simple one-hop mix.

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned

    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:
        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not len(msg.hmac) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the address and the message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)


def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with a set public key.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an hmac (20 bytes),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).
    """

    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    shared_element = private_key * public_key
    key_material = sha512(shared_element.export()).digest()

    # Use different parts of the shared key for different operations
    hmac_key = key_material[:16]
    address_key = key_material[16:32]
    message_key = key_material[32:48]

    ## Encrypt
    iv = b"\x00"*16
    address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)

    ## Generate HMAC
    h = Hmac(b"sha512", hmac_key)
    h.update(address_cipher)
    h.update(message_cipher)
    expected_mac = h.digest()[:20]

    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)



#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
#

from petlib.ec import Bn

# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key',
                                                   'hmacs',
                                                   'address',
                                                   'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn:
        - it derives a shared key (using its private_key),
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message.
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not isinstance(msg.hmacs, list) or \
               not len(msg.hmacs[0]) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()

        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00"*14)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys.
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes).

    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_cipher = pack("!H256s", len(address), address)
    message_cipher = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    hmacs = []
    key_materials = []

    """
    We need to precompute the private keys that we're going to be use considering
    the Blinding Factor. Encryption is back to front but Blinding factor is front to back,
    that's why we need to do this in advance.
    """
    for pk_i, public_key in enumerate(public_keys):
        shared_element = private_key *  public_key
        key_material = sha512(shared_element.export()).digest()

        key_materials.append(key_material)

        # Apply blinding factor to private key for the next shared key derivation
        blinding_factor = Bn.from_binary(key_material[48:])
        private_key *= blinding_factor

    """
    Iterate list back to front so that encryption is done in correct order.
    """
    for i, public_key in enumerate(reversed(public_keys)):
        shared_element = private_key * public_key
        key_material = key_materials[-(i + 1)]

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        ## Encrypt
        iv = b"\x00"*16
        address_cipher = aes_ctr_enc_dec(address_key, iv, address_cipher)
        message_cipher = aes_ctr_enc_dec(message_key, iv, message_cipher)

        def enc_hmac((index, hmac)):
            iv = pack("H14s", index, b"\x00"*14)
            return aes_ctr_enc_dec(hmac_key, iv, hmac)

        hmacs = map(enc_hmac, enumerate(hmacs))

        ## Generate HMAC
        h = Hmac(b"sha512", hmac_key)
        for other_hmac in hmacs:
            h.update(other_hmac)
        h.update(address_cipher)
        h.update(message_cipher)

        expected_mac = h.digest()[:20]

        hmacs.insert(0, expected_mac)

    return NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher)



#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces
#           the objective is to output an ordered list
#           of likely `friends` of a target user.

import random

def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """ Generate a simulated trace of traffic. """
    target = 0
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    ## Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample( others, threshold_size))
        receivers = sorted(random.sample( all_users, threshold_size))

        trace += [(senders, receivers)]

    ## Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample( others, threshold_size-1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample( all_users, threshold_size-1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


from collections import Counter

def analyze_trace(trace, target_number_of_friends, target=0):
    """
    Given a trace of traffic, and a given number of friends,
    return the list of receiver identifiers that are the most likely
    friends of the target.
    """

    receivers_count = {}

    for r in trace:
        (senders, receivers) = r
        if target in senders:
            for receiver in receivers:
                receivers_count[receiver] = 1 if receiver not in receivers_count else receivers_count[receiver] + 1

    return map(lambda x: x[0], sorted(receivers_count.items(), key=lambda x: x[1])[-target_number_of_friends:])

## TASK Q1 (Question 1): The mix packet format you worked on uses AES-CTR with an IV set to all zeros.
#                        Explain whether this is a security concern and justify your answer.

"""
There's two security concerns that arise from using a fixed IV in AES-CTR:

1. Two identical plaintexts are going to have the same ciphertexts. Thus, an attacker can
know when a client is sending the same message more than once.

2. Attackers have a real chance at decrypting messages. CTR can be boiled down to
C = P XOR F(K, IV), where C = ciphertext, P = plaintext, K = key.
Given two ciphertexts C_1 and C_2 and a static IV, an attacker is able to know:

C_1 XOR C_2 = P_1 XOR P_2

Now that the attacker knows P_1 XOR P_2 s/he can just start a crib-dragging attack. This won't
allow the attacker to learn about the plaintexts with 100% certainty. However, through guessing and trial and
error s/he might be able to decrypt parts of the plaintexts, eventually even their entirety.

Both issues can be easily solved by using a random IV for every message.
"""


## TASK Q2 (Question 2): What assumptions does your implementation of the Statistical Disclosure Attack
#                        makes about the distribution of traffic from non-target senders to receivers? Is
#                        the correctness of the result returned dependent on this background distribution?

"""
The implemented solution assumes that non-target senders are selecting receivers in equal probability (i.e. they
have no "friends"). If all senders also had a small group of corresponding receivers, the implemented algorithm
would not return correct results in some situations. For instace, if a non-target sender with a small group of potential
receivers happens to participate in the same rounds as the target. In this case, the algorithm won't be able to
distinguish between non-target and target friends as they'll all have been sent the same amount of messages during the same
mixing rounds.
"""
