#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py

###########################
# Group Members: Marti Serra
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher

def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")

    aes = Cipher("aes-128-gcm")
    iv = urandom(16)
    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)

    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K

        In case the decryption fails, throw an exception.
    """

    aes = Cipher("aes-128-gcm")
    plaintext = aes.quick_gcm_dec(K, iv, ciphertext, tag)

    return plaintext.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn
import binascii

def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x == None and y == None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    if x0 is x1 and y0 is y1:
        raise Exception("EC Points must not be equal")

    # Check for one of the points being Inf
    if x0 is None and y0 is None:
        return (x1, y1)

    if x1 is None and y1 is None:
        return (x0, y0)

    # Check for pt - pt = Inf
    x_sub = x0.mod_sub(x1, p)
    y_sub = y0.mod_sub(y1, p)
    try:
        x_sub.mod_inverse(p)
        y_sub = y0.mod_sub(y1, p)
    except:
        return (None, None)

    lam = y_sub.mod_mul(x_sub.mod_inverse(p), p)
    xr  = lam.mod_pow(2, p).mod_sub(x1, p).mod_sub(x0, p)
    yr  = lam.mod_mul(x1.mod_sub(xr, p), p).mod_sub(y1, p)

    return (xr, yr)

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """

    if x is None and y is None:
        return (None, None)

    lam = x.mod_pow(2, p).mod_mul(3, p).mod_add(a, p).mod_mul(y.mod_mul(2, p).mod_inverse(p), p)
    xr  = lam.mod_pow(2, p).mod_sub(x.mod_mul(2, p), p)
    yr  = lam.mod_mul(x.mod_sub(xr, p), p).mod_sub(y, p)

    return (xr, yr)

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)
    """
    Q = (None, None)
    P = (x, y)

    binary_rep = "{0:b}".format(scalar.int())
    rep_len = len(binary_rep) -1
    for i in range(scalar.num_bits()):
        if binary_rep[rep_len -i] == '1':
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])

        P = point_double(a, b, p, P[0], P[1])

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)
    """
    R0 = (None, None)
    R1 = (x, y)

    binary_rep = "{0:b}".format(scalar.int())
    rep_len = len(binary_rep) -1
    for i in reversed(range(0,scalar.num_bits())):
        if binary_rep[rep_len -i] is '0':
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])
        else:
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])

    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from hashlib import sha256

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")

    sig = do_ecdsa_sign(G, priv_sign, plaintext)

    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")

    res = do_ecdsa_verify(G, pub_verify, sig, plaintext)

    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE:

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()

    return (G, priv_dec, pub_enc)

def dh_get_shared_key(pub, priv):
    """ Return a 256bit key based on the x coordinate of the
    EC point multiplication between pub and priv.
    """
    x_coord = pub.pt_mul(priv).get_affine()[0]
    key_hex = sha256(x_coord.repr()).hexdigest()
    shared_key = key_hex[:32]

    return shared_key

def dh_encrypt(pub, message):
    """ Assume you know the public key of someone else (Bob),
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """

    (G, fresh_priv, fresh_pub) = dh_get_key()
    shared_key = dh_get_shared_key(pub, fresh_priv)

    plaintext = message.encode("utf8")
    aes = Cipher("aes-256-gcm")
    iv = urandom(32)
    ciphertext, tag = aes.quick_gcm_enc(shared_key, iv, plaintext)

    signature = ecdsa_sign(G, fresh_priv, message)

    return (ciphertext, iv, tag, fresh_pub, signature)

def dh_decrypt(priv_receiver, ciphertext, iv, tag, pub_sender, signature = None):
    """ Decrypt a received message encrypted using your public key,
    of which the private key is provided. Optionally verify
    the message came from Alice using her verification key."""

    shared_key = dh_get_shared_key(pub_sender, priv_receiver)

    aes = Cipher("aes-256-gcm")
    plaintext = aes.quick_gcm_dec(shared_key, iv, ciphertext, tag)

    message = plaintext.decode("utf8")

    G = EcGroup()
    if signature:
        verify = ecdsa_verify(EcGroup(), pub_sender, message, signature)
        if not verify:
            raise Exception("Could not verify message")

    return message

## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py

def test_encrypt():
    (bob_G, bob_priv, bob_pub) = dh_get_key()

    message = "Hello World"

    # Check Alice can send encrypted message to Bob
    (ciphertext, iv, tag, fresh_pub, signature) = dh_encrypt(bob_pub, message)

    assert len(ciphertext) == len(message)
    assert len(iv) == 32
    assert len(tag) == 16
    assert ecdsa_verify(bob_G, fresh_pub, message, signature)

def test_decrypt():
    (bob_G, bob_priv, bob_pub) = dh_get_key()

    message = "Hello World"

    # Alice encrypts message for Bob
    (ciphertext, iv, tag, sender_pub, signature) = dh_encrypt(bob_pub, message)

    # Bob decrypts message from Alice
    plaintext = dh_decrypt(bob_priv, ciphertext, iv, tag, sender_pub, signature)

    assert plaintext == message

def test_fails():
    from pytest import raises

    (bob_G, bob_priv, bob_pub) = dh_get_key()

    message = "Hello World"

    # Alice encrypts message for Bob
    (ciphertext, iv, tag, sender_pub, signature) = dh_encrypt(bob_pub, message)

    # Decryption fails when wrong public key
    with raises(Exception) as excinfo:
        dh_decrypt(123456, ciphertext, iv, tag, sender_pub, signature)
    assert 'decryption failed' in str(excinfo.value)

    # Decryption fails when wrong public key
    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, ciphertext, iv, tag, sender_pub.pt_mul(2), signature)
    assert 'decryption failed' in str(excinfo.value)

    # Decryption fails when wrong iv
    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, ciphertext, urandom(32), tag, sender_pub, signature)
    assert 'decryption failed' in str(excinfo.value)

    # Decryption fails when wrong tag
    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, ciphertext, iv, urandom(16), sender_pub, signature)
    assert 'decryption failed' in str(excinfo.value)

    # Decryption fails because of verify
    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, ciphertext, iv, tag, sender_pub, ecdsa_sign(bob_G, bob_priv, "Message"))
    assert 'Could not verify message' in str(excinfo.value)


#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

def time_scalar_mul():
    pass
