from __future__ import print_function

import bitcoin.core
import bitcoin.base58
from bitcoin.wallet import *

from ecdsa import SigningKey, VerifyingKey, util, SECP256k1, ellipticcurve
from pycoin import ecdsa

from binascii import hexlify, unhexlify

from pycoin.key import Key
from pycoin import encoding
from pycoin.intbytes import iterbytes
from pycoin.serialize import b2h, h2b
from pycoin.networks import registry

import pprint

#bitcoin.SelectParams('regtest')

ecdsa_signingkey = SigningKey.generate()

# Generate a random private key
valid_private_key = False
while not valid_private_key:
    my_secret = 1 #util.randrange(ecdsa.generator_secp256k1.order())
    valid_private_key = 0 < my_secret < ecdsa.generator_secp256k1.order()

print("")
my_prng = util.PRNG(util.randrange(ecdsa.generator_secp256k1.order()))
print("PRNG (random generator) 32 bytes: ", b2h(my_prng.__call__(32)))

my_netcode = "BTC" # mainnet: BTC, testnet3: XTN

my_key = Key(secret_exponent=my_secret, is_compressed=True, netcode=my_netcode)
## netcode list: pycoin.networks.all.py

pp = pprint.PrettyPrinter(indent=2)
my_network = registry.network_for_netcode(my_netcode)
my_addr_prefix = registry._lookup(my_netcode, "address")
getattr(my_network, "address")
pp.pprint(my_network.__dict__)
pprint.pprint(my_network.__dict__.keys(), width=60, depth=2)

privkey_hex = b2h(encoding.to_bytes_32(my_key.secret_exponent()))
assert(len(privkey_hex) == 64)

print("\npycoin.key.Key example - ", my_netcode)

#print("Private Key (dec): ", eval('0x' + privkey_hex))
print("Private Key (dec): ", int(privkey_hex, 16))
print("Private Key (hex): ", privkey_hex)
privkey_bytes = unhexlify(privkey_hex)
# use CBitcoinSecret to compress private key
btc_secret = CBitcoinSecret.from_secret_bytes(privkey_bytes, True)
print("     compressed: ", hexlify(btc_secret.to_bytes()))
assert(btc_secret.is_compressed == True)
assert(bitcoin.core.b2x(btc_secret.to_bytes()) == (privkey_hex + '01'))

print("Private Key   WIF: ", my_key.wif())
print("     uncompressed: ", my_key.wif(use_uncompressed=True))

print("Privkey hashed base58: ", encoding.b2a_hashed_base58(privkey_bytes))


print()
## Public key and address
public_key = my_key.public_pair()
(public_key_x, public_key_y) = public_key

print("Public Key Pair: ", public_key)
print("     x as hex: ", hex(public_key[0]))
print("     y as hex: ", hex(public_key[1]))

#compressed_indicator_1 = '02' if (public_key_y % 2) == 0 else '03'
compressed_indicator = True if (public_key_y % 2) == 0 else False
print("Public key y parity: ", 'even' if compressed_indicator else 'odd')
assert(compressed_indicator != my_key._use_uncompressed)

print("Public key     hex: ", my_key.sec_as_hex())
print("      uncompressed: ", my_key.sec_as_hex(use_uncompressed=True))
assert(my_key.sec_as_hex() == bitcoin.core.b2x(my_key.sec()))

print("Public key hash160: ", b2h(my_key.hash160()))
print("      uncompressed: ", b2h(my_key.hash160(use_uncompressed=True)))

#print("Bitcoin Address   : ", my_key.address())
addr_compressed = encoding.public_pair_to_bitcoin_address(public_key, True, my_addr_prefix)
addr_uncompressed = encoding.public_pair_to_bitcoin_address(public_key, False, my_addr_prefix)

print("Bitcoin    Address: ", addr_compressed)
print("      uncompressed: ", addr_uncompressed)

assert(encoding.is_valid_bitcoin_address(addr_compressed, my_addr_prefix))
assert(encoding.is_valid_bitcoin_address(addr_uncompressed, my_addr_prefix))
assert(my_key.address() == addr_compressed)

pubkey_bytes = encoding.public_pair_to_sec(public_key, True);
assert(my_key.sec_as_hex() == b2h(pubkey_bytes))
pubkey_bytes = encoding.public_pair_to_sec(public_key, False);
assert(my_key.sec_as_hex(use_uncompressed=True) == b2h(pubkey_bytes))

print()
#CBitcoinAddress.from_bytes(bitcoin.core.serialize.Hash160(my_key.address()), 111)
btc_addr = CBitcoinAddress.from_bytes(bitcoin.base58.decode(my_key.address()), bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR'])
print("Bitcoin Address hex: ", hexlify(btc_addr.to_bytes()))
assert(bitcoin.base58.encode(btc_addr.to_bytes()) == addr_compressed)

pubkey_b58 = encoding.b2a_base58(pubkey_bytes)
#CBitcoinAddress.from_scriptPubKey(pubkey_b58)

