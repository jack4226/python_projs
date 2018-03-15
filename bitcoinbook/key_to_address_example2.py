from __future__ import print_function

import bitcoin
#import bitcoin.core
#import bitcoin.core.serialize
import bitcoin.base58
from bitcoin.core.key import CECKey, CPubKey
from bitcoin.wallet import *

from ecdsa import SigningKey, VerifyingKey, util, SECP256k1, ellipticcurve
from pycoin import ecdsa

from pycoin import encoding
from binascii import unhexlify, hexlify
from pycoin.serialize import b2h, h2b

bitcoin.SelectParams('regtest')

## Version of address, script
## mainnet - 0, 5
## testnet and regtest - 111, 196

print()
print("Pubkey Addr Ver: ", bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR'], "Script Addr Ver: ",
      bitcoin.params.BASE58_PREFIXES['SCRIPT_ADDR'])

print("CECKey example")
# use CECKey class
cec_key = CECKey()
#cec_key.set_secretbytes(privkey_bytes)
random_nbr = util.randrange(ecdsa.generator_secp256k1.order())
my_secret_exp = '0279be667ef9dcbbac55a06295ce8345'
my_secret_exp = '0000000000000000000000000000000000000000000000000000000000000001'
#my_secret_exp = b2h(encoding.to_bytes_32(random_nbr))
cec_key.set_secretbytes(bitcoin.core.x(my_secret_exp))

print("Private Key hex: ", my_secret_exp)
privkey_wif = encoding.secret_exponent_to_wif(eval('0x' + my_secret_exp))
print("Private key WIF: ", privkey_wif)
privkey_wif = encoding.secret_exponent_to_wif(eval('0x' + my_secret_exp), False)
print("   uncompressed: ", privkey_wif)

privkey_wif = encoding.secret_exponent_to_wif(eval('0x' + my_secret_exp), wif_prefix=b'\xef')
print("        testnet: ", privkey_wif)

cec_key.set_compressed(True)
pubkey_pair = encoding.sec_to_public_pair(cec_key.get_pubkey())
print("Public key pair: ", pubkey_pair)

(pub_key_x, pub_key_y) = pubkey_pair
compressed_indicator = True if (pub_key_y % 2) == 0 else False
print("Public key y parity? ", 'even' if compressed_indicator else 'odd')
print()

#print("Private key hexlify: ", hexlify(cec_key.get_privkey()))
print("Public  key    hex: ", bitcoin.core.b2x(cec_key.get_pubkey()))
cec_key.set_compressed(False)
print("      uncompressed: ", bitcoin.core.b2x(cec_key.get_pubkey()))

addr_compressed = encoding.public_pair_to_bitcoin_address(pubkey_pair, True)
addr_uncompressed = encoding.public_pair_to_bitcoin_address(pubkey_pair, False)

# convert public key pair to public key to address
pubkey_hashed = encoding.public_pair_to_hash160_sec(pubkey_pair, True)
print("Public key hash160: ", bitcoin.core.b2x(pubkey_hashed))
pubkey_addr = encoding.hash160_sec_to_bitcoin_address(pubkey_hashed)
assert(addr_compressed == pubkey_addr)

pubkey_hashed = encoding.public_pair_to_hash160_sec(pubkey_pair, False)
print("      uncompressed: ", bitcoin.core.b2x(pubkey_hashed))
pubkey_addr = encoding.hash160_sec_to_bitcoin_address(pubkey_hashed)
assert(addr_uncompressed == pubkey_addr)

print("Bitcoin    Address: ", addr_compressed)
print("      uncompressed: ", addr_uncompressed)
assert(encoding.is_valid_bitcoin_address(addr_compressed))
assert(encoding.is_valid_bitcoin_address(addr_uncompressed))
print()

## Uncompressed public key
pubkey_bytes = encoding.public_pair_to_sec(pubkey_pair, False); # uncompressed
pubkey_b58 = encoding.b2a_base58(pubkey_bytes)
assert(pubkey_bytes == encoding.a2b_base58(pubkey_b58))

btc_addr = CBitcoinAddress.from_bytes(pubkey_bytes, bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR'])
assert(b2h(cec_key.get_pubkey()) == b2h(btc_addr.to_bytes()))
assert(hexlify(cec_key.get_pubkey()) == hexlify(pubkey_bytes))

#print("Uncompressed public key")
c_pubkey = CPubKey(pubkey_bytes)
#print("Is public key valid? ", c_pubkey.is_valid, ", compressed? ", c_pubkey.is_compressed)
assert(c_pubkey.is_compressed == False)
assert(c_pubkey.is_valid == True)

#print("Public Key base58:", pubkey_b58)
#print("           hashed:", encoding.b2a_hashed_base58(pubkey_bytes))

## Compressed public key
pubkey_bytes = encoding.public_pair_to_sec(pubkey_pair, True); # compressed
pubkey_b58 = encoding.b2a_base58(pubkey_bytes)
assert(pubkey_bytes == encoding.a2b_base58(pubkey_b58))

btc_addr = CBitcoinAddress.from_bytes(pubkey_bytes, bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR'])
assert(bitcoin.core.b2x(cec_key.get_pubkey()) != bitcoin.core.b2x(btc_addr.to_bytes()))
assert(hexlify(btc_addr.to_bytes()) == hexlify(pubkey_bytes))

#print("Compressed public key")
c_pubkey = CPubKey(pubkey_bytes)
#print("Is public key valid? ", c_pubkey.is_valid, ", compressed? ", c_pubkey.is_compressed)
assert(c_pubkey.is_compressed == True)
assert(c_pubkey.is_valid == True)

#print("Public Key base58:", pubkey_b58)
#print("           hashed:", encoding.b2a_hashed_base58(pubkey_bytes))


btc_addr = CBitcoinAddress.from_bytes(bitcoin.base58.decode(addr_compressed), bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR'])
print("Bitcoin address hex: ", hexlify(btc_addr.to_bytes()))
assert(bitcoin.base58.encode(btc_addr.to_bytes()) == addr_compressed)

btc_addr = CBitcoinAddress.from_bytes(bitcoin.base58.decode(addr_uncompressed), bitcoin.params.BASE58_PREFIXES['PUBKEY_ADDR'])
#print("      uncompressed: ", hexlify(btc_addr.to_bytes()))
assert(bitcoin.base58.encode(btc_addr.to_bytes()) == addr_uncompressed)

