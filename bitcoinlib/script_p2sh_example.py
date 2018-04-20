"""Low-level example of how to spend a P2SH/BIP16 txout"""

from __future__ import print_function

import sys
if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)

import bitcoin
import hashlib
import struct

from bitcoin import SelectParams
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret
from bitcoin.core.key import CECKey, CPubKey
from bitcoin.core import b2x, lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160
from bitcoin.core.script import CScript, CScriptOp, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH

from pycoin import encoding
from base_script import MySignatureHash, MyCScript

from pycoin.tx.Tx import Tx

my_netcode = "testnet"
#my_netcode = "mainnet"
bitcoin.SelectParams(my_netcode)

my_params = bitcoin.params
my_privkey_prefix = bytes(bytearray([my_params.BASE58_PREFIXES['SECRET_KEY']]))
my_pubaddr_prefix = bytes(bytearray([my_params.BASE58_PREFIXES['PUBKEY_ADDR']]))

# Create the (in)famous correct brainwallet secret key.
h = hashlib.sha256(b'correct horse battery staple').digest()
seckey = CBitcoinSecret.from_secret_bytes(h)

cec_key = CECKey()
cec_key.set_secretbytes(h)

print("Secret key  hex: ", seckey.hex());
btc_addr = encoding.public_pair_to_bitcoin_address(cec_key.get_pubkey(), address_prefix=my_pubaddr_prefix)
print("Bitcoin address: ", btc_addr)

# Create a redeemScript, with public key and checksig op code (0xac)
# Similar to a scriptPubKey the redeemScript must be satisfied for the funds to be spent.
txin_redeemScript = CScript([seckey.pub, OP_CHECKSIG])
print("Public key of address #", seckey.pub.hex())
# 0x21 + secret.pub + OP_CHECKSIG (0x87)
print("Tx-in Redeem Script: ", b2x(txin_redeemScript))

# Create the magic P2SH scriptPubKey format from that redeemScript. You should
# look at the CScript.to_p2sh_scriptPubKey() function in bitcoin.core.script to
# understand what's happening, as well as read BIP16:
# https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
print("Redeem script hash160 #", b2x(bitcoin.core.Hash160(txin_redeemScript)))
# OP_HASH169 (0xa9) + 0x14 + hash160(txin_redeemscript) + OP_EQUALS (0x87)
print("Tx-in scriptPubKey:", b2x(txin_scriptPubKey))

# Convert the P2SH scriptPubKey to a base58 Bitcoin address and print it.
# You'll need to send some funds to it to create a txout to spend.
txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
print('Tx-in script address: ', str(txin_p2sh_address))
assert(isinstance(txin_p2sh_address, bitcoin.wallet.P2SHBitcoinAddress))

# Same as the txid:vout the createrawtransaction RPC call requires
#
# lx() takes *little-endian* hex and converts it to bytes; in Bitcoin
# transaction hashes are shown little-endian rather than the usual big-endian.
# There's also a corresponding x() convenience function that takes big-endian
# hex and converts it to bytes.
txid = lx('bff785da9f8169f49be92fa95e31f0890c385bfb1bd24d6b94d7900057c617ae')
print("Previous Tx-Id: ", b2x(txid))
vout = 0

# Create the txin structure, which includes the outpoint. The scriptSig
# defaults to being empty.
txin = CMutableTxIn(COutPoint(txid, vout))

# Create the txout. This time we create the scriptPubKey from a Bitcoin
# address.
pay_to_h = hashlib.sha256(b'pay to correct horse battery staple').digest()
pay_to_seckey = CBitcoinSecret.from_secret_bytes(pay_to_h)
pay_to_cec_key = CECKey()
pay_to_cec_key.set_secretbytes(pay_to_h)
to_btc_addr = encoding.public_pair_to_bitcoin_address(pay_to_cec_key.get_pubkey(), address_prefix=my_pubaddr_prefix)

print()
print("Pay this Bitcoin address: ", to_btc_addr)
#txout = CMutableTxOut(0.0005*COIN, CBitcoinAddress('323uf9MgLaSn9T7vDaK1cGAZ2qpvYUuqSp').to_scriptPubKey())
txout = CMutableTxOut(0.0005*COIN, CBitcoinAddress(to_btc_addr).to_scriptPubKey())
print("     pay to scriptPubKey: ", b2x(CBitcoinAddress(to_btc_addr).to_scriptPubKey()))

# Create the unsigned transaction.
tx = CMutableTransaction([txin], [txout])

# Calculate the signature hash for that transaction. Note how the script we use
# is the redeemScript, not the scriptPubKey. That's because when the CHECKSIG
# operation happens EvalScript() will be evaluating the redeemScript, so the
# corresponding SignatureHash() function will use that same script when it
# replaces the scriptSig in the transaction being hashed with the script being
# executed.

## override module method
SignatureHash = MySignatureHash

sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)

# Now sign it. We have to append the type of signature we want to the end, in
# this case the usual SIGHASH_ALL.
sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

# Set the scriptSig of our transaction input appropriately.
txin.scriptSig = CScript([sig, txin_redeemScript])

# Verify the signature worked. This calls EvalScript() and actually executes
# the opcodes in the scripts to see if everything worked out. If it doesn't an
# exception will be raised.
VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))

# Done! Print the transaction to standard output with the bytes-to-hex
# function.
print("Transaction:\n", b2x(tx.serialize()))

pycoin_tx = Tx.from_bin(tx.serialize())
print("Pycoin tx:\n", pycoin_tx.__repr__())

