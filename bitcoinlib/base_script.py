# my_script.py

from bitcoin.core.script import CScript, CScriptOp, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
import struct
import bitcoin

## override class method
class MyCScript(CScript):
    def is_witness_scriptpubkey(self):
        """Returns true if this is a scriptpubkey signaling segregated witness
        data. """
        return 3 <= len(self) <= 42 and CScriptOp(struct.unpack('<b',self[0:1])[0]).is_small_int()
    

__all__ = (
        'MyCScript',
)

SIGVERSION_BASE = 0
SIGVERSION_WITNESS_V0 = 1

def MySignatureHash(script, txTo, inIdx, hashtype, amount=None, sigversion=SIGVERSION_BASE):
    print("in My SignatureHash method...")
    if sigversion == SIGVERSION_WITNESS_V0:
        hashPrevouts = b'\x00'*32
        hashSequence = b'\x00'*32
        hashOutputs  = b'\x00'*32

        if not (hashtype & SIGHASH_ANYONECANPAY):
            serialize_prevouts = bytes()
            for i in txTo.vin:
                serialize_prevouts += i.prevout.serialize()
            hashPrevouts = bitcoin.core.Hash(serialize_prevouts)

        if (not (hashtype & SIGHASH_ANYONECANPAY) and (hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE):
            serialize_sequence = bytes()
            for i in txTo.vin:
                serialize_sequence += struct.pack("<I", i.nSequence)
            hashSequence = bitcoin.core.Hash(serialize_sequence)

        if ((hashtype & 0x1f) != SIGHASH_SINGLE and (hashtype & 0x1f) != SIGHASH_NONE):
            serialize_outputs = bytes()
            for o in txTo.vout:
                serialize_outputs += o.serialize()
            hashOutputs = bitcoin.core.Hash(serialize_outputs)
        elif ((hashtype & 0x1f) == SIGHASH_SINGLE and inIdx < len(txTo.vout)):
            serialize_outputs = txTo.vout[inIdx].serialize()
            hashOutputs = bitcoin.core.Hash(serialize_outputs)

        f = _BytesIO()
        f.write(struct.pack("<i", txTo.nVersion))
        f.write(hashPrevouts)
        f.write(hashSequence)
        txTo.vin[inIdx].prevout.stream_serialize(f)
        BytesSerializer.stream_serialize(script, f)
        f.write(struct.pack("<q", amount))
        f.write(struct.pack("<I", txTo.vin[inIdx].nSequence))
        f.write(hashOutputs)
        f.write(struct.pack("<i", txTo.nLockTime))
        f.write(struct.pack("<i", hashtype))

        return bitcoin.core.Hash(f.getvalue())

    assert not MyCScript.is_witness_scriptpubkey(script)

    (h, err) = bitcoin.core.script.RawSignatureHash(script, txTo, inIdx, hashtype)
    if err is not None:
        raise ValueError(err)
    return h
