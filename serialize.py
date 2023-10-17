import json
import msgpack
import base64
import amazon.ion.simpleion as ion
from amazon.ion.symbols import shared_symbol_table
import cbor2
import gzip
import lzma
import brotli
import zstandard

from pprint import pprint

from securesystemslib.interface import (
    import_ed25519_privatekey_from_file,
    import_ed25519_publickey_from_file,
)
from securesystemslib.keys import create_signature
from securesystemslib.formats import encode_canonical
from securesystemslib import dsse
from securesystemslib.signer import Signature, SSlibSigner

import tuf_pb2 as pb


ROLES = ["root", "snapshot"]

NUMKEYS = {"root": 5, "snapshot": 1}

# TODO: Why does dsse.Envelope().sign() require a signer? How does this fit into
#       signatures from TUF?
#
#       I think the API is just confusing, for some reason it takes signatures
#       in the constructor AND it lets you sign(), but you can't compute the PAE
#       until the class is created? Dunno how this is supposed to work, but it
#       doesn't matter for serialization comparisons.


def _compact_json(obj):
    return json.dumps(obj, separators=(",", ":")).encode("utf8")


def canonical_json(keys, meta):
    cano = encode_canonical(meta).encode("utf8")
    signed = {"signed": meta, "signatures": [create_signature(k, cano) for k in keys]}
    return _compact_json(signed)


def _sign_dsse(en, keys):
    for key in keys:
        en.sign(SSlibSigner(key))
    return en


def dsse_json(keys, meta):
    data = _compact_json(meta)
    en = dsse.Envelope(data, "application/vnd.tuf+json", [])
    en = _sign_dsse(en, keys)
    return _compact_json(en.to_dict())


def dsse_json_utf(keys, meta):
    data = _compact_json(meta)
    en = dsse.Envelope(data, "application/vnd.tuf+json", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()
    d["payload"] = base64.b64decode(d["payload"]).decode("utf8")
    return _compact_json(d)


def dsse_msgpack(keys, meta):
    data = msgpack.packb(meta)
    en = dsse.Envelope(data, "application/vnd.tuf+msgpack", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()
    d["payload"] = base64.b64decode(d["payload"])
    d["signatures"] = [
        {"keyid": s["keyid"], "sig": base64.b64decode(s["sig"])}
        for s in d["signatures"]
    ]
    return msgpack.packb(d)


def dsse_ionb(keys, meta):
    data = ion.dumps(meta, binary=True)
    en = dsse.Envelope(data, "application/vnd.tuf+ionb", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()
    d["payload"] = base64.b64decode(d["payload"])
    d["signatures"] = [
        {"keyid": s["keyid"], "sig": base64.b64decode(s["sig"])}
        for s in d["signatures"]
    ]
    return ion.dumps(d, binary=True)


def dsse_iont(keys, meta):
    data = ion.dumps(meta, binary=False).encode("utf8")
    en = dsse.Envelope(data, "application/vnd.tuf+iont", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()
    d["payload"] = base64.b64decode(d["payload"])
    d["signatures"] = [
        {"keyid": s["keyid"], "sig": base64.b64decode(s["sig"])}
        for s in d["signatures"]
    ]
    return ion.dumps(d, binary=False).encode("utf8")


tuf_table = shared_symbol_table(
    "tuf",
    1,
    [
        "_type",
        "spec_version",
        "consistent_snapshot",
        "expires",
        "keys",
        "keytype",
        "scheme",
        "keyval",
        "public",
        "roles",
        "keyids",
        "threshold",
        "version",
        "meta",
        "hashes",
        "length",
    ],
)


def dsse_sionb(keys, meta):
    data = ion.dumps(meta, imports=[tuf_table], binary=True)
    en = dsse.Envelope(data, "application/vnd.tuf+ionb", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()
    d["payload"] = base64.b64decode(d["payload"])
    d["signatures"] = [
        {"keyid": s["keyid"], "sig": base64.b64decode(s["sig"])}
        for s in d["signatures"]
    ]
    return ion.dumps(d, imports=[tuf_table], binary=True)


def dsse_siont(keys, meta):
    data = ion.dumps(meta, imports=[tuf_table], binary=False).encode("utf8")
    en = dsse.Envelope(data, "application/vnd.tuf+iont", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()
    d["payload"] = base64.b64decode(d["payload"])
    d["signatures"] = [
        {"keyid": s["keyid"], "sig": base64.b64decode(s["sig"])}
        for s in d["signatures"]
    ]
    return ion.dumps(d, imports=[tuf_table], binary=False).encode("utf8")


def dsse_proto(keys, meta):
    # there's probably a better way to do this, but dirty is good enough for
    # now.
    if meta["_type"] == "root":
        pbmeta = pb.RootRole()
        pbmeta.spec_version = meta["spec_version"]
        pbmeta.consistent_snapshot = meta["consistent_snapshot"]
        pbmeta.expires = meta["expires"]
        pbmeta.version = meta["version"]

        for keyid, key in meta["keys"].items():
            pbmeta.keys[keyid].keytype = key["keytype"]
            pbmeta.keys[keyid].scheme = key["scheme"]
            pbmeta.keys[keyid].keyval.public = key["keyval"]["public"]

        for rolename, role in meta["roles"].items():
            pbmeta.roles[rolename].keyids.extend(role["keyids"])
            pbmeta.roles[rolename].threshold = role["threshold"]
    elif meta["_type"] == "snapshot":
        pbmeta = pb.SnapshotRole()
        pbmeta.spec_version = meta["spec_version"]
        pbmeta.expires = meta["expires"]
        pbmeta.version = meta["version"]

        for filename, snap in meta["meta"].items():
            pbmeta.meta[filename].version = snap["version"]
            if "length" in snap:
                pbmeta.meta[filename].length = snap["length"]
            pbmeta.meta[filename].hashes.update(snap.get("hashes", {}))
    else:
        raise RuntimeError("unknown type")

    data = pbmeta.SerializeToString()
    en = dsse.Envelope(data, "application/vnd.tuf+proto", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()

    pben = pb.Envelope()
    pben.payload = base64.b64decode(d["payload"])
    pben.payloadType = d["payloadType"]

    for sig in d["signatures"]:
        pbsig = pben.signatures.add()
        pbsig.keyid = sig["keyid"]
        pbsig.sig = base64.b64decode(sig["sig"])

    return pben.SerializeToString()


def dsse_cbor(keys, meta):
    data = cbor2.dumps(meta)
    en = dsse.Envelope(data, "application/vnd.tuf+cbor", [])
    en = _sign_dsse(en, keys)
    d = en.to_dict()
    d["payload"] = base64.b64decode(d["payload"])
    d["signatures"] = [
        {"keyid": s["keyid"], "sig": base64.b64decode(s["sig"])}
        for s in d["signatures"]
    ]
    return cbor2.dumps(d)


FORMATS = {
    ".canonical.json": canonical_json,
    ".dsse.json": dsse_json,
    ".dsse.jsont": dsse_json_utf,
    ".dsse.msgpack": dsse_msgpack,
    ".dsse.ionb": dsse_ionb,
    ".dsse.iont": dsse_iont,
    ".dsse.proto": dsse_proto,
    ".dsse.cbor": dsse_cbor,
    ".dsse.sionb": dsse_sionb,
    ".dsse.siont": dsse_siont,
}

# Format, Size,

for role in ROLES:
    with open(f"example/{role}.json") as fp:
        meta = json.load(fp)
    keys = [
        import_ed25519_privatekey_from_file(f"keys/{role}/key{kn}")
        for kn in range(1, NUMKEYS[role] + 1)
    ]

    for format, formatter in FORMATS.items():
        data = formatter(keys, meta)

        with open(f"output/{role}/{role}{format}", "wb") as bfp:
            bfp.write(data)

        with open(f"output/{role}/{role}{format}.gz", "wb") as bfp:
            bfp.write(gzip.compress(data, mtime=0))

        with open(f"output/{role}/{role}{format}.xz", "wb") as bfp:
            bfp.write(lzma.compress(data))

        with open(f"output/{role}/{role}{format}.br", "wb") as bfp:
            bfp.write(brotli.compress(data))

        with open(f"output/{role}/{role}{format}.zst", "wb") as bfp:
            bfp.write(zstandard.compress(data, level=19))
