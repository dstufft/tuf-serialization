import secrets
import json
import random
import hashlib

"""
{
    "_type": "snapshot",
    "spec_version": "1.0.0",
    "expires": "2030-01-01T00:00:00Z",
    "meta": {
        "targets.json": {"version": 1},
        "project1.json": {
            "version": 1,
            "hashes": {
                "sha256": "f592d072e1193688a686267e8e10d7257b4ebfcf28133350dae88362d82a0c8a"
            },
        },
        "project2.json": {
            "version": 1,
            "length": 604,
            "hashes": {
                "sha256": "1f812e378264c3085bb69ec5f6663ed21e5882bbece3c3f8a0e8479f205ffb91"
            },
        },
    },
    "version": 1,
}
"""

SNAPSHOT_META_FILES = 500_000


# Generate a snapshot.json with ~500k files. This is probably more than we'll
# ever have, but if every project currently on PyPI had it's own delegation,
# then this is about how many it would take today.
#
# We're also going to include length, and a sha256 hash. We'll likely include
# both when we implement.
#
# Going to use random values, to keep any serialization formats from cheating.
snapshot = {
    "_type": "snapshot",
    "spec_version": "1.0.0",
    "expires": "2030-01-01T00:00:00Z",
    "version": 100000,
    "meta": {
        secrets.token_urlsafe(16): {
            "version": random.randint(1, 99999999),
            "length": random.randint(1, 99999999),
            "hashes": {"sha256": hashlib.sha256(secrets.token_bytes(16)).hexdigest()},
        }
        for _ in range(SNAPSHOT_META_FILES)
    },
}


with open("example/snapshot.json", "w") as fp:
    json.dump(snapshot, fp, indent=4)
