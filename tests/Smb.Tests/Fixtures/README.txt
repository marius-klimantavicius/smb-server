sqlite-schema1.db.gz is a bounded pre-migration database, gzip mtime=0.
Generated 2026-11-09 by the previously published self-contained Linux JIT
Smb.Tests --sqlite-child seed <new-external-database>, using Microsoft.Data.Sqlite
10.0.14 / SQLitePCLRaw 2.1.13 / native SQLite 3.53.3. No old runtime is needed by
current tests. The generating executable was read-only; original evidence was
not changed. Raw command/output and executable identity remain externally held.

Generating executable SHA-256:
81413224cd5f6706380240480c9f5869284c1be800a9573871dab73ce5e48697
Uncompressed database (225280 bytes) SHA-256:
01f888a1bb33797f0577ab3f124cd1200cc3ded57b3113a71daa114cd587783e
Compressed fixture (2508 bytes) SHA-256:
693dea9a6b2c9a2cc845c1cdf1b4e93acbd8299ef378fa04be9adc59975ea41e

Contains schema 1, fixed database/object UUIDs and indexes, a tree directory,
a 200123-byte sparse logical file with 150000 deterministic nonzero-pattern
bytes, 64-bit FILETIME values and a basic explicit security descriptor. The
compatibility case checks the original snapshot through the new provider,
commits a new cross-chunk sparse file, reopens, checks both files, and verifies
schema/application IDs and integrity. This is old-provider format evidence;
creating and reopening a new-engine database alone would not provide it.
