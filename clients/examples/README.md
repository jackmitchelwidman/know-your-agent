# Examples

- `verifier.mjs`: a system that issues IDs and writes receipts through the register's open door. Registers
  itself, writes an owner and an agent, writes two receipts, calls `/verify`, then runs the handshake.
  `node verifier.mjs [register url]`.
- `owner-key.mjs`: hold your own owner key and sign a descriptor by hand, for an owner whose agents run on a
  platform that would otherwise keep the key. `node owner-key.mjs keygen | id | sign < descriptor.json`.
