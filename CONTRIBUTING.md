# Contributing

Changes to the format are versioned. Version 1 is fixed: the ID, descriptor, receipt, proof and checkpoint
formats do not change. New fields and new calls arrive as version 2 and are discussed in an issue first.

Clients and examples take fixes and new languages at any time. Keep them small, with no dependencies where
the language allows it, and make them pass `spec/vectors/verify.mjs` or its equivalent.

Every commit carries a Developer Certificate of Origin sign-off (`git commit -s`), which says you wrote the
change or have the right to submit it under this repository's licences.
