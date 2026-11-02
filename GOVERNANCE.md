# Governance

## What is fixed and what can change

The format, version 1, is fixed: the ID, the descriptor, the receipt, the proof and the checkpoint do not change.
An implementation written against version 1 keeps working. Changes come as version 2, proposed in an issue in this
repository, discussed in the open, and published with new schemas and test vectors. Until a second operator exists,
Sheaf Labs decides when version 2 is final; from then on, the operators decide together (below).

The code (the clients, the examples and the register server) changes freely under the usual pull-request process.
Nothing enters this repository without review by a maintainer.

## Registers

Anyone may run a register from the server in this repository. A register is a public service that holds entries in
this format and answers the lookup. The register at traceableagents.org is the first and, until the operators say
otherwise, the canonical one: the instance other systems check by default.

Registers that speak the format can answer each other's lookups (see the format's section on registers that talk to
each other). An operator joins the network by publishing its register's key and address and asking the existing
operators to list it. Each operator keeps its own data and its own rules on who may join; the format and the lookup
are what they share.

## Who decides

Today: Sheaf Labs, which started the register, wrote the format and runs traceableagents.org.

The plan: a body of the register's members. Every system that issues IDs and writes receipts (a verifier), and every
operator that runs a register, gets a seat. Format changes, the list of registers, and the standing of verifiers are
decided there. The founding company gets no special answer from the lookup, and its own agents go through the same
door as everyone else's.

## Names

"Traceable Agents", "Register of Traceable Agents", the seal and traceableagents.org identify the canonical register
and its operator. The code and the format are open for anyone to use under their own name. See TRADEMARKS.md.

## Where things live

The standard: <https://know-your-agent.org> and this repository. The canonical register: <https://traceableagents.org>.

## Contact

register@traceableagents.org
