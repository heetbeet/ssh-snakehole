ssh-snakehole

An importable Python package for temporary, code-paired SSH access across
Windows, Linux and macOS, without an extra native runtime dependency.

This repository currently contains a researched specification. There is no
working package, installer, relay service or security-audited implementation.
Start at docs/index.html. Python's standard library is allowed, including
ssl and hashlib. Additional native extensions and transport helper programs
are excluded from the proposed runtime.

The existing product audited for this design is heetbeet/ssh-magic at commit
6c8e1517a236296103f22c9c11fd6f0e3c2db0ac. That project is unchanged.
This is a separate design, with no backward compatibility requirement.

Authoritative specifications belong in docs/. Research downloads, probes and
other disposable process material belong in ignored docs/temp/.
