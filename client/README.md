# svmvisor-client

This is a Windows x64 library core with a native process picker, process wrapper
and console helpers. It does not currently contain an executable frontend.

Live access is temporarily disabled. `connect` returns `ErrorKind::ReaderDisabled`
before reading kernel profiles or calling the runtime. The existing picker shows
that message and returns the error when closed. No command or setting restores
the retired guest interface.

This closes the unauthenticated path; it does not complete the private client.
Re-enabling this client on the same PC while resisting a compromised Windows
kernel requires a proven isolation boundary for authentication and protected
results. An ordinary Windows process cannot keep those secrets from its kernel.
No substitute credentials, handshake or fallback have been added here.

[INTEGRATION.md](INTEGRATION.md) maps the reusable client code to the remaining
hardware, Windows coexistence and protected interactive-peer milestones.

Build and test the library from the workspace root:

```text
cargo build -p svmvisor-client --locked
cargo test -p svmvisor-client --locked
```
