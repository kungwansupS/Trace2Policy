# Red-team Mutations v0.1

Red-team replay mutates normal traces offline and evaluates the generated policy
against the mutated events.

Supported attack classes:

- `indirect_prompt_injection`
- `tool_poisoning`
- `data_exfiltration`
- `untrusted_to_shell`
- `scope_creep`
- `confused_deputy`
- `unsafe_public_write`
- `secret_read_attempt`

Mutations never call live tools, shells, networks, or external services.
