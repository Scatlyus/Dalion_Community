# ATLAS Gateway Configuration

Project: Dalion
Stack: TypeScript + Node.js

## Commands

```bash
atlas dev              # Interactive programming mode
atlas task "..."       # Execute single task
atlas review           # Quick compliance check
atlas audit            # Deep audit with stub detection
atlas status           # Show project health
```

## Token Optimization

- Axioms: Reusable patterns are stored in .agent/axioms/
- Logs: Session history in .agent/logs/
- Handshake: Mandatory briefing prevents token waste
- Project context: see [Dalion overview](../docs/00-overview.md).
- Dalion agent references: see [the local manifest](manifests/dalion.yaml). Cross-project manifests and protocols are local reference material, not Dalion configuration.

## Frozen Paths

These directories are protected from modification:
- .agent
- node_modules
- .git
- dist
- build
