<!-- SPECKIT START -->
For additional context about technologies to be used, project structure,
shell commands, and other important information, read
`specs/003-sparse-pq-ratchet/plan.md`
<!-- SPECKIT END -->

## dr-go Agent Requirements

- Use TDD for implementation work by default.
- Start by adding or updating a failing test that captures the expected behavior.
- Make the smallest code change needed to get the test passing.
- Run the relevant Go tests after each meaningful step and finish with `go test ./...` when feasible.
- For bug fixes, prefer reproducing the bug with a test before changing implementation code.
