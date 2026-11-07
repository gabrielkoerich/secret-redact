<!-- shipcheck:start v5 -->

## Tests and commits

- Do not run the test commands (`pytest`, `cargo test`, `npm test`, `go test`, `just test` and the like). Run `shipcheck run`. It runs this repository's CI on your working copy, and its result is the PR's required check.
- Commit with `shipcheck commit -m "<subject>"`, never `git commit`. It commits every file, exactly the tree that passed.
- Work in small steps: one change, `shipcheck run`, `shipcheck commit`. Delete scratch files first, because every file is committed.
- Exit 1: read `shipcheck logs`, fix, then `shipcheck run --job <id>` for the failed job as often as needed. A partial run is never the check, so finish with one full `shipcheck run`, then `shipcheck commit`. Exit 2: shipcheck could not run, and your code did not run. Run `shipcheck doctor` and follow it. If that does not fix it, do not stop: commit with `git commit` and push as usual, and the PR waits for its checks until shipcheck runs.
- If `shipcheck` is not on PATH, run the project's tests and commit with git.
- Never edit `.github/workflows/` or `shipcheck.toml` to get a pass. Details: https://shipcheck.run/llms.txt

<!-- shipcheck:end -->
