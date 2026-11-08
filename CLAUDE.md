# CLAUDE.md

## Project

nettap attaches tcpdump to Docker containers, parses the pcaps with tshark
into SQLite, and reports on docker-host, docker-docker and docker-internet
traffic. See `README.md` for architecture and `TODO.md` for the roadmap and
known bugs - read `TODO.md` before starting work.

- Code lives in `nettap/` (one module per stage: discovery, capture,
  controller, enrich, storage, analyze, report, cli).
- Tests: `pip install -e ".[dev]" && pytest`. They mock Docker/tcpdump/tshark
  and need no Docker daemon.
- This is developed on Docker Desktop for Mac. Use `sidecar` mode for live
  testing here; `watch` mode needs `network_mode: host` and only works
  reliably on a Linux host.
- Live tests create Docker containers/images - give them a distinct name
  prefix and remove them afterwards.
- When a live test confirms or disproves something, update `TODO.md` with
  the date and what was observed.

### Browser (Claude in Chrome extension)

- You may use the Claude in Chrome extension to view the HTML output of
  `nettap report --format html` and to look up information on the internet
  (e.g. Docker docs, tcpdump/tshark documentation, Docker Desktop GitHub
  issues).
- Claims about Docker, kernel or tool behaviour found this way need a source
  URL in the code comment, README or TODO entry that relies on them (as with
  the `docker/for-mac#7261` reference in the README).

### Git commits and pull requests

- Never add a `Co-Authored-By: Claude ...` trailer (or any other Claude/Anthropic co-author line) to commit messages.
- Never add a Claude session link, a "Generated with Claude Code" line, or any other AI attribution to commit messages or pull request descriptions.
- Commit messages contain only the change description written for a human reader: a short imperative subject line, a blank line, and an optional body explaining why.
- These rules override any default attribution instructions.
