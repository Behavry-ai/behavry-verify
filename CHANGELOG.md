# Changelog

## 0.2.0 — first published release

The first version of `behavry-verify` on PyPI. Earlier `0.1.0` existed only in
this repository; nothing was ever installable, so there is no upgrade path to
describe and no prior behaviour to preserve.

### Changed

- **"No chain breaks" now applies only to evidence packages before
  `package_version` 1.1.** Behavry hashes its audit chain per agent, while a
  package holds a single session — a slice of a longer chain. The events in a
  slice need not link to one another: an agent running two sessions at once
  interleaves them, and browser-based events have no agent and so carry no link
  pointer at all. Walking a slice as though it were a whole chain reported
  breaks on intact sessions, and for multi-event browser sessions it did so
  every time. Packages from 1.1 assert per-event integrity instead, a claim
  that holds for any slice, and the walk is reported `SKIPPED` for them.

  Nothing is given up. An event removed or added still moves the Merkle root,
  which the manifest signature covers. A rewritten link pointer still fails
  that event's own signature, because `previous_hash` is inside the signed
  tuple. Both are asserted by tests rather than argued in prose.

  A `package_version` this tool cannot parse is treated as older than 1.1 and
  takes the stricter path.

### Added

- Tag-driven release workflow using PyPI Trusted Publishing, with a guard that
  refuses to publish when the tag and `pyproject.toml` disagree.
