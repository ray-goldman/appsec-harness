# Source-file boundaries

MCP `appsec_read_code`, `appsec_search_code`, finding previews, triage context and triage evidence use the same source reader. This includes both the primary location and evidence of manually added findings.

The reader resolves the selected root, inspects every descendant component and requires canonical containment. It rejects directory junctions and symlinks anywhere below the root, including links to another location inside the root. A root alias explicitly selected by the operator is allowed and resolved to its canonical directory.

File arguments must be relative paths to regular files. Absolute paths, parent traversal components, Windows drive-relative paths and alternate data streams are rejected. Missing or unreadable files, directories, files larger than 1 MiB and paths deeper than 40 components are also rejected. MCP reads return an error; searches skip unreadable candidates; previews omit context; evidence validation fails.

The file is opened once and read through that descriptor. Device/inode identities, file size and modification/change timestamps are checked around opening and reading. Path components are checked again before reading and before returning. An observed replacement or content change rejects the read. Reads use a bounded buffer, and descriptors close on success and failure.

## Filesystem limits

Portable Node.js path checks are not an atomic directory-handle sandbox. They reject static links and observed changes, but cannot prove safety against a process repeatedly mutating the tree in synchrony with the checks. Scan a stable snapshot when another process can modify hostile input. Pre-existing hard links are regular files and are outside the directory-link guarantee. Report/output directories remain operator-selected and are a separate boundary.

## Regression coverage

`test/file-confinement.test.js` exercises ordinary reads, outside and in-root junctions, nested links, leaf symlinks, selected root aliases, invalid paths, every evidence channel, previews, search, size limits, descriptor cleanup and controlled path/file mutations.

On Windows without file-symlink privileges, the leaf-symlink test explicitly skips. Windows also blocks renaming a directory with an open file; the two tests requiring that mutation explicitly skip after checking descriptor cleanup where applicable. Directory-junction tests run on Windows. The Linux CI job exercises the POSIX link and rename cases.

These tests verify a filesystem boundary. They do not change scanner rules or measure vulnerability-detection accuracy.
