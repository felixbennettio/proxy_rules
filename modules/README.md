# Surge modules

This directory mirrors the 20 remote modules installed in the owner's Surge and their 28 declared script resources. Surge's built-in modules and the unconfigured built-in UniFi plugin are not redistributed.

`SOURCES.json` identifies public module/script origins and records the provenance of the initial copies. The initial module files came from the owner's installed modules; initial scripts came from the owner's successful Surge cache. The original `Oranjekop/Surge-Module` repository currently returns 404 and `kelee.one` script downloads fail in the owner's network. These copies are explicitly cached versions, not a claim that upstream was freshly fetched.

- `upstream/*.sgmodule`: original module snapshots, with original metadata preserved.
- `*.sgmodule`: generated modules whose declared `script-path` dependencies use the private GitLab Repository Files API.
- `scripts/*.js`: verified script files, deduplicated by source URL.
- `STATUS.json`: per-source freshness, last successful content timestamp, checksum, and cache fallback reason.

GitHub Actions runs `tools/sync_modules.py` every day at 04:47 UTC+8. It downloads public sources, validates non-empty UTF-8 content, and preserves a verified previous copy when a source is unavailable. A newly introduced dependency without a valid download or existing copy aborts publication. An unavailable source is reported as cached, with a warning in the workflow summary. Unused generated modules and script dependencies are removed. This workflow does not change rule-upstream failure handling.

GitLab's existing 05:17 UTC+8 synchronization copies every published module/script from `DIST_MANIFEST.json`. Credentials never appear in GitHub or GitLab repository content.

## Private installation

A module URL has this form (replace `TOKEN` locally):

```text
https://git.routeforge.zone/api/v4/projects/13/repository/files/modules%2FScript-Hub.sgmodule/raw?ref=main&private_token=TOKEN
```

Modules with scripts declare `GitLabToken` using Surge's native module argument mechanism. Set that argument to the same repository-only read token. Existing arguments such as weather-provider options are retained. The token is stored only in the local Surge module instance, not as a default value in these files.

The module URL authenticates the module download; its `GitLabToken` argument authenticates nested script downloads. Both are needed for script-bearing modules. Pure-rule modules need only the authenticated module URL.

Original module behavior, service API endpoints, and original author/license notices are preserved. Only the declared script download locations and the added authentication argument change.
