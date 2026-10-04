# User guide

Start from a local checkout and an explicit provider scope. The foundation can
validate configuration, inspect Yandex Cloud resources, and run bounded
read-only diagnostics. Lifecycle and gateway functionality are introduced by
the second implementation wave; their walkthrough identifies the required
modules before any cloud operation.

1. [Install from source](installation.md) and run the offline smoke check.
2. [Configure provider access](configuration.md) with a preauthenticated `yc` profile.
3. [Read CLI results](cli.md), including unsupported observations and exit codes.
4. [Prepare the first deployment](first-deployment.md) with explicit ownership and mutation consent.

F-Layer has no stable API before `v1.0.0`. The installed-wheel
[API reference](../api/index.md) describes the actual modules in this revision.
