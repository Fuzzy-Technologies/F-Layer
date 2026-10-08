![F-Layer with AIna in the Fuzzy Technologies engineering laboratory](assets/brand/FTech-card-F-Layer.png){ .fl-project-art }

# Deploy and operate cloud servers

**F-Layer** helps engineers deploy servers in the cloud, manage the resources
created for a service, and check whether that service is reachable. You can use
it from the command line or integrate its Python APIs into your application.

Describe the deployment in a configuration file. F-Layer prepares a resource
plan, creates the cloud resources you explicitly authorize, and keeps a local
record of their identities. Use the same plan and record to inspect the stack,
recover an interrupted operation or remove its resources.

The current release supports **Yandex Cloud**, a **secure SSH gateway** with
per-device connection settings, and HTTP availability and timing checks.
It is useful for teams automating service environments and for developers
building infrastructure features into their own products. Other clouds and VPN
profiles are planned. F-Layer is open source; cloud usage is billed by your provider.

## Quick Start

[Install the stable release and run your first check](guide/index.md).
Once installed, this command works without cloud access:

```bash
python -m flayer check --format json
```

Expect `"status": "ok"` and exit code `0`. This confirms local Python/package
availability. To create a server, continue with the deployment walkthrough.

## Choose your next step

<div class="grid cards" markdown>

- **Prepare a cloud server**

    Follow the [first deployment](guide/first-deployment.md) to build a gateway
    plan, review its resources and authorize deployment.

- **Check a running service**

    Use the [CLI guide](guide/cli.md) for HTTP health checks, timing measurements
    and JSON results.

- **Integrate with your application**

    Explore the [Python API](api/index.md) and the
    [architecture](architecture.md) behind configuration, state and providers.

- **Extend or contribute**

    Read the [development guide](development.md) for the repository workflow
    and tests.

</div>

[Fuzzy Technologies](https://fuzzy-technologies.github.io/) ·
[GitHub repository](https://github.com/Fuzzy-Technologies/F-Layer)
