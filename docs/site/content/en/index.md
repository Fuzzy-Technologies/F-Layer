![F-Layer with AIna in the Fuzzy Technologies engineering laboratory](assets/brand/FTech-card-F-Layer.png){ .fl-project-art }

# Deploy and operate cloud servers

**F-Layer** helps engineers deploy servers in the cloud, manage the resources
created for a service, and check whether that service is reachable. You can use
it from the command line or integrate its Python APIs into your application.

Describe the deployment in a configuration file. F-Layer prepares a resource
plan, creates the cloud resources you explicitly authorize, and keeps a local
record of their identities. Use the same plan and record to inspect the stack,
recover an interrupted operation or remove its resources.

The **2.0 development candidate** adds a private VPN workflow: deploy one Yandex
Cloud server with **AmneziaWG 3.1** and **VLESS Reality**, then import the generated
settings into your clients. The published **v1.2.1** release provides the secure
SSH gateway and HTTP checks; it does not include the new VPN commands. Version
2.0 is not yet a published stable release. Other cloud providers need an adapter.
F-Layer is open source; cloud usage is billed by your provider.

## Quick Start

Choose the stable or candidate package in [Install](guide/installation.md).
The [Quick Start](guide/index.md) takes the 2.0 candidate from installation to
a private project, Yandex Cloud deployment and client connection.
Once installed, this command works without cloud access:

```bash
python -m flayer check --format json
```

Expect `"status": "ok"` and exit code `0`. This confirms local Python/package
availability. To create a server, continue with the deployment walkthrough.

## Choose your next step

<div class="grid cards" markdown>

- **Connect through your own VPN server**

    Follow the [Quick Start](guide/index.md) for both protocols in the 2.0
    candidate, or the [SSH gateway guide](guide/first-deployment.md) for v1.2.1.

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
