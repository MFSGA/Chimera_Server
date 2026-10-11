# Chimera Server

This archive contains the Chimera Server executable, a minimal local SOCKS example, and the project
license.

The example listens on `127.0.0.1:11001`. Validate it before starting the service.

On Linux:

```bash
./chimera_server_app --config config.example.json5 --check
./chimera_server_app --config config.example.json5
```

On Windows, use PowerShell:

```powershell
.\chimera_server_app.exe --config config.example.json5 --check
.\chimera_server_app.exe --config config.example.json5
```

Replace the example with your own configuration before exposing the service to a network. Check the
[project README](https://github.com/MFSGA/Chimera_Server/blob/master/README.md) and
[compatibility matrix](https://github.com/MFSGA/Chimera_Server/blob/master/COMPATIBILITY.md) for
configuration details and current feature limits.
