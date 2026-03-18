# dodoco

An HTTP/HTTPS proxy that routes traffic through specific network interfaces based on hostname rules. Useful for sending traffic for certain domains through a VPN interface while letting everything else go through the default route.

## How it works

dodoco is a forward proxy. You configure your browser or system to use it as an HTTP proxy. When a request comes in, dodoco checks the destination hostname against a rules file. If a rule matches, it binds the outgoing connection to the specified network interface (e.g. a VPN tunnel) and DNS server. If no rule matches, it uses the default route. (which is just forwarding using your default interface)

Rules support glob patterns (e.g. `*.x.com`). The rules file is watched for changes and reloaded automatically.

An admin web UI is served on a separate port for viewing and editing rules. (defaults to https://localhost:9090)

## Requirements

- Go 1.26+
- Linux (uses `SO_BINDTODEVICE`, requires `CAP_NET_RAW`)

## Build

```
make build
```

This builds the binary to `dist/dodoco` and sets the `CAP_NET_RAW` capability on it (requires sudo).

## Run

```
make run
```

Or run the binary directly:

```
./dist/dodoco
```

By default it reads config from `~/.config/dodoco/config.json` and rules from `~/.config/dodoco/rules.json`.

## Install

```
make install
```

This installs the binary to `~/.local/bin`, copies the default config to `~/.config/dodoco/`, and creates a systemd user service. Enable it with:

```
systemctl --user enable --now dist/dodoco
```

## Configuration

`config.json`:

```json
{
  "addr": ":8080",
  "admin": ":9090",
  "rulesPath": "~/.config/dodoco/rules.json",
  "username": "",
  "password": ""
}
```

| Field     | Description                                      |
|-----------|--------------------------------------------------|
| addr      | Proxy listen address                             |
| admin     | Admin UI listen address (empty to disable)       |
| rulesPath | Path to the rules file                           |
| username  | Proxy authentication username (empty to disable) |
| password  | Proxy authentication password                    |

All fields can be overridden with command-line flags (`-addr`, `-admin`, `-rulesPath`, `-username`, `-password`). Use `-config` to specify a different config file path.

## Rules

`rules.json`:

```json
{
  "rules": {
    "x.com": {
      "targetInterface": "tun0"
    },
    "*.twitter.com": {
      "targetInterface": "tun0",
      "targetDNS": "1.1.1.1"
    }
  }
}
```

Keys are hostname patterns (glob syntax). Each rule can specify:

- `targetInterface` - Network interface to bind outgoing connections to.
- `targetDNS` - DNS server to use for resolving the destination hostname.

Rules are matched by specificity: more specific patterns take priority over wildcards.

## Usage

### Browser

**Firefox**: Settings > General > Network Settings > Manual proxy configuration. Set HTTP Proxy to `127.0.0.1`, port `8080`. Check "Also use this proxy for HTTPS".

**Chromium/Chrome**: Launch the browser using a flag:

```
chromium --proxy-server="http://127.0.0.1:8080"
```

## Big Fat Warning on System-Wide
Setting the proxy system-wide is not recommended. If dodoco goes down, all network traffic will fail. Prefer configuring it per-browser or per-application instead.

That being said, this is how you run your entire system to dodoco:

### Linux

Set the environment variables:

```
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

Add these to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) to make them persistent. Most command-line tools (curl, wget, etc.) and many applications will respect these variables.

If you configured proxy authentication, include the credentials in the URL:

```
export http_proxy=http://user:pass@127.0.0.1:8080
export https_proxy=http://user:pass@127.0.0.1:8080
```

### GNOME

Settings > Network > Network Proxy > Manual. Set HTTP and HTTPS proxy to `127.0.0.1` port `8080`.

### KDE Plasma

System Settings > Network Settings > Proxy > Manual. Set HTTP and HTTPS proxy to `127.0.0.1` port `8080`.

### Windows

Settings > Network & internet > Proxy > Manual proxy setup. Turn on "Use a proxy server", set address to `127.0.0.1` and port to `8080`.

### macOS

System Settings > Network > Wi-Fi (or your active connection) > Details > Proxies. Enable "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)", set both to `127.0.0.1` port `8080`.

## Uninstall

```
make uninstall
```
