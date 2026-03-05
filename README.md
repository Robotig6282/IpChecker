# IpChecker

A minimal Minecraft server that displays client IP addresses.

## Usage

```bash
./ipchecker                    # Quiet mode (default)
./ipchecker -debug             # Verbose logging
./ipchecker -motd-ip-show      # Show client IP in MOTD
./ipchecker -icon=server-icon.png # Server list icon (64x64 PNG)
./ipchecker -icon=""           # Disable icon
./ipchecker -port=25566        # Custom port
./ipchecker -v                 # Show version
```

Place a valid 64x64 PNG at `server-icon.png` (or pass another path via `-icon`) to show a custom server icon in the Minecraft server list.

## How it works

1. Listens on TCP port 25565 (configurable)
2. Parses Minecraft handshake packets to extract protocol version
3. Handles status requests (server list pings)
4. Disconnects login attempts with the client's IP address and protocol version

## Build

```bash
go build -o ipchecker main.go
```

## Online

Hosted at: `ipchecker.robotig.xyz`
