# UFW Block Analyzer

A real-time UFW firewall log analyzer that monitors blocked connections and enriches them with Docker network context.

This tool continuously monitors `journalctl` for UFW BLOCK messages, parses the log entries, and provides structured output with Docker network information when applicable. It's particularly useful for understanding which Docker containers or projects are being blocked by your firewall rules.

## Features

- **Real-time monitoring**: Uses `journalctl -f` to capture UFW BLOCK messages as they happen
- **Docker network enrichment**: Automatically identifies Docker bridge interfaces and maps them to Docker Compose projects
- **Structured output**: Converts UFW log entries into clean TOML format
- **Filtered data**: Removes unnecessary technical fields to focus on relevant information
- **Comprehensive logging**: Includes both console output and rotating log files
- **Verbose mode**: Optional detailed output for debugging

## Installation

### Dependencies

Install the required Python packages:

```bash
pip install click loguru rtoml
```

### System Requirements

- Python 3.6+
- `journalctl` access (usually requires sudo or appropriate permissions)
- Docker (optional, for Docker network enrichment)
- UFW firewall with logging enabled

## Usage

### Basic Usage

Monitor UFW blocks in real-time:

```bash
sudo python3 ufw_block_analyzer.py
```

### Verbose Mode

See all captured log lines:

```bash
sudo python3 ufw_block_analyzer.py --verbose
```

### Make Executable

For easier usage, make the script executable:

```bash
chmod +x ufw_block_analyzer.py
sudo ./ufw_block_analyzer.py
```

## Output Format

The tool outputs blocked connections in TOML format. Here's an example:

```toml
src = 192.168.1.100
dst = 10.0.0.5
spt = 45678
dpt = 80
proto = tcp
in = br-abc123def456
out = eth0
docker_project = myapp
docker_network = myapp_default
```

### Key Fields

- `src/dst`: Source and destination IP addresses
- `spt/dpt`: Source and destination ports
- `proto`: Protocol (tcp, udp, etc.)
- `in/out`: Network interfaces involved
- `docker_project`: Docker Compose project name (if applicable)
- `docker_network`: Docker network name (if applicable)

For non-Docker traffic, `docker_project` and `docker_network` will be set to `"not_docker"`.

## Docker Network Detection

The tool automatically detects Docker bridge interfaces (those starting with `br-`) and matches them to Docker networks using:

```bash
docker network ls --format json
```

It extracts Docker Compose project names from network labels, providing context about which containerized applications are being blocked.

## Logging

The tool creates two types of logs:

1. **Console output**: INFO level messages to stderr
2. **Log file**: DEBUG level messages to `ufw_block_analyzer.log` (next to the script)
   - Rotates at 10 MB
   - Keeps 7 days of logs

## UFW Configuration

Ensure UFW logging is enabled to capture block events:

```bash
sudo ufw logging on
```

You can adjust the logging level if needed:

```bash
sudo ufw logging medium  # or low, high, full
```

## Permissions

The script requires elevated privileges to:
- Read system logs via `journalctl`
- Query Docker networks via `docker network ls`

Run with `sudo` or ensure your user has appropriate permissions for these operations.

## Troubleshooting

### No Output Appearing

1. Check that UFW logging is enabled: `sudo ufw status verbose`
2. Verify UFW is actually blocking traffic by checking logs manually: `sudo journalctl -f | grep UFW`
3. Ensure the script has proper permissions to read system logs

### Docker Networks Not Detected

1. Verify Docker is running: `sudo docker ps`
2. Check Docker network access: `sudo docker network ls`
3. Ensure the user running the script can execute Docker commands

## Development

This project was created with assistance from [aider.chat](https://github.com/Aider-AI/aider/).

### Code Structure

- `get_docker_networks()`: Queries Docker for network information
- `parse_ufw_block_line()`: Parses UFW log entries using regex
- `run_ufw_monitor()`: Main monitoring loop using journalctl
- `main()`: CLI entry point with click

### Contributing

The code uses:
- Type hints throughout for better maintainability
- Comprehensive docstrings in NumPy style
- Keyword arguments preferred over positional arguments
- Robust error handling and logging
