#!/usr/bin/env python3
"""
UFW Block Analyzer - Continuously monitors journalctl for UFW BLOCK messages.

This script runs journalctl -f with grep to capture UFW BLOCK log entries,
then parses each line using regex to extract key=value pairs and converts
them into a dictionary with title case keys.

Created with assistance from aider.chat
"""

import json
import re
import subprocess
import sys
from typing import Dict, Optional

import click
import rtoml
from loguru import logger


def get_docker_networks() -> Dict[str, Dict[str, str]]:
    """
    Get Docker network information using 'docker network ls --format json'.

    Returns a dictionary mapping network ID prefixes to network metadata
    including project names extracted from Docker Compose labels.

    Returns
    -------
    Dict[str, Dict[str, str]]
        Dictionary mapping network ID prefixes to network info
    """
    try:
        result = subprocess.run(
            ["sudo", "docker", "network", "ls", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )

        networks = {}
        for line in result.stdout.strip().split("\n"):
            if line:
                network = json.loads(line)
                network_id = network.get("ID", "")
                # Use first 12 characters of network ID for matching
                network_prefix = network_id[:12]

                # Extract project name from Docker Compose labels
                labels = network.get("Labels", "")
                project_name = "unknown"
                if labels:
                    for label in labels.split(","):
                        if label.startswith("com.docker.compose.project="):
                            project_name = label.split("=", 1)[1]
                            break

                networks[network_prefix] = {
                    "name": network.get("Name", "unknown"),
                    "project": project_name,
                    "id": network_id,
                }

        logger.info(f"Loaded {len(networks)} Docker networks")
        return networks

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get Docker networks: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error parsing Docker networks: {e}")
        return {}


def parse_ufw_block_line(
    line: str, docker_networks: Dict[str, Dict[str, str]]
) -> Optional[Dict[str, str]]:
    """
    Parse a UFW BLOCK log line and extract key=value pairs with Docker network info.

    Uses regex to find all KEY=VALUE patterns in the line and converts
    keys to lowercase. Matches interface names to Docker networks and
    adds project information. Removes unnecessary technical fields.

    Parameters
    ----------
    line : str
        The UFW BLOCK log line to parse
    docker_networks : Dict[str, Dict[str, str]]
        Dictionary mapping network ID prefixes to network metadata

    Returns
    -------
    Dict[str, str] or None
        Dictionary with lowercase keys and string values, or None if no UFW BLOCK found
    """
    # Only process lines that contain UFW BLOCK
    if "[UFW BLOCK]" not in line:
        return None

    # Regex pattern to match KEY=VALUE pairs
    pattern = r"([A-Z]+)=([^\s]*)"
    matches = re.findall(pattern, line)

    if not matches:
        logger.warning(f"No key=value pairs found in line: {line.strip()}")
        return None

    # Convert to dictionary with lowercase keys
    parsed_data = {}
    for key, value in matches:
        parsed_data[key.lower()] = value

    # Match interface to Docker network and add project info
    interface = parsed_data.get("in") or parsed_data.get("out", "")
    if interface.startswith("br-"):
        network_id = interface[3:]  # Remove 'br-' prefix
        for net_prefix, net_info in docker_networks.items():
            if network_id.startswith(net_prefix):
                parsed_data["DockerProject"] = net_info["project"]
                parsed_data["DockerNetwork"] = net_info["name"]
                break
        else:
            parsed_data["DockerProject"] = "unknown"
            parsed_data["DockerNetwork"] = "unknown"

    # Remove unwanted technical fields
    keys_to_remove = ["len", "tos", "prec", "id", "ttl", "window", "res", "urgp"]
    for key in keys_to_remove:
        parsed_data.pop(key, None)

    return parsed_data


def run_ufw_monitor(verbose: bool, docker_networks: Dict[str, Dict[str, str]]) -> None:
    """
    Continuously monitor journalctl for UFW BLOCK messages.

    Uses subprocess.Popen to run journalctl -f to monitor UFW BLOCK messages.
    Enriches each blocked connection with Docker network information.

    Parameters
    ----------
    verbose : bool
        Whether to print captured lines
    docker_networks : Dict[str, Dict[str, str]]
        Dictionary mapping network ID prefixes to network metadata
    """
    logger.info("Starting UFW block analyzer...")
    logger.info("Monitoring journalctl for UFW BLOCK messages...")

    try:
        # Run journalctl -f
        # We use shell=True here to easily chain the commands with pipe
        process = subprocess.Popen(
            "journalctl -f",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,  # Line buffered for real-time output
        )

        logger.info("Successfully started journalctl monitoring")

        # Process each line as it comes in
        for line in iter(process.stdout.readline, ""):
            if line:
                if verbose:
                    print(f"Captured line: {line.strip()}")

                parsed_data = parse_ufw_block_line(line.strip(), docker_networks)
                if parsed_data:
                    formatted_output = rtoml.dumps(parsed_data)
                    logger.info(f"UFW Block detected:\n{formatted_output}")

    except KeyboardInterrupt:
        logger.info("Received interrupt signal, stopping monitor...")
        if "process" in locals():
            process.terminate()
        sys.exit(0)

    except Exception as e:
        logger.error(f"Error running UFW monitor: {e}")
        sys.exit(1)


@click.command()
@click.option("--verbose", is_flag=True, help="Print captured lines")
def main(verbose: bool) -> None:
    """UFW Block Analyzer - Monitor and analyze UFW BLOCK messages with Docker context."""
    # Configure loguru to output to stderr so it doesn't interfere with data output
    logger.remove()
    logger.add(sys.stderr, level="INFO")

    # Get Docker networks once at startup
    docker_networks = get_docker_networks()

    run_ufw_monitor(verbose=verbose, docker_networks=docker_networks)


if __name__ == "__main__":
    main()
