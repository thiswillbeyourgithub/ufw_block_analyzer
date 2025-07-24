#!/usr/bin/env python3
"""
UFW Block Analyzer - Continuously monitors journalctl for UFW BLOCK messages.

This script runs journalctl -f with grep to capture UFW BLOCK log entries,
then parses each line using regex to extract key=value pairs and converts
them into a dictionary with title case keys.

Created with assistance from aider.chat
"""

import re
import subprocess
import sys
from typing import Dict, Optional

from loguru import logger


def parse_ufw_block_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parse a UFW BLOCK log line and extract key=value pairs.
    
    Uses regex to find all KEY=VALUE patterns in the line and converts
    keys to title case. This approach handles the variable structure
    of UFW log entries where some fields may be missing or have empty values.
    
    Parameters
    ----------
    line : str
        The UFW BLOCK log line to parse
        
    Returns
    -------
    Dict[str, str] or None
        Dictionary with title case keys and string values, or None if no UFW BLOCK found
    """
    # Only process lines that contain UFW BLOCK
    if "[UFW BLOCK]" not in line:
        return None
    
    # Regex pattern to match KEY=VALUE pairs
    # This captures alphanumeric keys followed by = and values that can contain
    # various characters including colons, dots, slashes, etc.
    pattern = r'([A-Z]+)=([^\s]*)'
    
    matches = re.findall(pattern, line)
    
    if not matches:
        logger.warning(f"No key=value pairs found in line: {line.strip()}")
        return None
    
    # Convert to dictionary with title case keys
    # Title case is used to make the output more readable while preserving
    # the original structure of the UFW log format
    parsed_data = {}
    for key, value in matches:
        parsed_data[key.title()] = value
    
    return parsed_data


def run_ufw_monitor() -> None:
    """
    Continuously monitor journalctl for UFW BLOCK messages.
    
    Uses subprocess.Popen to run journalctl -f piped through grep to filter
    for UFW BLOCK messages. This approach allows real-time processing of
    log entries as they appear in the system journal.
    """
    logger.info("Starting UFW block analyzer...")
    logger.info("Monitoring journalctl for UFW BLOCK messages...")
    
    try:
        # Run journalctl -f | grep 'UFW BLOCK'
        # We use shell=True here to easily chain the commands with pipe
        process = subprocess.Popen(
            "journalctl -f | grep 'UFW BLOCK'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1  # Line buffered for real-time output
        )
        
        logger.info("Successfully started journalctl monitoring")
        
        # Process each line as it comes in
        for line in iter(process.stdout.readline, ''):
            if line:
                parsed_data = parse_ufw_block_line(line.strip())
                if parsed_data:
                    logger.info(f"UFW Block detected: {parsed_data}")
                    print(f"Parsed UFW Block: {parsed_data}")
                
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, stopping monitor...")
        if 'process' in locals():
            process.terminate()
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Error running UFW monitor: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Configure loguru to output to stderr so it doesn't interfere with data output
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    
    run_ufw_monitor()
