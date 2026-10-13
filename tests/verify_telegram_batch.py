#!/usr/bin/env python3
"""Official engine grouping check; only temporary configs and loopback receivers.

Usage: python3 tests/verify_telegram_batch.py /path/to/crowdsec-v1.8.1
"""
import sys
from verify_engine import verify

if __name__ == '__main__':
    verify(sys.argv[1], telegram_delivery='batch')
