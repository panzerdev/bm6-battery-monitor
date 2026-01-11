#!/usr/bin/env python3

import argparse
import json
import asyncio
import signal
import sys
import logging
import os
import socket
import platform
import time
from Crypto.Cipher import AES
from bleak import BleakClient, BleakScanner
import paho.mqtt.client as mqtt
import bluetooth_auto_recovery

bluetooth_mac = os.environ.get('BLUETOOTH_MAC', None)

# Setup logging to include timestamps
logging.basicConfig(
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.info


def get_local_ip():
    """Get the actual local IP address (not 127.0.0.1)."""
    try:
        # Method 1: Connect to a remote address to see which local IP is used
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        pass
    
    try:
        # Method 2: Try to parse ip route output (Linux)
        import subprocess
        result = subprocess.run(['ip', 'route', 'get', '1.1.1.1'], 
                              capture_output=True, text=True, check=True)
        for line in result.stdout.split('\n'):
            if 'src' in line:
                return line.split('src')[1].split()[0]
    except:
        pass
    
    try:
        # Method 3: Try to get from hostname resolution to external DNS
        hostname = socket.gethostname()
        # Get all addresses for this hostname
        addresses = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for addr in addresses:
            ip = addr[4][0]
            if not ip.startswith('127.'):
                return ip
    except:
        pass
    
    return "unknown"


def get_host_info():
    """Get information about the host system."""
    try:
        hostname = socket.gethostname()
    except:
        hostname = "unknown"
        
    local_ip = get_local_ip()
    
    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "platform": platform.system(),
        "platform_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "bluetooth_mac": bluetooth_mac,
        "startup_time": int(time.time()),
        "status": "online"
    }


async def publish_startup_info(client, mqtt_topic):
    """Publish host information and online status on startup."""
    host_info = get_host_info()
    
    # Publish host info to a dedicated topic
    host_topic = f"{mqtt_topic}/host"
    host_payload = json.dumps(host_info, indent=2)
    client.publish(host_topic, host_payload, retain=True)
    log(f"Published host information to {host_topic}")
    
    # Publish online status
    status_topic = f"{mqtt_topic}/status"
    status_payload = json.dumps({
        "status": "online",
        "timestamp": int(time.time()),
        "hostname": host_info["hostname"]
    })
    client.publish(status_topic, status_payload, retain=True)
    log(f"Published online status to {status_topic}")


async def scan_bm6_devices(name: str, timeout: int):
    """Return a list of (address, rssi) tuples for devices whose name matches *name*."""
    devices = []
    scan = await BleakScanner.discover(return_adv=True, timeout=timeout)
    for dev, adv in scan.values():
        if dev.name == name:
            log(f"Found device with name {dev.name}: {dev.address} (RSSI: {adv.rssi} dBm)")
            devices.append((dev.address, adv.rssi))
    return devices


async def fetch_bm6_data(address: str):
    log(f"Getting data for {address} …")
    
    key = bytearray([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])
    bm6_data = {"voltage": None, "temperature": None, "soc": None}

    def decrypt(crypted):
        cipher = AES.new(key, AES.MODE_CBC, 16 * b'\0')
        return cipher.decrypt(crypted).hex()

    def encrypt(plaintext):
        cipher = AES.new(key, AES.MODE_CBC, 16 * b'\0')
        return cipher.encrypt(plaintext)

    async def notification_handler(sender, data):
        msg = decrypt(data)
        if msg[0:6] == "d15507":
            bm6_data["voltage"] = int(msg[15:18], 16) / 100
            bm6_data["soc"] = int(msg[12:14], 16)
            if msg[6:8] == "01":
                bm6_data["temperature"] = -int(msg[8:10], 16)
            else:
                bm6_data["temperature"] = int(msg[8:10], 16)

    async with BleakClient(address, timeout=30) as client:
        await client.write_gatt_char(
            "FFF3",
            encrypt(bytearray.fromhex("d1550700000000000000000000000000")),
            response=True,
        )
        await client.start_notify("FFF4", notification_handler)

            # Helper coroutine for waiting on data
        async def _wait_for_data(bm6_data):
            while bm6_data["voltage"] is None and bm6_data["temperature"] is None:
                await asyncio.sleep(0.1)
            await client.stop_notify("FFF4")

        # wait until we get a voltage OR temperature – this is the same logic
        # that the original get_bm6_data() used
        # Wait for data, but add a timeout to avoid hanging forever
        try:
            await asyncio.wait_for(
            _wait_for_data(bm6_data),
            timeout=5  # seconds
            )
        except asyncio.TimeoutError:
            log(f"Timeout waiting for data from {address}")


    return bm6_data


async def monitor_loop(name, interval, mqtt_host, mqtt_topic, timeout):
    """The main loop that does the scanning + publishing."""
    # Create a single MQTT client that stays alive for the life of the loop
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(mqtt_host)
    client.loop_start()          # run network loop in a background thread

    # Publish startup information
    await publish_startup_info(client, mqtt_topic)

    try:
        while True:
            log(f"[{name}] Scanning for devices …")
            # 1. Scan for all devices with the given name
            try:
                devices = await scan_bm6_devices(name, timeout)
            except Exception as exc:
                log(f"[{name}] error scanning for devices: {exc}")
                await bluetooth_auto_recovery.recover_adapter(hci=0, mac=bluetooth_mac)
                await asyncio.sleep(interval)
                continue

            # Publish scan results (without retain flag)
            scan_topic = f"{mqtt_topic}/scan"
            scan_payload = json.dumps({
                "timestamp": int(asyncio.get_event_loop().time()),
                "devices_found": len(devices),
                "devices": [{"address": addr, "rssi": rssi} for addr, rssi in devices]
            })
            client.publish(scan_topic, scan_payload, retain=False)
            log(f"[{name}] published scan results to {scan_topic}: {len(devices)} devices found")

            if not devices:
                log(f"[{name}] No devices found – sleeping {interval}s …")
                await asyncio.sleep(interval)
                continue

            # 2. Read each device and publish
            for address, rssi in devices:
                try:
                    data = await fetch_bm6_data(address)
                except Exception as exc:
                    log(f"[{address}] error reading data: {exc}")
                    await bluetooth_auto_recovery.recover_adapter(hci=0, mac=bluetooth_mac)
                    await asyncio.sleep(interval)
                    continue

                # Compose topic and payload
                full_topic = f"{mqtt_topic}/devices/{address.replace(':', '-')}"
                payload = json.dumps(data)
                client.publish(full_topic, payload, retain=True)
                log(f"[{address}] published to {full_topic}")

            # 3. Wait until the next interval
            log(f"[{name}] Sleeping {interval}s …")
            await asyncio.sleep(interval)

    finally:
        # Publish offline status before disconnecting
        status_topic = f"{mqtt_topic}/status"
        offline_payload = json.dumps({
            "status": "offline",
            "timestamp": int(time.time()),
            "hostname": get_host_info()["hostname"]
        })
        client.publish(status_topic, offline_payload, retain=True)
        log("Published offline status")
        
        client.loop_stop()
        client.disconnect()


# ----------------------------------------------------------------------
# Argument parser – extend with a new "monitor" sub‑command
# ----------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--format",
        choices=["ascii", "json"],
        default="ascii",
        help="Output format for --scan / --address",
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--address", metavar="<address>", help="Address of BM6 to poll data from")
    group.add_argument("--scan", action="store_true", help="Scan for available BM6 devices")
    # --------- new sub‑command -----------------------------------------
    monitor = parser.add_argument_group("monitoring")
    monitor.add_argument("--monitor", action="store_true", help="Start a periodic MQTT monitor loop")
    monitor.add_argument("--name", metavar="<name>", help="BLE name to match (e.g. 'BM6')")
    monitor.add_argument("--interval", type=int, default=30, help="Polling interval in seconds")
    monitor.add_argument("--mqtt-host", metavar="<host>", help="MQTT broker host")
    monitor.add_argument("--mqtt-topic", metavar="<topic>", help="Base MQTT topic")
    monitor.add_argument("--scan_timeout", type=int, default=15, help="BLE scan timeout in seconds")
    return parser


# ----------------------------------------------------------------------
# Main entry point – dispatch to the appropriate mode
# ----------------------------------------------------------------------
if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    
    if args.address:
        try:
            data =  asyncio.run(fetch_bm6_data(args.address))
            print(json.dumps(data) if args.format == "json" else data)
        except Exception as exc:
            log(f"Error fetching address: {exc}")
            asyncio.run(bluetooth_auto_recovery.recover_adapter(hci=0, mac=bluetooth_mac))

    elif args.scan:
        try:
            data = asyncio.run(scan_bm6_devices(args.name, timeout=args.scan_timeout))
            print(json.dumps(data) if args.format == "json" else data)
        except Exception as exc:
            log(f"Error scanning: {exc}")
            asyncio.run(bluetooth_auto_recovery.recover_adapter(hci=0, mac=bluetooth_mac))

    elif args.monitor:
        # Basic validation
        if not args.name or not args.mqtt_host or not args.mqtt_topic:
            print("Error: --monitor requires --name, --mqtt-host and --mqtt-topic")
            sys.exit(1)

        # Graceful shutdown on Ctrl‑C
        def _signal_handler(sig, frame):
            log("\nStopping monitor…")
            sys.exit(0)
        signal.signal(signal.SIGINT, _signal_handler)

        try:
            asyncio.run(
                monitor_loop(
                    name=args.name,
                    interval=args.interval,
                    mqtt_host=args.mqtt_host,
                    mqtt_topic=args.mqtt_topic,
                    timeout=args.scan_timeout,
                )
            )
        except Exception as exc:
            log(f"Monitoring loop failed: {exc}")

