#!/usr/bin/env python3

import argparse
import json
import asyncio
import signal
import sys
import logging
import os
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
                full_topic = f"{mqtt_topic}/{address.replace(':', '-')}"
                payload = json.dumps(data)
                client.publish(full_topic, payload, retain=True)
                log(f"[{address}] published to {full_topic}")

            # 3. Wait until the next interval
            log(f"[{name}] Sleeping {interval}s …")
            await asyncio.sleep(interval)

    finally:
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

