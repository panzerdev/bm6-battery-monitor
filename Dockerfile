# -------------------------------------------------------------
#  bm6‑battery‑monitor – Docker image
#
#  This image contains all runtime dependencies for the
#  script you posted (Bleak, python‑cryptodome, paho‑mqtt)
#  plus the native libraries required for BLE on Linux.
#
#  Build:
#      docker build -t bm6-monitor .
#
#  Run (example):
#      docker run --rm -it --net=host \
#          -v "$(pwd):/app" \
#          bm6-monitor \
#          --monitor --name BM6 --interval 30 --mqtt-host 127.0.0.1 --mqtt-topic ble/battery
#
#  The container runs the script with whatever arguments you
#  supply on the command line.  The `--net=host` is recommended
#  for BLE access (or you can expose the required devices
#  explicitly).  If you do not need host networking, use
#  `--privileged` instead – see the documentation for Bleak.
# -------------------------------------------------------------

# Use a slim Debian base – smaller image, still has apt.
FROM python:3

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Install the system dependencies required by Bleak and
# the Python runtime.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        libudev-dev \
        libdbus-1-dev \
        libglib2.0-dev \
        libbluetooth-dev \
	bluez \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy the Python script into the image
COPY requirements.txt /app/

RUN pip install -r requirements.txt

COPY bm6.py /app/

# Export an environment variable so the Python output is not
# buffered – useful for logs that are read in real time.
ENV PYTHONUNBUFFERED=1

# Default command – the script itself.  Any arguments you
# pass on `docker run` will be appended automatically.
ENTRYPOINT ["python3", "/app/bm6.py"]


