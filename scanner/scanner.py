import socket
import ipaddress
import platform
import subprocess
import re
import http.client
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

# Scapy is recommended on Kali/Linux for very fast ARP discovery.
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# =========================================================
# CONFIGURATION
# =========================================================

# Keep the port list small for the Welcome Week exercise.
# The important clue is TCP/80.
COMMON_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8080: "HTTP-alt",
    81: "HTTP",
    23: "TELNET"
}

# Ports used only as a fallback if Scapy/ARP discovery
# is unavailable.
DISCOVERY_PORTS = [
    22, 80, 443, 554, 8080, 23, 81
]


# =========================================================
# NETWORK INFORMATION
# =========================================================

def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # This does not need Internet access. It lets the OS
        # tell us which local interface it would use.
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]

    except Exception:
        return "127.0.0.1"

    finally:
        sock.close()


def get_local_subnet():
    local_ip = get_local_ip()

    return ipaddress.ip_network(
        f"{local_ip}/24",
        strict=False
    )


# =========================================================
# FAST ARP DISCOVERY
# =========================================================

def discover_devices_arp(network):
    """
    Actively asks every IP in the local subnet who is present.

    This is much faster than pinging every host and then
    checking many TCP ports.
    """

    if not SCAPY_AVAILABLE:
        return []

    print("\n" + "=" * 70)
    print("🔎 DISCOVERING DEVICES")
    print("=" * 70)

    print(f"\n[*] Network: {network}")
    print("[*] Sending a fast ARP discovery request...")
    print("[*] Please wait...\n")

    try:
        # Make Scapy use the normal interface.
        conf.verb = 0

        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            pdst=str(network)
        )

        answered, _ = srp(
            request,
            timeout=2,
            verbose=False
        )

        devices = []

        for _, received in answered:

            ip = received.psrc
            mac = received.hwsrc.upper()

            devices.append({
                "ip": ip,
                "mac": mac
            })

        devices.sort(
            key=lambda x: ipaddress.ip_address(x["ip"])
        )

        for device in devices:
            print(
                f"[+] Device found: "
                f"{device['ip']}    "
                f"{device['mac']}"
            )

        return devices

    except Exception as error:

        print(
            f"\n[!] ARP discovery failed: {error}"
        )

        return []


# =========================================================
# FAST FALLBACK DISCOVERY
# =========================================================

def ping_host(ip):

    system = platform.system().lower()

    if system == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            "300",
            str(ip)
        ]
    else:
        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            str(ip)
        ]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )

        return result.returncode == 0

    except Exception:
        return False


def tcp_probe(ip, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.25)

    try:
        return sock.connect_ex(
            (str(ip), port)
        ) == 0

    except Exception:
        return False

    finally:
        sock.close()


def host_is_alive(ip):

    if ping_host(ip):
        return True

    for port in DISCOVERY_PORTS:
        if tcp_probe(ip, port):
            return True

    return False


def discover_devices_fallback(network):

    print("\n" + "=" * 70)
    print("🔎 DISCOVERING DEVICES")
    print("=" * 70)

    print(f"\n[*] Network: {network}")
    print("[*] ARP discovery is unavailable.")
    print("[*] Using quick ICMP/TCP fallback...\n")

    devices = []

    hosts = list(network.hosts())

    with ThreadPoolExecutor(max_workers=100) as executor:

        futures = {
            executor.submit(
                host_is_alive,
                ip
            ): ip
            for ip in hosts
        }

        for future in as_completed(futures):

            ip = futures[future]

            try:
                if future.result():

                    devices.append({
                        "ip": str(ip),
                        "mac": "Unknown"
                    })

                    print(
                        f"[+] Device found: {ip}"
                    )

            except Exception:
                pass

    devices.sort(
        key=lambda x: ipaddress.ip_address(x["ip"])
    )

    return devices


def discover_devices(network):

    # Preferred path: active ARP sweep.
    if SCAPY_AVAILABLE:

        devices = discover_devices_arp(network)

        if devices:
            return devices

    # Fallback if Scapy is unavailable or ARP fails.
    return discover_devices_fallback(network)


# =========================================================
# HOSTNAME
# =========================================================

def get_hostname(ip):

    try:
        hostname = socket.gethostbyaddr(ip)[0]

        if hostname and hostname != ip:
            return hostname

    except Exception:
        pass

    return "Unknown"


# =========================================================
# MAC ADDRESS
# =========================================================

def get_mac_address(ip):

    # If ARP discovery already supplied a MAC, use that.
    try:
        result = subprocess.run(
            [
                "ip",
                "neigh",
                "show",
                ip
            ],
            capture_output=True,
            text=True,
            timeout=1
        )

        match = re.search(
            r"lladdr\s+([0-9a-fA-F:]{17})",
            result.stdout
        )

        if match:
            return match.group(1).upper()

    except Exception:
        pass

    # Linux ARP table fallback.
    try:
        with open("/proc/net/arp", "r") as arp_file:

            for line in arp_file.readlines()[1:]:

                fields = line.split()

                if len(fields) >= 4:

                    arp_ip = fields[0]
                    mac = fields[3]

                    if arp_ip == ip and mac != "00:00:00:00:00:00":
                        return mac.upper()

    except Exception:
        pass

    # Windows fallback.
    try:
        result = subprocess.run(
            [
                "arp",
                "-a",
                ip
            ],
            capture_output=True,
            text=True,
            timeout=1
        )

        match = re.search(
            r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})",
            result.stdout
        )

        if match:
            return match.group(1).replace(
                "-",
                ":"
            ).upper()

    except Exception:
        pass

    return "Unknown"


# =========================================================
# MAC VENDORS
# =========================================================

MAC_VENDORS = {
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",

    "00000C": "Cisco",
    "001B54": "Cisco",
    "0022BD": "Cisco",
    "001C58": "Cisco",
    "00260B": "Cisco",

    "000C29": "VMware",
    "005056": "VMware",

    "080027": "VirtualBox",

    "00155D": "Microsoft",
    "001DD8": "Microsoft",

    "001B21": "Intel",
    "001C23": "Intel",
    "3C970E": "Intel",

    "50C7BF": "TP-Link",
    "C0A0BB": "TP-Link",

    "00223F": "Netgear",
    "A00460": "Netgear",

    "001C42": "Apple",
    "3C0754": "Apple",
}


def get_vendor(mac):

    if mac == "Unknown":
        return "Unknown"

    compact = (
        mac
        .replace(":", "")
        .replace("-", "")
        .upper()
    )

    return MAC_VENDORS.get(
        compact[:6],
        "Unknown"
    )


# =========================================================
# DEVICE TYPE
# =========================================================

def identify_device_type(
    vendor,
    hostname,
    open_ports=None,
    services=None
):

    open_ports = open_ports or []
    services = services or []

    hostname_lower = hostname.lower()

    if vendor == "Cisco":
        return "Network device"

    if 554 in open_ports:
        return "Possible IP camera"

    for service in services:

        details = service["details"].lower()

        for keyword in [
            "camera",
            "ipcam",
            "surveillance",
            "dvr",
            "nvr",
            "video"
        ]:

            if keyword in details:
                return "Possible IP camera"

    if 80 in open_ports or 8080 in open_ports:
        return "Web-enabled device"

    if 22 in open_ports:
        return "Linux / network device"

    if (
        "router" in hostname_lower
        or "gateway" in hostname_lower
    ):
        return "Router / gateway"

    return "Unknown"


# =========================================================
# ENRICH DEVICES
# =========================================================

def enrich_devices(devices):

    for device in devices:

        ip = device["ip"]

        if device.get("mac") == "Unknown":
            device["mac"] = get_mac_address(ip)

        device["hostname"] = get_hostname(ip)

        device["vendor"] = get_vendor(
            device["mac"]
        )

        device["device_type"] = identify_device_type(
            device["vendor"],
            device["hostname"]
        )

    return devices


# =========================================================
# DISPLAY DEVICES
# =========================================================

def print_devices(devices):

    print("\n")

    print("=" * 105)

    print(
        f"{'#':<5}"
        f"{'IP ADDRESS':<18}"
        f"{'MAC ADDRESS':<20}"
        f"{'VENDOR':<18}"
        f"{'DEVICE':<25}"
    )

    print("=" * 105)

    for number, device in enumerate(
        devices,
        start=1
    ):

        print(
            f"{number:<5}"
            f"{device['ip']:<18}"
            f"{device['mac']:<20}"
            f"{device['vendor']:<18}"
            f"{device['device_type']:<25}"
        )

    print("=" * 105)


# =========================================================
# PORT SCANNING
# =========================================================

def scan_port(ip, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(0.35)

    try:

        if sock.connect_ex(
            (ip, port)
        ) == 0:

            return port

    except Exception:
        pass

    finally:
        sock.close()

    return None


def scan_ports(ip):

    print(
        f"\n[*] Checking selected device: {ip}"
    )

    print(
        "[*] Checking common services..."
    )

    open_ports = []

    with ThreadPoolExecutor(
        max_workers=len(COMMON_PORTS)
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                ip,
                port
            ): port
            for port in COMMON_PORTS
        }

        for future in as_completed(futures):

            try:

                result = future.result()

                if result is not None:
                    open_ports.append(result)

            except Exception:
                pass

    return sorted(open_ports)


# =========================================================
# HTTP IDENTIFICATION
# =========================================================

def get_http_info(ip, port):

    try:

        connection = http.client.HTTPConnection(
            ip,
            port=port,
            timeout=1.5
        )

        connection.request(
            "GET",
            "/"
        )

        response = connection.getresponse()

        server = response.getheader(
            "Server"
        )

        body = response.read(
            32768
        )

        connection.close()

        title = "Unknown"

        text = body.decode(
            "utf-8",
            errors="ignore"
        )

        match = re.search(
            r"<title[^>]*>(.*?)</title>",
            text,
            re.IGNORECASE | re.DOTALL
        )

        if match:

            title = re.sub(
                r"\s+",
                " ",
                match.group(1)
            ).strip()

        return {
            "server": server or "Unknown",
            "title": title
        }

    except Exception:
        return None


# =========================================================
# SSH
# =========================================================

def get_ssh_banner(ip):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(1.5)

    try:

        sock.connect(
            (ip, 22)
        )

        return sock.recv(
            1024
        ).decode(
            "utf-8",
            errors="ignore"
        ).strip()

    except Exception:
        return None

    finally:
        sock.close()


# =========================================================
# RTSP
# =========================================================

def check_rtsp(ip):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(1.5)

    try:

        sock.connect(
            (ip, 554)
        )

        request = (
            f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            "\r\n"
        )

        sock.sendall(
            request.encode()
        )

        response = sock.recv(
            2048
        ).decode(
            "utf-8",
            errors="ignore"
        )

        return "RTSP/" in response

    except Exception:
        return False

    finally:
        sock.close()


# =========================================================
# SERVICE IDENTIFICATION
# =========================================================

def identify_services(
    ip,
    open_ports
):

    services = []

    for port in open_ports:

        if port in [80, 443, 8080]:

            info = get_http_info(
                ip,
                port
            )

            if info:

                services.append({
                    "port": port,
                    "service": "HTTP",
                    "details":
                        f"Server={info['server']} | "
                        f"Title={info['title']}"
                })

        elif port == 22:

            banner = get_ssh_banner(
                ip
            )

            services.append({
                "port": 22,
                "service": "SSH",
                "details":
                    banner or "SSH service detected"
            })

        elif port == 554:

            services.append({
                "port": 554,
                "service": "RTSP",
                "details":
                    "RTSP response detected"
                    if check_rtsp(ip)
                    else "TCP/554 open"
            })

    return services


# =========================================================
# DISPLAY PORTS
# =========================================================

def print_ports(open_ports):

    print("\n")

    print("=" * 55)

    print(
        f"{'PORT':<10}"
        f"{'STATE':<12}"
        f"{'SERVICE':<25}"
    )

    print("=" * 55)

    for port in open_ports:

        print(
            f"{port:<10}"
            f"{'OPEN':<12}"
            f"{COMMON_PORTS.get(port, 'Unknown'):<25}"
        )

    print("=" * 55)


# =========================================================
# DISPLAY SERVICE DETAILS
# =========================================================

def print_service_details(services):

    if not services:
        return

    print("\n")

    print("=" * 80)

    print(
        f"{'PORT':<10}"
        f"{'SERVICE':<15}"
        f"{'DETAILS':<55}"
    )

    print("=" * 80)

    for service in services:

        print(
            f"{service['port']:<10}"
            f"{service['service']:<15}"
            f"{service['details']:<55}"
        )

    print("=" * 80)


# =========================================================
# CAMERA WEB CLUE
# =========================================================

def show_web_clue(
    target_ip,
    open_ports
):

    if 80 not in open_ports:
        return

    url = f"http://{target_ip}/"

    print("\n")

    print("=" * 70)
    print("💡 CLUE")
    print("=" * 70)

    print(
        "Port 80 is OPEN."
    )

    print(
        "Port 80 commonly provides a web service."
    )

    print(
        "\nOpen the camera's web page:"
    )

    # OSC 8 creates a clickable terminal link in
    # terminals that support it.
    clickable = (
        f"\033]8;;{url}\033\\"
        f"🌐 {url}"
        f"\033]8;;\033\\"
    )

    print(clickable)

    print(
        "\n[Tip] Click the link above."
    )

    print("=" * 70)


# =========================================================
# SELECTED DEVICE
# =========================================================

def investigate_device(target):

    target_ip = target["ip"]

    print("\n")

    print("=" * 70)
    print("🎯 SELECTED DEVICE")
    print("=" * 70)

    print(
        f"IP Address : {target_ip}"
    )

    print(
        f"MAC Address: {target.get('mac', 'Unknown')}"
    )

    print(
        f"Vendor     : {target.get('vendor', 'Unknown')}"
    )

    print("=" * 70)

    # -----------------------------------------------------
    # PORTS
    # -----------------------------------------------------

    open_ports = scan_ports(
        target_ip
    )

    if not open_ports:

        print(
            "\n[!] No open services found."
        )

        return

    print_ports(
        open_ports
    )

    # -----------------------------------------------------
    # SERVICES
    # -----------------------------------------------------

    services = identify_services(
        target_ip,
        open_ports
    )

    print_service_details(
        services
    )

    # -----------------------------------------------------
    # DEVICE ASSESSMENT
    # -----------------------------------------------------

    device_type = identify_device_type(
        target.get("vendor", "Unknown"),
        target.get("hostname", "Unknown"),
        open_ports,
        services
    )

    print("\n")

    print("=" * 70)

    print(
        f"DEVICE ASSESSMENT: {device_type}"
    )

    print("=" * 70)

    # -----------------------------------------------------
    # PORT 80 CLUE
    # -----------------------------------------------------

    show_web_clue(
        target_ip,
        open_ports
    )

    print(
        "\n[+] Investigation complete."
    )


# =========================================================
# START SCREEN
# =========================================================

def show_start_screen():

    print("\n")

    print("=" * 70)

    print(
        "              🔐 CYBERSECURITY LAB"
    )

    print("=" * 70)

    print(
        "\nYou are the cybersecurity consultant."
    )

    print(
        "Your first task is to discover the devices"
    )

    print(
        "on the isolated lab network."
    )

    print("\n")

    print(
        "Press ENTER to start scanning."
    )

    print(
        "Type Q to quit."
    )

    print("=" * 70)


# =========================================================
# MAIN LOOP
# =========================================================

def main():

    while True:

        show_start_screen()

        choice = input(
            "\n> "
        ).strip().lower()

        if choice == "q":

            print(
                "\nGoodbye!"
            )

            break

        # -------------------------------------------------
        # NETWORK
        # -------------------------------------------------

        network = get_local_subnet()

        print(
            f"\n[+] Local network detected: {network}"
        )

        # -------------------------------------------------
        # FAST DISCOVERY
        # -------------------------------------------------

        devices = discover_devices(
            network
        )

        if not devices:

            print(
                "\n[!] No active devices found."
            )

            input(
                "\nPress ENTER to return..."
            )

            continue

        print(
            f"\n[+] Found {len(devices)} device(s)."
        )

        # -------------------------------------------------
        # DEVICE INFORMATION
        # -------------------------------------------------

        devices = enrich_devices(
            devices
        )

        print_devices(
            devices
        )

        # -------------------------------------------------
        # SELECT TARGET
        # -------------------------------------------------

        while True:

            selection = input(
                "\nSelect a device number "
                "(Q to cancel): "
            ).strip().lower()

            if selection == "q":
                break

            try:

                number = int(
                    selection
                )

                if not (
                    1
                    <= number
                    <= len(devices)
                ):

                    print(
                        "[!] Invalid device number."
                    )

                    continue

                target = devices[
                    number - 1
                ]

                investigate_device(
                    target
                )

                break

            except ValueError:

                print(
                    "[!] Please enter a number."
                )

        # -------------------------------------------------
        # LOOP
        # -------------------------------------------------

        print("\n")

        print("=" * 70)

        print(
            "🔄 READY FOR ANOTHER SCAN"
        )

        print("=" * 70)

        print(
            "Press ENTER to scan again."
        )

        print(
            "Type Q to quit."
        )

        choice = input(
            "\n> "
        ).strip().lower()

        if choice == "q":

            print(
                "\nGoodbye!"
            )

            break


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()
