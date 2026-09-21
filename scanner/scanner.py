
import socket
import os
import ipaddress
import platform
import subprocess
import re
import http.client
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional fast ARP discovery on Kali/Linux.
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# TERMINAL COLOURS

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def paint(text, colour):
    return f"{colour}{text}{C.RESET}"


def header(title):
    print("\n" + paint("=" * 72, C.BLUE))
    print(paint(f"{title:^72}", C.BOLD + C.CYAN))
    print(paint("=" * 72, C.BLUE))


def msg(prefix, text, colour=C.WHITE):
    print(f"{paint(prefix, C.BOLD + colour)} {text}")

# LAB CONFIGURATION

# IMPORTANT LAB PORTS:
# TCP/23 = Telnet
# TCP/81 = camera web interface
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    80: "HTTP",
    81: "HTTP - CAMERA WEB",
    443: "HTTPS",
    554: "RTSP",
    8080: "HTTP-alt",
}

DISCOVERY_PORTS = list(COMMON_PORTS)

# Known devices in the Welcome Week lab.
# These names make the discovery stage easier for beginners to understand.
KNOWN_DEVICES = {
    "192.168.0.1": "SCA_Router",
    "192.168.0.101": "SCA_Cisco_Switch",
    "192.168.0.114": "SCA_IP_CAM",
}

# The scanner should identify the laptop running it by its local IP.
LOCAL_DEVICE_NAME = "Laptop"


# NETWORK

def clear_screen():
    """Reliably clear the current Windows console or ANSI terminal."""
    try:
        if platform.system().lower() == "windows":
            os.system("cls")
            print("\033[2J\033[H", end="", flush=True)
        else:
            os.system("clear")
            print("\033[2J\033[H", end="", flush=True)

    except Exception:
        # Last-resort fallback for unusual terminal environments.
        print("\n" * 100, end="", flush=True)


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No Internet traffic is required.
        sock.connect(("192.168.0.1", 80))
        return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        sock.close()


def get_local_subnet():
    ip = get_local_ip()
    if ip == "127.0.0.1":
        return ipaddress.ip_network("192.168.0.0/24")
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def ping_host(ip):
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "300", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        return subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5
        ).returncode == 0
    except Exception:
        return False


def tcp_probe(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        return sock.connect_ex((str(ip), port)) == 0
    except Exception:
        return False
    finally:
        sock.close()


def host_is_alive(ip):
    if ping_host(ip):
        return True

    # Cameras may ignore ping, so test TCP services as well.
    return any(tcp_probe(ip, port) for port in DISCOVERY_PORTS)


def discover_devices_arp(network):
    if not SCAPY_AVAILABLE:
        return []

    try:
        conf.verb = 0
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            pdst=str(network)
        )
        answered, _ = srp(request, timeout=2, verbose=False)

        devices = [
            {"ip": r.psrc, "mac": r.hwsrc.upper()}
            for _, r in answered
        ]
        return sorted(
            devices,
            key=lambda x: ipaddress.ip_address(x["ip"])
        )
    except Exception:
        return []


def discover_devices_fallback(network):
    hosts = list(network.hosts())
    devices = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(host_is_alive, ip): ip
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
            except Exception:
                pass

    return sorted(
        devices,
        key=lambda x: ipaddress.ip_address(x["ip"])
    )


def discover_devices(network):
    msg("[*]", f"Scanning {network} for active devices...", C.CYAN)

    if SCAPY_AVAILABLE:
        devices = discover_devices_arp(network)
        if devices:
            msg("[+]", f"ARP discovery found {len(devices)} device(s).", C.GREEN)
            return devices

    msg("[*]", "Using ping/TCP discovery fallback...", C.YELLOW)
    devices = discover_devices_fallback(network)
    msg("[+]", f"Discovery found {len(devices)} device(s).", C.GREEN)
    return devices

# DEVICE INFORMATION

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0].strip()
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass
    return "Unknown"


def get_mac_address(ip):
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=1
        )
        match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", result.stdout)
        if match:
            return match.group(1).upper()
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["arp", "-a", ip],
            capture_output=True,
            text=True,
            timeout=1
        )
        match = re.search(
            r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})",
            result.stdout
        )
        if match:
            return match.group(1).replace("-", ":").upper()
    except Exception:
        pass

    return "Unknown"


MAC_VENDORS = {
    "00000C": "Cisco",
    "001B54": "Cisco",
    "0022BD": "Cisco",
    "001C58": "Cisco",
    "00260B": "Cisco",
    "50C7BF": "TP-Link",
    "C0A0BB": "TP-Link",
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "VirtualBox",
}


def get_vendor(mac):
    if not mac or mac == "Unknown":
        return "Unknown"
    compact = mac.replace(":", "").replace("-", "").upper()
    return MAC_VENDORS.get(compact[:6], "Unknown")


def get_device_name(device):
    """Return a friendly lab name instead of showing Unknown where possible."""
    ip = device["ip"]

    if ip in KNOWN_DEVICES:
        return KNOWN_DEVICES[ip]

    if ip == get_local_ip():
        return LOCAL_DEVICE_NAME

    hostname = device.get("hostname", "")
    if hostname and hostname.lower() != "unknown":
        return hostname

    vendor = device.get("vendor", "")
    if vendor and vendor.lower() != "unknown":
        return f"{vendor} Device"

    return "Lab Device"


def print_devices(devices):
    header("DEVICES FOUND")

    print(
        f"{paint('DEVICE', C.BOLD + C.CYAN):<8}"
        f"{paint('NAME', C.BOLD + C.CYAN):<30}"
        f"{paint('IP ADDRESS', C.BOLD + C.CYAN):<18}"
        f"{paint('MAC ADDRESS', C.BOLD + C.CYAN)}"
    )
    print(paint("-" * 82, C.BLUE))

    for n, device in enumerate(devices, 1):
        name = get_device_name(device)

        # [1], [2], [3] makes the selection format obvious to beginners.
        selector = f"[{n}]"

        print(
            f"{paint(selector, C.BOLD + C.YELLOW):<8}"
            f"{paint(name, C.BOLD + C.WHITE):<30}"
            f"{device['ip']:<18}"
            f"{device.get('mac', 'Unknown')}"
        )

    print(paint("-" * 82, C.BLUE))
    print(paint(
        "Select a device using its number, e.g.  [1]  [2]  [3]",
        C.BOLD + C.CYAN
    ))

# SERVICE ENUMERATION

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.50)
    try:
        if sock.connect_ex((ip, port)) == 0:
            return port
    except Exception:
        pass
    finally:
        sock.close()
    return None


def scan_ports(ip):
    header("SERVICE ENUMERATION")
    msg("[*]", f"Checking TCP services on {ip}", C.CYAN)
    msg(
        "[*]",
        "Required lab checks: TCP/23 Telnet and TCP/81 camera web service",
        C.YELLOW
    )

    open_ports = []

    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port
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


def get_http_info(ip, port):
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=1.5)
        conn.request("GET", "/")
        response = conn.getresponse()
        server = response.getheader("Server") or "Unknown"
        body = response.read(32768)
        conn.close()

        text = body.decode("utf-8", errors="ignore")
        title = "Unknown"

        match = re.search(
            r"<title[^>]*>(.*?)</title>",
            text,
            re.I | re.S
        )
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()

        return server, title
    except Exception:
        return None


def print_ports(open_ports):
    header("OPEN SERVICES")

    print(
        f"{paint('PORT', C.BOLD + C.CYAN):<10}"
        f"{paint('STATE', C.BOLD + C.CYAN):<16}"
        f"{paint('SERVICE', C.BOLD + C.CYAN)}"
    )
    print(paint("-" * 58, C.BLUE))

    for port in open_ports:
        if port == 23:
            print(
                f"{paint('23', C.BOLD + C.RED):<20}"
                f"{paint('OPEN', C.BOLD + C.RED):<26}"
                f"{paint('TELNET', C.BOLD + C.RED)}"
            )
        elif port == 81:
            print(
                f"{paint('81', C.BOLD + C.GREEN):<20}"
                f"{paint('OPEN', C.BOLD + C.GREEN):<26}"
                f"{paint('HTTP - CAMERA WEB', C.BOLD + C.GREEN)}"
            )
        else:
            print(
                f"{port:<20}"
                f"{paint('OPEN', C.BOLD + C.GREEN):<26}"
                f"{COMMON_PORTS[port]}"
            )

    print(paint("-" * 58, C.BLUE))

# CAMERA CLUE

def show_camera_clue(target_ip, open_ports):
    # The lab camera uses TCP/81, not TCP/80.
    if 81 not in open_ports:
        return

    url = f"http://{target_ip}:81/securecam.html"

    header("CAMERA WEB INTERFACE")

    msg(
        "[+]",
        "TCP/81 is OPEN and provides the camera web service.",
        C.GREEN
    )

    print()
    print(paint(
        "Use the target IP address together with port 81.",
        C.YELLOW
    ))
    print(paint(
        "The lab camera page is:",
        C.WHITE
    ))
    print()
    print(paint(
        f"  {url}",
        C.BOLD + C.GREEN
    ))
    print()
    print(paint(
        "Copy the URL into your browser.",
        C.BOLD + C.CYAN
    ))

    choice = input(
        "\nOpen it automatically? [B = browser / ENTER = continue]: "
    ).strip().lower()

    if choice == "b":
        try:
            # Open the camera URL without leaving it printed in the terminal.
            webbrowser.open_new_tab(url)

            # Give Windows a moment to hand the URL to the browser.
            import time
            time.sleep(0.35)

            # Wipe the entire previous investigation, including the URL.
            clear_screen()

            # Return directly to the reusable scan state.
            print(paint("=" * 72, C.BLUE))
            print(paint("READY FOR ANOTHER SCAN", C.BOLD + C.CYAN))
            print(paint("=" * 72, C.BLUE))
            print()
            print(paint(
                "The camera page has been opened in the browser.",
                C.GREEN
            ))
            print()
            print(paint(
                "The previous investigation details have been cleared.",
                C.YELLOW
            ))

        except Exception:
            clear_screen()
            print(paint("=" * 72, C.BLUE))
            print(paint("READY FOR ANOTHER SCAN", C.BOLD + C.CYAN))
            print(paint("=" * 72, C.BLUE))
            print()
            msg(
                "[!]",
                "The browser could not be opened automatically.",
                C.YELLOW
            )
            print()
            print(paint(
                "The previous investigation details have been cleared.",
                C.YELLOW
            ))

# INVESTIGATION

def investigate_device(target):
    target_ip = target["ip"]

    header("SELECTED DEVICE")
    print(f"{paint('Name       :', C.BOLD + C.CYAN)} {get_device_name(target)}")
    print(f"{paint('IP Address :', C.BOLD + C.CYAN)} {target_ip}")
    print(f"{paint('MAC Address:', C.BOLD + C.CYAN)} {target.get('mac', 'Unknown')}")
    print(f"{paint('Vendor     :', C.BOLD + C.CYAN)} {target.get('vendor', 'Unknown')}")

    open_ports = scan_ports(target_ip)

    if not open_ports:
        msg("[!]", "No open services found.", C.YELLOW)
        return

    print_ports(open_ports)

    if target_ip == "192.168.0.114":
        header("DEVICE IDENTIFICATION")
        msg(
            "[+]",
            "Known lab target: SCA Secure IP CAM",
            C.GREEN
        )

    if 23 in open_ports and 81 in open_ports:
        header("DEVICE IDENTIFICATION")
        msg(
            "[+]",
            "TCP/23 Telnet + TCP/81 HTTP is consistent with the lab IP camera.",
            C.GREEN
        )
        msg(
            "[!]",
            "These exposed services are now evidence to investigate.",
            C.YELLOW
        )

    show_camera_clue(target_ip, open_ports)

    print()
    msg("[+]", "Investigation complete.", C.GREEN)


# MAIN

def show_start_screen():
    header("CYBERSECURITY LAB")

    print(paint(
        "You are the cybersecurity consultant.",
        C.BOLD + C.WHITE
    ))
    print("Discover devices on the isolated lab network.")
    print("Select a device and enumerate its exposed services.")
    print()
    print(paint(
        "METHOD: Discover -> Select -> Enumerate -> Identify -> Investigate",
        C.BOLD + C.CYAN
    ))
    print()
    print(paint(
        "Only scan the equipment provided for this lab.",
        C.YELLOW
    ))
    print()
    print(paint("Press ENTER to start scanning.", C.BOLD + C.GREEN))
    print(paint("Type Q to quit.", C.BOLD + C.RED))


def main():
    while True:
        show_start_screen()
        choice = input("\n> ").strip().lower()

        if choice == "q":
            msg("[*]", "Goodbye.", C.CYAN)
            return

        network = get_local_subnet()

        header("NETWORK DISCOVERY")
        msg("[+]", f"Local network detected: {network}", C.GREEN)

        devices = discover_devices(network)

        if not devices:
            msg("[!]", "No active devices found.", C.RED)
            input("\nPress ENTER to return...")
            continue

        for device in devices:
            if device.get("mac") == "Unknown":
                device["mac"] = get_mac_address(device["ip"])
            device["hostname"] = get_hostname(device["ip"])
            device["vendor"] = get_vendor(device["mac"])

        print_devices(devices)

        print()
        msg(
            "[i]",
            "Known lab devices are automatically labelled for you.",
            C.CYAN
        )

        while True:
            selection = input(
                "\nSelect a device [1] [2] [3]... or Q to cancel: "
            ).strip().lower()

            if selection == "q":
                break

            try:
                number = int(selection)
                if not 1 <= number <= len(devices):
                    msg("[!]", "Invalid device number.", C.RED)
                    continue

                investigate_device(devices[number - 1])
                break

            except ValueError:
                msg("[!]", "Please enter a valid device number.", C.RED)

        print()
        print(paint("=" * 72, C.BLUE))
        print(paint("READY FOR ANOTHER SCAN", C.BOLD + C.CYAN))
        print(paint("=" * 72, C.BLUE))

        choice = input(
            "Press ENTER to scan again, or Q to quit: "
        ).strip().lower()

        if choice == "q":
            msg("[*]", "Goodbye.", C.CYAN)
            return


if __name__ == "__main__":
    main()
