# Nmap
#!/usr/bin/env python3
import asyncio
import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# ------------------ Address Detection ------------------ #
def detect_family(target):
    try:
        socket.inet_pton(socket.AF_INET, target)
        return socket.AF_INET
    except OSError:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, target.split("%")[0])
        return socket.AF_INET6
    except OSError:
        pass

    raise ValueError("Invalid IP address.")
    # ------------------ Banner Grabbing ------------------ #
async def grab_banner(target, port, family):
    try:
        if family == socket.AF_INET6:
            host = target.split("%")[0]
            zone = target.split("%")[1] if "%" in target else None

            reader, writer = await asyncio.open_connection(
                host=host,
                port=port,
                family=family,
                flags=socket.AI_NUMERICHOST,
                local_addr=None
            )
        else:
            reader, writer = await asyncio.open_connection(target, port)

        writer.write(b"\r\n")
        await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(128), timeout=0.4)
            return data.decode(errors="ignore").strip()
        except:
            return None

    except:
        return None
        # ------------------ Basic Port Scan (Thread) ------------------ #
def thread_scan(target, port, family):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(0.25)

        if family == socket.AF_INET6:
            if "%" in target:
                host, zone = target.split("%")
                zone_id = int(zone) if zone.isdigit() else 0
                result = sock.connect_ex((host, port, 0, zone_id))
            else:
                result = sock.connect_ex((target, port))
        else:
            result = sock.connect_ex((target, port))

        sock.close()
        return (port, result == 0)
    except:
        return (port, False)


# ------------------ Async Dispatcher ------------------ #
async def ultra_scan(target, start_port, end_port, output_file):

    family = detect_family(target)
    open_ports = []
    banners = {}

    print(f"\n[*] Scanning {target} ({'IPv4' if family==socket.AF_INET else 'IPv6'})")
    print(f"[*] Port range: {start_port}–{end_port}\n")

    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=400)

    tasks = []
    ports = range(start_port, end_port + 1)

    # Progress bar
    with tqdm(total=len(ports), desc="Scanning", unit="port") as bar:
        for port in ports:
            task = loop.run_in_executor(executor, thread_scan, target, port, family)
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        for port, is_open in results:
            bar.update(1)
            if is_open:
                open_ports.append(port)

    print("\n[*] Found open ports:", open_ports)

    # ------------------ Banner Grabbing ------------------ #
    print("\n[*] Gathering service banners (safe)…")
    banner_tasks = []

    for port in open_ports:
         banner_tasks.append(grab_banner(target, port, family))

    banner_results = await asyncio.gather(*banner_tasks)

    for port, banner in zip(open_ports, banner_results):
        banners[port] = banner

    # ------------------ Output File ------------------ #
    if output_file:
        with open(output_file, "w") as f:
            f.write(f"Target: {target}\n")
            f.write(f"Open Ports:\n")
            for port in open_ports:
                f.write(f"{port} : {banners.get(port,'')}\n")
        print(f"\n[+] Results saved to {output_file}")

    # Final detailed output
    print("\n=== FINAL RESULTS ===")
    for port in open_ports:
        print(f"Port {port:<5} | Banner: {banners.get(port, 'None')}")


# ------------------ Entry Point ------------------ #
if __name__ == "__main__":
    try:
        print("=== Ultra IPv4 + IPv6 Port Scanner ===")
        target = input("Target IP: ").strip()

        start_port = int(input("Start port: ").strip())
        end_port = int(input("End port: ").strip())
        output_file = input("Output file (leave blank for none): ").strip()
        if output_file == "":
            output_file = None

        start = time.time()
        asyncio.run(ultra_scan(target, start_port, end_port, output_file))
        end = time.time()

        print(f"\nScan completed in {end - start:.2f} seconds.")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)






