"""
Author: Blossom Babalola
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name} {platform.release()}")


"""=============================================
A dictionary of common ports and their associated services for reference during scanning.
================================================
"""
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?

    """
    @property simplifies the creation of getter, setter and deleter methods by transforming methods into properties, eliminating the need for explicit method calls. In the above code, @property allows us to access the target attribute as if it were a regular attribute.
    
    @target.setter is used to define a method that sets the value of a property. It allows for controlled attribute assingnment with validation. In the above code, it ensures that the target cannot be set to an empty string.
    """

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value.strip() == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
"""
PortScanner reuses code from NetworkTool through inheritance. By calling super().__init__(target) in its constructor, PortScanner can reuse the target attribute without having to redefine the logic for handling the target.
"""


class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        #  Q4: What would happen without try-except here?
        """
        Without try-except, any error would cause the entire program to crash. The try-except block allows us to anticipate these exceptions, handle them and print an error message. We can then continue executing the code even if an error occurs.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Socket error on port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    """Threading allows us to scan multiple ports simultaneously, providing faster results.done. If we were to scan 1024 ports without threading, it would take a long time as each port would be scanned sequentially. With threading, we can scan all ports in parallel, making the process much more efficient.
    """

    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


DB_NAME = "scan_history.db"


def save_results(target, results):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """
        )
        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now())),
            )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


def load_past_scans():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()
        if rows:
            for row in rows:
                print(f"[{row[4]}] {row[0]} : Port {row[1]} ({row[3]}) - {row[2]}")
        else:
            print("No past scans found.")
    except sqlite3.Error:
        print("No past scans found.")
    finally:
        conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    print("Welcome to the Port Scanner!")
    try:
        target = input("Enter target IP address (default 127.0.0.1): ").strip()
        if not target:
            target = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): ").strip())
        while start_port < 1 or start_port > 1024:
            print("Port must be between 1 and 1024.")
            start_port = int(input("Enter start port (1-1024): ").strip())

        end_port = int(input("Enter end port (1-1024): ").strip())
        while end_port < start_port or end_port > 1024:
            print("End port must be between start port and 1024.")
            end_port = int(input("Enter end port (1-1024): ").strip())

        print(f"Scanning {target} from port {start_port} to {end_port}...")

        portScanner = PortScanner(target)
        portScanner.scan_range(start_port, end_port)
        open_ports = portScanner.get_open_ports()
        print(f"--- Scan Results for {target} ---")
        for port, status, service in open_ports:
            print(f"Port {port}: {status} ({service})")
        print("------")
        print(f"Total open ports found: {len(open_ports)}")
        save_results(target, portScanner.scan_results)

        show_history = (
            input("Would you like to see past scan history? (yes/no): ").strip().lower()
        )
        if show_history == "yes":
            load_past_scans()
    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        exit(0)


# Q5: New Feature Proposal
"""
Feature: Export Scan Results to CSV
A new export_to_csv(target, results, open_only=False) function would write scan results to a CSV file named after the target and timestamp. It would use nested if statements to control what gets exported: if open_only is True, it checks each result, and if the port status is "Open", it writes the row — otherwise it skips it. This allows users to export either a full report or a filtered report of only open ports for easier analysis in
spreadsheet software.

if open_only:
    if result[1] == "Open":   # nested if — only write open ports
        writer.writerow(result)
else:
    writer.writerow(result)   # write everything

"""
