import socket
import os
import argparse
import ipaddress
import logging
import ctypes
import struct

# Define the IP header structure using ctypes
class IPHeader(ctypes.Structure):
    _fields_ = [
        ("version_ihl", ctypes.c_ubyte),
        ("tos", ctypes.c_ubyte),
        ("total_length", ctypes.c_uint16),
        ("identification", ctypes.c_uint16),
        ("flags_offset", ctypes.c_uint16),
        ("ttl", ctypes.c_ubyte),
        ("protocol", ctypes.c_ubyte),
        ("checksum", ctypes.c_uint16),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32)
    ]

def parse_arguments():
    """
    Parses command-line arguments to get the IP address.
    Ensures the IP address is valid.
    """
    parser = argparse.ArgumentParser(description='Network packet sniffer.')
    parser.add_argument('ip_address', type=str, help='IP address to bind the socket to')
    
    # Parse the arguments
    args = parser.parse_args()
    ip_addr = args.ip_address
    
    # Validate the IP address
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError:
        logging.error(f"Invalid IP address '{ip_addr}'.")
        exit(1)
    
    return args

def parse_ip_header(data):
    """
    Parses the IP header from the packet data and extracts relevant information.
    """
    # Extract the first 20 bytes of the IP header
    ip_header_raw = data[:20]
    
    # Unpack the IP header using the correct format
    unpacked_header = struct.unpack('!BBHHHBBHII', ip_header_raw)
    
    version_ihl = unpacked_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    
    protocol = unpacked_header[6]
    
    # Convert source and destination IP addresses from bytes
    src_ip = socket.inet_ntoa(struct.pack('!I', unpacked_header[8]))
    dst_ip = socket.inet_ntoa(struct.pack('!I', unpacked_header[9]))
    
    return {
        'version': version,
        'ihl': ihl,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip
    }

def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Parse command-line arguments
    arguments = parse_arguments()
    ip_address = arguments.ip_address

    # Determine the appropriate protocol based on the operating system
    protocol = socket.IPPROTO_IP if os.name == 'nt' else socket.IPPROTO_ICMP

    sniffer_socket = None

    try:
        # Create a raw socket to capture network packets
        sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        
        # Bind the socket to the specified IP address and an arbitrary port
        sniffer_socket.bind((ip_address, 0))
        
        # Set the socket option to include the IP header in packets
        sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # On Windows, enable the socket to capture all packets
        if os.name == 'nt':
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        logging.info("Listening for packets...")
        
        # Receive a packet (up to 65565 bytes)
        data, addr = sniffer_socket.recvfrom(65565)
        logging.info(f"Received packet from {addr}")

        # Parse the IP header
        ip_info = parse_ip_header(data)
        logging.info(f"IP Version: {ip_info['version']}")
        logging.info(f"Header Length: {ip_info['ihl']}")
        logging.info(f"Protocol: {ip_info['protocol']}")
        logging.info(f"Source IP: {ip_info['src_ip']}")
        logging.info(f"Destination IP: {ip_info['dst_ip']}")

    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        # Ensure the socket is closed if it was created
        if sniffer_socket is not None:
            # On Windows, disable the capture-all mode
            if os.name == 'nt':
                sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            # Close the socket
            sniffer_socket.close()

if __name__ == '__main__':
    main()
