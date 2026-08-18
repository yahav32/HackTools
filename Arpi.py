import argparse
from typing import Tuple

from scapy.all import Ether, ARP, srp, sniff
import ipaddress


class NetworkValidator:
    def __init__(self, ip_address: str, subnet_mask: str):
        self.__ip_address = ip_address
        self.__subnet_mask = subnet_mask

    def get_network(self) -> Tuple:
        try:
            net = ipaddress.ip_network(f"{self.__ip_address}/{self.__subnet_mask}",strict=False)
            return True, net
        except ValueError:
            return False, None

    def get_ip(self):
        return self.__ip_address
    def get_subnetmask(self):
        return self.__subnet_mask

class NetworkScanner:
    def __init__(self, network: str):
        self.__broadcast = "ff:ff:ff:ff:ff:ff"
        self.__network = network
    def start(self):
        validator = NetworkValidator(*self.__network.split("/", 1))
        network = validator.get_network()[1]

        print(network)

        pack = Ether(dst=self.__broadcast)/ARP(pdst=str(network))

        answered, unanswered = srp(pack, timeout=2)

        print(f"{'IP Address':<15} | {'MAC Address'}")
        print("-" * 35)
        print(f"[+] IP in the network: {len(answered)}")
        for sent, received in answered:
            print(f"{received.psrc:<15} | {received.hwsrc}")

def parse_args():
    parser = argparse.ArgumentParser(description="ARP Network Scanner")
    parser.add_argument("-n", "--network", required=True, help="Network in CIDR format, example: 192.168.1.10/24")
    return parser.parse_args()

def main():
    args = parse_args()
    scanner = NetworkScanner(args.network)
    scanner.start()


if __name__ == "__main__":
    main()