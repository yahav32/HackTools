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
    def __init__(self):
        self.__broadcast = "ff:ff:ff:ff:ff:ff"

    def start(self):
        ip = input("Enter IP: ")
        subnetmask = input("Enter subnetmask: ")
        validator = NetworkValidator(ip, subnetmask)
        network = validator.get_network()[1]

        print(network)

        pack = Ether(dst=self.__broadcast)/ARP(pdst=str(network))

        answered, unanswered = srp(pack, timeout=2)

        print(f"{'IP Address':<15} | {'MAC Address'}")
        print("-" * 35)
        print(f"[+] IP in the network: {len(answered)}")
        for sent, received in answered:
            print(f"{received.psrc:<15} | {received.hwsrc}")


scn = NetworkScanner().start()

