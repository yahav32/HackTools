from scapy.all import Ether, ARP, srp, sniff
import ipaddress


class NetworkValidator:
    def __init__(self, ip_address: str, subnet_mask: str):
        self.__ip_address = ip_address
        self.__subnet_mask = subnet_mask

    def validate(self) -> bool:
        try:
            ip = ipaddress.ip_address(self.__ip_address)
            if not self.__subnet_mask.isdigit():
                mask = ipaddress.ip_address(self.__subnet_mask)
                net = ipaddress.ip_network(f"{self.__ip_address}/{self.__subnet_mask}", strict=False)
            else:
                net = ipaddress.ip_network(f"{self.__ip_address}/{self.__subnet_mask}", strict=False)

            print(ip, self.__subnet_mask, net)
            return True
        except (ValueError, ipaddress.AddressValueError) if 'AddressValueError' in globals() else ValueError:
            pass



net = NetworkValidator("1.1.1.0","255.255.255.240")

net.validate()
