from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    print(f"scanning {ip_range}... Please wait.")

    # Send the packet and receive responses
    result = srp(packet, timeout=2, verbose=False) [0]

    # Print out the results
    devices=[]
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("\nAvailable Devices in the Network:")
    print("IP" + " " * 18+"MAC")
    print("-"*40)
    for device in devices:
        print("{:16} {}".format(device['ip'], device['mac']))

if __name__=="__main__":
    target_ip = input("Enter the IP range (e.g., 192.168.1.0/24): ")
    scan_network(target_ip)