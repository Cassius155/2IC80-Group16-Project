#script for easily adding new machines to the lab environment
import os

def create_machine(machine_name, ip_address, dns_name="10.0.0.2", dirPath = "myLab"):
    filepath = dirPath + "/" + machine_name + ".startup"
    startupCommand = """#!/bin/bash\n echo "nameserver """ + dns_name +"""" > /etc/resolv.conf\nip addr add """ + ip_address +"""/24 dev eth0\nip link set eth0 up\nip route add default via 10.0.0.1"""
    
    with open(filepath, "w") as f:
        f.write(startupCommand)
    
if __name__ == "__main__":
    print("Input number of machines to create: ")
    machineNum = input()
    for i in range(int(machineNum)):
        mName = "pc" + str(i+1)
        mIp = "10.0.0." + str(4+i)
        create_machine(mName, mIp)
    
    #remove additional machines
    val = int(machineNum)+1
    extraFile = "myLab/pc" + str(val) + ".startup"
    while os.path.exists(extraFile):
        os.remove(extraFile)
        val += 1
        extraFile = "myLab/pc" + str(val) + ".startup"


    print(machineNum + " machines created successfully.")

    configBase = """LAB_DESCRIPTION="Simple LAN with 3 PCs, a DNS server and a Web server"c\nLAB_VERSION="1.0"\nattacker[0]=A\nattacker[sysctl]="net.ipv4.ip_forward=1" # enable IP forwarding for MITM\ndns1[0]=A\nweb1[0]=A"""
    for i in range(int(machineNum)):
        configBase += "\npc" + str(i+1) + "[0]=A"
    with open("myLab/lab.conf", "w") as f:
        f.write(configBase)