#script for easily adding new machines to the lab environment
from ipaddress import ip_address
import os
import random

LABDIRECTORY = "Environment1"

def create_machine(machine_name, ip_address, dns_name="10.0.0.2", dirPath = LABDIRECTORY):
    filepath = dirPath + "/" + machine_name + ".startup"
    startupCommand = """#!/bin/bash\n echo "nameserver """ + dns_name +"""" > /etc/resolv.conf\nip addr add """ + ip_address +"""/24 dev eth0\nip link set eth0 up\nip route add default via 10.0.0.1"""
    
    with open(filepath, "w") as f:
        f.write(startupCommand)
    
def createWebServer(name, ip_address, dirPath = LABDIRECTORY):
    baseFile = "webBase.startup"
    with open(baseFile) as f:
        baseContent = f.read()
    startupCommand = "#!/bin/bash\n\nip addr add " + ip_address + "/24 dev eth0\n" + baseContent
    filepath = dirPath + "/" + name + ".startup"
    with open(filepath, 'r+') as f:
        f.write(startupCommand)


if __name__ == "__main__":
    print("Input number of machines to create: ")
    machineNum = input()
    print("Input seed for random IP generation: ")
    randSeed = input()

    random.seed(randSeed)
    ips = []
    for i in range(int(machineNum)):
        mName = "pc" + str(i+1)
        randIp = random.randint(10, 250)
        while randIp in ips:
            randIp = random.randint(10, 250)
        mIp = "10.0.0." + str(randIp)
        ips.append(randIp)
        create_machine(mName, mIp)
    
    #Create web server
    webIp = random.randint(10, 250)
    while webIp in ips:
        webIp = random.randint(10, 250)
    webServerIp = "10.0.0." + str(webIp)
    createWebServer("web1", webServerIp)

    #remove additional machines
    val = int(machineNum)+1
    extraFile = LABDIRECTORY + "/pc" + str(val) + ".startup"
    while os.path.exists(extraFile):
        os.remove(extraFile)
        val += 1
        extraFile = LABDIRECTORY + "/pc" + str(val) + ".startup"
    print(machineNum + " machines created successfully.")

    #Create web server startup file


    #Create lab.conf file
    configBase = """LAB_DESCRIPTION="Simple LAN with """ + machineNum + """ PCs, a DNS server and a Web server"c\nLAB_VERSION="1.0"\nattacker[0]=A\nattacker[sysctl]="net.ipv4.ip_forward=1" # enable IP forwarding for MITM\nweb1[bridged]=true\nattacker[bridged]=true\ndns1[0]=A\nweb1[0]=A"""
    for i in range(int(machineNum)):
        configBase += "\npc" + str(i+1) + "[0]=A"
    with open(LABDIRECTORY + "/lab.conf", "w") as f:
        f.write(configBase)