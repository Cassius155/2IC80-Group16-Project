#script for easily adding new machines to the lab environment
from ipaddress import ip_address
import os
import random
import shutil

LABDIRECTORY = "Environment1"

def create_machine(machine_name, ip_address, gateway, dns_name, dirPath = LABDIRECTORY):
    filepath = dirPath + "/" + machine_name + ".startup"
    startupCommand = """#!/bin/bash\n echo "nameserver """ + dns_name +"""" > /etc/resolv.conf\nip addr add """ + ip_address +"""/24 dev eth0\nip link set eth0 up\nip route add default via 10.0.0.""" + str(gateway)
    with open(filepath, "w") as f:
        f.write(startupCommand)
    f.close()
    
def createWebServer(name, ip_address, dirPath = LABDIRECTORY):
    #Load base template
    baseFile = "TemplateLab/defaultStartups/webBase.startup"
    with open(baseFile) as f:
        baseContent = f.readlines()
    
    #Modify base content with specific values
    baseContent[2] = "ip addr add " + ip_address + "/24 dev eth0\n"
    baseContent[19] =  """    -subj "/C=US/ST=None/L=None/O=Test/OU=Lab/CN=""" + name +""".mylab.test"\n"""

    #Write to new file
    filepath = dirPath + "/" + name + ".startup"
    with open(filepath, 'w+') as f:
        f.writelines(baseContent)
    f.close()

    #Copy web server files
    try:
        os.mkdir(dirPath + "/" + name)
    except FileExistsError:
        pass
    shutil.copytree("TemplateLab/webBase", dirPath + "/" + name, dirs_exist_ok=True)

def createAttacker(gateWay, dnsIp, dirPath = LABDIRECTORY):
    #load base template
    baseFile = "TemplateLab/defaultStartups/attacker.startup"

    with open(baseFile) as f:
        baseContent = f.readlines()
    
    #Modify base content with specific values
    baseContent[5] = """echo "nameserver """ + dnsIp + """" > /etc/resolv.conf\n"""
    baseContent[6] = "ip route add default via 10.0.0." + str(gateWay) + "\n"
    baseContent[26] = """echo "nameserver """ + dnsIp + """" > /etc/resolv.conf\n"""

    #write to startup file
    filepath = dirPath + "/attacker.startup"
    with open(filepath, 'w+') as f:
        f.writelines(baseContent)
    f.close()

def createFileStruct(envName):
    os.mkdir(envName)
    os.mkdir(envName + "/attacker")
    shutil.copytree("TemplateLab/attacker", envName + "/attacker", dirs_exist_ok=True)


def createDNSserver(envName, dnsIp, webIps):
    #Load base template
    baseFile = "TemplateLab/defaultStartups/dnsBase.startup"
    with open(baseFile) as f:
        baseContent = f.readlines()
    
    #Modify base content with specific values
    baseContent[3] = "ip addr add " + dnsIp + "/24 dev eth0\n"
    baseContent[6] = "ip route add default via 10.0.0." +str(webIps[0]) + "\n"
    webEntries = "dns1    IN      A       " + dnsIp + "\n"
    for i, ip in enumerate(webIps):
        webEntries += "web" + str(i+1) + "    IN      A       10.0.0." + str(ip) + "\n"
    baseContent.insert(55, webEntries)

    #Write to new file
    filepath = envName + "/dns1.startup"
    with open(filepath, 'w+') as f:
        f.writelines(baseContent)
    f.close()


if __name__ == "__main__":

    #Take input data
    print("Environment Creation Script\n ------------------------- \n Input environment name: ")
    envName = input()
    print("Input number of machines to create: ")
    machineNum = input()
    print("Input number of web servers to create: ")
    webNum = input()
    print("Input seed for random IP generation: ")
    randSeed = input()

    #Create file structure
    createFileStruct(envName)
    LABDIRECTORY = envName

    random.seed(randSeed)
    ips = [] #store used IPs to avoid duplicates


    #Create web servers
    for i in range(int(webNum)):
        wName = "web" + str(i+1)
        randIp = random.randint(10, 250)
        while randIp in ips:
            randIp = random.randint(10, 250)
        wIp = "10.0.0." + str(randIp)
        ips.append(randIp)
        createWebServer(wName, wIp, envName)

    #Create DNS server
    dnsIp = random.randint(10, 250)
    while dnsIp in ips:
        dnsIp = random.randint(10, 250)
    dnsServerIp = "10.0.0." + str(dnsIp)
    createDNSserver(envName, dnsServerIp, ips)
    ips.append(dnsIp)

    #Create attacker machine
    createAttacker(ips[0], dnsServerIp, envName)

    #Create machines
    for i in range(int(machineNum)):
        mName = "pc" + str(i+1)
        randIp = random.randint(10, 250)
        while randIp in ips:
            randIp = random.randint(10, 250)
        mIp = "10.0.0." + str(randIp)
        ips.append(randIp)
        create_machine(mName, mIp, ips[0], dnsServerIp, envName)
    

    #Create lab.conf file
    configBase = """LAB_DESCRIPTION="Simple LAN with """ + machineNum + """ PCs, a DNS server and """ + webNum + """ Web servers"\nLAB_VERSION="1.0"\nattacker[0]=A\nattacker[sysctl]="net.ipv4.ip_forward=1" # enable IP forwarding for MITM\n\ndns1[0]=A\n"""
    for i in range(int(machineNum)):
        configBase += "\npc" + str(i+1) + "[0]=A"
    for i in range(int(webNum)):
        configBase += "\nweb" + str(i+1) + "[0]=A"
        configBase += "\nweb" + str(i+1) + "[bridged]=true"
    with open(LABDIRECTORY + "/lab.conf", "w") as f:
        f.write(configBase)