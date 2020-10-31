#coded by 4nm0u5
#any part of the code is subject to copyright,descent use is public


import nmap

scanner = nmap.PortScanner()

print("welcome to my first nmap")
print("<------------------------>")

ip_addr = input("Please enter the IP that you want to scan")
print("You entered IP : ",ip_addr)

type(ip_addr)

resp = input("""\nWhat type of scan you want to perform 
                  1.SYN ACK scan
                  2.UDP scan
                  3.Comprehensive scan\n""")
                  
print("You have entered option ", resp)

if resp == '1':
       print("Nmap version : ", scanner.nmap_version())
       scanner.scan(ip_addr, '1-1024', ' -v -sS')
       print(scanner.scaninfo())
       print("IP status: " ,scanner[ip_addr].state())
       print(scanner[ip_addr].all_protocols())
       print("Open Ports: " , scanner[ip_addr]['tcp'].keys())
       
elif resp == '2':
       print("Nmap version :  ",scanner.nmap_version())
       scanner.scan(ip_addr, '1-1024', ' -v -sU')
       print(scanner.scaninfo())
       print("IP status: " ,scanner[ip_addr].state())
       print(scanner[ip_addr].all_protocols())
       print("Open Ports:", scanner[ip_addr]['udp'].keys())
      
elif resp == '3':
       print("Nmap version:", scanner.nmap_version())
       scanner.scan(ip_addr, '1-1024', ' -v -sS -sV -sS -A -O')
       print(scanner.scaninfo())
       print("IP status: " ,scanner[ip_addr].state())
       print(scanner[ip_addr].all_protocols())
       print("Open Ports:", scanner[ip_addr]['udp'].keys())
      
       
       
       