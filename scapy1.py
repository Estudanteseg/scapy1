#!/usr/bin/env python
# -*- coding: utf-8 -*-
import netifaces
import os
from datetime import datetime
from scapy.all import *

CEND      = '\33[0m'
CRED    = '\33[31m'
CGREEN  = '\33[32m'
CYELLOW = '\33[33m'

lista=[]
macs=[]
dicionario={}

def ModoMonitora() :
    opcoes = ""
    interfaces = netifaces.interfaces()

    i = 0

    for interface in interfaces:
        i=i+1
        net1 = netifaces.ifaddresses(interface)
        mac = net1[netifaces.AF_LINK][0]['addr']
    
        try:
            ip = net1[netifaces.AF_INET][0]['addr']

        except KeyError as e:
            ip = 'Sem IP'
            #continue

        opcoes = opcoes + CGREEN +  str(i) + CEND +  ": " + str(interface) + " MAC=> " + str(mac) + "  IP=> " + str(ip) + "\n"

    while  True:
        try:
            print(opcoes)
            monitorar = int(input("Qual interface acima será utilizada para monitorar ? ")) - 1
            if monitorar <=  len(interfaces):
                break
            else:
                print (CRED + "Valor inválido. Tente de 1 a " + str(len(interfaces)) + CEND + "\n\n\n")
        except:
            print(CRED + "Valor inválido. \n\n\n" + CEND)


    placa = str(interfaces[monitorar])
    print("Vamos monitorar " + placa)
    #if placa != "wlan0mon":
    os.system("sudo ifconfig " + placa + " down")
    os.system("sudo ip link set " + placa + " name wlan0")
    os.system("sudo ifconfig wlan0 down")
    os.system("sudo macchanger -a wlan0")
    os.system("sudo ifconfig wlan0 up")
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng start wlan0")

    print("Monitoramento iniciando...")


def PacketHandler(pkt) :

    if pkt.haslayer(Dot11) :
       if pkt.type == 0 and pkt.subtype == 4 :
          if pkt.info :
             varMacCli = pkt.addr2
             varRedCli = pkt.info
             redes = ""

             varRedCli = varRedCli.upper()
             varMacCli = varMacCli.upper()

             if varRedCli not in dicionario.keys() :
                dicionario[varRedCli]=[]

             if varMacCli not in dicionario[varRedCli] :
                dicionario[varRedCli].append(varMacCli)

             print("\n" * 130)

             for rede in sorted(dicionario.keys()) :
                 redes = redes +  "SSID: " + str(rede) + " Macs: " + str(dicionario[rede]) + "\n"

        
             print(redes)
             now = datetime.now()
             agora = str(now.year) + str(now.month) + str(now.day) + " " + str(now.hour) + ":" + str(now.minute) 
             redes = agora + "\n" + redes
             GravaArquivo(redes) 
             


def GravaArquivo(vTexto) :
    file = open('scapy1.txt','w') 
    file.write(vTexto) 
    file.close() 

ModoMonitora()
sniff(iface="wlan0mon", prn=PacketHandler)
