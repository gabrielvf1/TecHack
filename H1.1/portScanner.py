import socket
import subprocess
import sys
from datetime import datetime
from tkinter import *
from tkinter import scrolledtext
import nmap3
from scapy.all import *
import os
import sys
import subprocess
from netaddr import *

if os.geteuid() == 0:
    print("We're root!")
else:
    print("We're not root.")
    subprocess.call(['sudo', 'python3', *sys.argv])
    sys.exit()

nmap = nmap3.Nmap()

window = Tk()
window.title("Port Scanner Francato")

lbl = Label(window, text="Insira o IP desejado: ")
lbl.grid(column=0, row=0)

txt = Entry(window,width=10)
txt.grid(column=1, row=0)

tipoScan = IntVar()

txtPort1 = Entry(window,width=10)
txtPort1.grid(column=0, row=3)

lblPortaInicial = Label(window, text="Porta Inicial (abaixo)")
lblPortaInicial.grid(column=0, row=2)


txtPort2 = Entry(window,width=10)
txtPort2.grid(column=2, row=3)

lblPortaFinal = Label(window, text="Porta Inicial (abaixo)")
lblPortaFinal.grid(column=2, row=2)

rad1 = Radiobutton(window,text='TCP', value=1, variable = tipoScan)

rad2 = Radiobutton(window,text='UDP', value=2, variable = tipoScan)

rad1.grid(column=0, row=1)

rad2.grid(column=1, row=1)

txtScroll = scrolledtext.ScrolledText(window,width=40,height=10)
txtScroll.grid(column=1,row=4)

def scan_IP(IP1,portaI,portaF):
    serverParaScanIP = IP1
    listaPortas = []
    txtScroll.insert(INSERT,'IP Pesquisado: '+ IP1)
    txtScroll.insert(INSERT, '\n')
    for port in range(portaI,portaF):
        if (tipoScan.get() == 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((serverParaScanIP, port))
            try:
                servico = socket.getservbyport(port)
            except:
                servico = "Unknown"
            if result == 0:
                listaPortas.append("Port {}: 	 Open -> Servico {}".format(port, servico))
            sock.close()
        elif (tipoScan.get() == 2):
            pkt = sr1(IP(dst=serverParaScanIP)/UDP(sport=port, dport=port), timeout=2, verbose=0)
            if pkt == None:
                listaPortas.append("Port {}: 	 Open ".format(port))
            else:
                if pkt.haslayer(ICMP):
                    listaPortas.append("Port {}: 	 Closed ".format(port))
                elif pkt.haslayer(UDP):
                    listaPortas.append("Port {}: 	 Open ".format(port))
                else :
                    listaPortas.append("Port {}: 	 Unknown {}".format(port, pkt.summary()))
    if (len(listaPortas) == 0):
        txtScroll.insert(INSERT,'Nenhuma Porta aberta achada')
        txtScroll.insert(INSERT, '\n')
        txtScroll.insert(INSERT, '\n')
    else:
        for i in listaPortas:
                txtScroll.insert(INSERT,i)
                txtScroll.insert(INSERT, '\n')
        txtScroll.insert(INSERT, '\n')


def clicked():
    txtScroll.delete(1.0,END)
    serverParaScan = txt.get()
    portaInicial = int(txtPort1.get())
    portaFinal = int(txtPort2.get())
    if ('/' in serverParaScan):
        for ip in IPNetwork(serverParaScan):
            print(ip)
            ip_atual = str(ip)
            serverParaScanIP = socket.gethostbyname(ip_atual)
            scan_IP(serverParaScanIP,portaInicial,portaFinal)
    else:
        serverParaScanIP = socket.gethostbyname(serverParaScan)
        scan_IP(serverParaScanIP,portaInicial,portaFinal)
    print('FIM')


btn = Button(window, text="Pesquisar", command=clicked)
btn.grid(column=2, row=0)
window.mainloop()