from PacketAnalyzer import PacketAnalyzer
from PacketDigester import PacketDigester
from MetaPacketCap import MetaPacketCap
from MetaCapBase import MetaCapBase

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import tkinter as tk
from tkinter import filedialog, simpledialog
import os.path
import pathlib

class MetaCapLibrary(object):

    def __init__(self):
        self.packetLibrary = []
        root = tk.Tk()
        root.withdraw()

        # define options for opening or saving a file
        self.file_opt = options = {}
        #options['defaultextension'] = '.txt'
        #options['filetypes'] = [('all files', '.*'), ('text files', '.txt')]
        options['filetypes'] = [('Network Traffic Captures', '*.pcapng *.pcap *.cap'), ('Pcap-ng files', '*.pcapng'),
                                ('Pcap files', '*.pcap'), ('text files', '*.txt'), ('all files', '.*')]
        options['initialdir'] = '/home/irvin/PycharmProjects/scapy_tutorial/NewPcaps/TunnelCaps_2016'
        #options['initialfile'] = 'myfile.txt'
        #options['parent'] = root
        #options['title'] = 'This is a title'
        options['multiple'] = 'True'

        self.capbase = MetaCapBase()
        print('capbase directory: ', self.capbase.base_loc)
        self.fig = None
        self.ax = None
        self.gs = None

    def add_to_lib(self, newMetaCap):
        self.packetLibrary.append(newMetaCap)

    def add_to_base(self, newMetaCap):

        return

    def load_single_pcap(self):

        return

    # def load_pcaps(self):
    #     return

    def load_pcaps_from_files(self, protocol_base='unknown'):
        file_paths = filedialog.askopenfilenames(**self.file_opt)

        #If protocol base is not known, ASK!
        if protocol_base is None or protocol_base == '' or protocol_base == 'unknown':
            print("Protocol Base is: ", protocol_base)
            protocol_base = simpledialog.askstring(
                "Base Protocol", "What is the possible base protocol?", initialvalue="unknown")

        for capfile_path in file_paths:
            #print(file_path)
            self.add_to_lib(MetaPacketCap(capfile_path,protocol_base))
            print(len(self.get_packet_library()))
            self.write_path_to_base(protocol_base, capfile_path)

        return file_paths

    def write_path_to_base(self, base_file_name, f_path):
        if self.capbase.base_loc == '':
            print("Base not yet set")
        elif self.capbase.base_loc == 'unknown':
            print("WARNING: Base is 'unknown' ")
        p = pathlib.Path(self.capbase.base_loc + '/' + base_file_name)
        try:
            with p.open('r') as rf:
                #Check if entry exists
                if f_path in rf.read():
                    print('Already existing PcapPath! : ' + f_path )
                else:
                    with p.open('a+') as f:
                        f.write(f_path+'\n')
        except:
            print("Base File Path does not exist ... creating base protocol store at: " +
                  self.capbase.base_loc + '/' + base_file_name)
            file = open(self.capbase.base_loc + '/' + base_file_name, 'a+')
            file.write(f_path+'\n')
        return

    def get_packet_library(self):
        return self.packetLibrary

    #def load_specific_from_base(self, protocolLabel):

    def load_specific_proto_from_base(self, protocolLabel, filterContainsTerm=None):
        #Load packet capture paths from specific protocol base file/store
        #Read protocol base file store and append entries into local packetLibrary list
        p = pathlib.Path(self.capbase.base_loc + '/' + protocolLabel)
        pathList = []
        skipped = 0
        try:
            with p.open('r') as rf:
                if filterContainsTerm is None or filterContainsTerm == '':
                    pathList = rf.readlines()
                else:
                    for line in rf:
                        if str(filterContainsTerm).lower() in str(line).rsplit('/',1)[1].lower():
                            pathList.append(line)
                        else:
                            #print("Filter term missing in base file: "+ filterContainsTerm)
                            skipped +=1
                #pathList = rf.readlines()
        except:
            print("Base File Path does not exist ...")

        print("Skipped/Filtered out entries from base: ", skipped)

        if len(pathList) > 0:
            for counter,file_path in enumerate(pathList):
                self.packetLibrary.append(MetaPacketCap(str(file_path).rstrip(),protocolLabel))
                print("CapLibEntry: ", counter+1)
        else:
            print("Base Protocol file is empty.")

        return

    def load_all_from_bases(self):
        return

    def doSuperPlot(self, plot_statistic, markercolor):
        #self.fig = plt.figure(figsize=(12, 9), dpi=100, facecolor='w', edgecolor='k')
        self.fig = plt.figure(figsize=(16, 9), dpi=90, facecolor= 'w')
        my_axes = []
        yVariable =[]

        for counter, cap in enumerate(self.packetLibrary):
            if plot_statistic == "HttpReqEntropy":
                yVariable.append(cap.getHttpReqEntropy())
            elif plot_statistic == "ftpReqEntropy":
                yVariable.append(cap.getHttpReqEntropy())
            print("CapLibPlotEntry: ", counter+1)
            x_coord = int(counter/4)
            y_coord = int(counter-(x_coord*4))
            my_axes.append(plt.subplot2grid((4,4),(x_coord,y_coord)))
            #my_axes[counter].plot(yVariable, marker="+", markeredgecolor=markercolor, linestyle="None", color="blue")
            self.fig.add_subplot(my_axes[counter])

        print("Myaxes length: ", len(my_axes))
        print("Myaxes type: ", type(my_axes))
        print("Myaxes type: ", type(my_axes[0]))
        #self.ax = plt.axes()
        #self.gs = gridspec.GridSpec(4,4)

        #plt.plot(perPktCharEntropySeq, marker="+", markeredgecolor="red", linestyle="solid", color="blue")
        #self.ax.plot(yVariable, marker="+", markeredgecolor=markercolor, linestyle="None", color="blue")
        #self.ax = self.fig.add_subplot(1,1,1)
        #self.ax = plt.subplot(self.gs[1,2])
        #self.ax.plot(yVariable, marker="+", markeredgecolor=markercolor, linestyle="solid", color="blue")

        # self.fig.add_subplot(self.ax)
        #self.fig.add_subplot(my_axes)
        self.fig.show()
        #self.fig.savefig()
        self.fig.waitforbuttonpress(timeout= -1)

        return

httpCapLib = MetaCapLibrary()
ftpCapLib = MetaCapLibrary()

#httpCapLib.load_pcaps_from_files('http')
#ftpCapLib.load_pcaps_from_files('ftp')

#httpCapLib.load_specific_proto_from_base('http')
httpCapLib.load_specific_proto_from_base('http','http')
#print("Length: ",  len(httpCapLib.__getattribute__("packetLibrary")))
#print("Length: ",  len(httpCapLib.get_packet_library()))

# ftpCapLib.load_specific_proto_from_base('ftp', 'ftp')
# print("Length: ",  len(ftpCapLib.get_packet_library()))

#httpMCap = httpCapLib.get_packet_library()[0]
#httpMCap.doPlot(httpMCap.getHttpReqEntropy(), 'red', "HTTP Request Entropy", "Packet Sequence (Time)", "Byte (Char) Entropy per packet")

#httpCapLib.doSuperPlot(httpCapLib.get_packet_library()[0].getHttpReqEntropy(), "red")
httpCapLib.doSuperPlot('HttpReqEntropy', "red")

