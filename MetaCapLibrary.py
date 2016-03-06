from PacketAnalyzer import PacketAnalyzer
from PacketDigester import PacketDigester
from MetaPacketCap import MetaPacketCap
from MetaCapBase import MetaCapBase

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

        self.capbase = MetaCapBase(filedialog.askdirectory(initialdir=''))
        print('capbase: ', self.capbase.base_loc)

    def add_to_lib(self, newMetaCap):
        self.packetLibrary.append(newMetaCap)

    def load_single_pcap(self):

        return

    # def load_pcaps(self):
    #     return

    def load_pcaps_from_files(self, protocol_base='unknown'):
        file_paths = filedialog.askopenfilenames(**self.file_opt)

        #If protocol base is not known, ASK!
        if protocol_base == '' or 'unknown':
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

    def load_specific_proto_from_base(self, protocolLabel):
        #Load packet capture paths from specific protocol base file/store
        #Read protocol base file store and append entries into local packetLibrary list
        p = pathlib.Path(self.capbase.base_loc + '/' + protocolLabel)
        pathList = []
        try:
            with p.open('r') as rf:
                pathList = rf.readlines()
        except:
            print("Base File Path does not exist ...")

        if len(pathList) > 0:
            for file_path in pathList:
                self.packetLibrary.append(MetaPacketCap(file_path,protocolLabel))
        else:
            print("Base Protocol file is empty.")

        return

    def load_all_from_bases(self):
        return



httpCapLib = MetaCapLibrary()
httpCapLib.load_pcaps_from_files(protocol_base='http')

