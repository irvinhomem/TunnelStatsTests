from PacketAnalyzer import PacketAnalyzer
from PacketDigester import PacketDigester
from MetaPacketCap import MetaPacketCap
from MetaCapBase import MetaCapBase

import tkinter as tk
from tkinter import filedialog
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

    def load_pcaps(self):
        file_paths = filedialog.askopenfilenames(**self.file_opt)

        for file_path in file_paths:
            #print(file_path)
            self.add_to_lib(MetaPacketCap(file_path,'http'))
            print(len(self.get_packet_library()))
            self.write_path_to_base('http', file_path)

        return file_paths

    def write_path_to_base(self, file_name, f_path):
        p = pathlib.Path(self.capbase.base_loc + '/' + file_name)
        try:
            with p.open('a+') as f:
                #Check if entry exists
                f.write(f_path+'\n')

        except:
            print("File Path does not exist ... creating base protocol file")
            file = open(self.capbase.base_loc + '/' + file_name, 'w+')
        return

    def get_packet_library(self):
        return self.packetLibrary

    #def load_specific_from_base(self, protocolLabel):

    def load_specific_proto_from_base(self, protocolLabel):
        return

    def load_all_from_base(self):
        return



httpCapLib = MetaCapLibrary()
httpCapLib.load_pcaps()



#print(filepath)
