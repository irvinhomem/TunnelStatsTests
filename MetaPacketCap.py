import PacketAnalyzer
import PacketDigester

from scapy.all import *
from collections import Counter, namedtuple
import math

class MetaPacketCap(object):

    def __init__(self, file_path):
        self.pcapFilePath = file_path
        self.cap = rdpcap(self.pcapFilePath)

        self.pktCharFreqDict = {}
        self.pktCharEntropySeq = []
        self.specificPktLens = []

        print("Finished initializing and reading pcap file ...")
        print("Type : ", type(self.cap))

    # def set_file_path(self, file_path):
    #     self.pcapFilePath = file_path
    #
    # def get_pkt_char_entropy_seq(self):
    #     return self.pktCharEntropySeq
    #
    # def get_pkt_lens(self):
    #     return self.specificPktLens

    def calcEntropy(self, myFreqDict):
        '''
        Entropy calculation function
        H(x) = sum [p(x)*log(1/p)] for i occurrences of x
        Arguments: Takes a dictionary containing byte/char keys and their frequency as the value
        '''
        h = 0.0
        for aKey in myFreqDict:
            # Calculate probability of each even occurrence
            prob = myFreqDict[aKey]/sum(myFreqDict.values())
            # Entropy formula
            h += prob * math.log((1/prob),2)
        return h

    def getFtpPktEntropy(self):
        '''
        Get the Entropy of
        :return:
        '''

    def getIpPacketEntropy(self):
        '''

        :return:
        '''
        self.pktCharEntropySeq = [self.calcEntropy(Counter(bytes(pkt[IP])))
                                  for pkt in self.cap if IP in pkt]
        return self.pktCharEntropySeq

    def getDnsPktEntropy(self):
        '''

        :return:
        '''
        self.pktCharEntropySeq = [self.calcEntropy(Counter(bytes(pkt[IP][UDP][DNS])))
                                  for pkt in self.cap if UDP in pkt and pkt[UDP].dport==53]
        return self.pktCharEntropySeq


    def getHttpReqEntropy(self):
        '''
        Get the Entropy of only the HTTP Request characters in TCP packets
        that have a payload and have the destination port = 80
        :return:
        '''
        self.pktCharEntropySeq = [self.calcEntropy(Counter(bytes(pkt[IP][TCP][Raw].load)))
                                  for pkt in self.cap if TCP in pkt and Raw in pkt and pkt[TCP].dport==80]
        return self.pktCharEntropySeq


    def getHttpReqLen(self):
        self.specificPktLens = [len(pkt[IP][TCP][Raw].load)
                           for pkt in self.cap if TCP in pkt and Raw in pkt and pkt[TCP].dport==80]
        return self.specificPktLens
