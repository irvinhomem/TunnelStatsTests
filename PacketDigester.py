# from scapy.all import *
# from collections import Counter, namedtuple
# import math
# import random
#
# import MetaPacketCap

class PacketDigester(object):

    def __init__(self):
        '''Do initialization stuff'''
        # self.pcapPath = pcapFilePath
        #self.metapcap = packet_capture
        # #self.pktCharFreqDict = {}
        # self.pktCharEntropySeq = []
        # self.specificPktLens = []
        # #self.fig, self.ax = plt.subplots()
        # self.fig = plt.figure()
        # self.ax = plt.axes()

        self.populationSeqs = dict(testSeq=[],grndTruthSeq=[])
        self.multiSampleSeq = {}
        # #self.twoTestSamples = namedtuple("SampledSequences", ['x','y'])
        # self.twoTestSamples= dict(testSeq=[],grndTruthSeq=[])

        print("Finished Digesting pcap files ...")
        # print("Type : ", type(self.cap))

    def ingest(self, pcapFile):
        '''
        Take Packet Capture Object and read out the packets
        :param pcapFile:
        :return:
        '''

    def getPopulationLists(self,testName, testMetaPcapSeq, grndTruthMpcapSeq):
        self.populationSeqs['testSeq'] = testMetaPcapSeq
        self.populationSeqs['grndTruthSeq'] = grndTruthMpcapSeq

        print("Test against: ", testName)
        print("\t Ground Truth Population Seq Length: ", len(grndTruthMpcapSeq))
        print("\t Test Population Seq Length: ", len(testMetaPcapSeq))

        return self.populationSeqs




