# from scapy.all import *
# from collections import Counter, namedtuple
# import math
# import random
#
# import MetaPacketCap
import logging

class PacketDigester(object):

    def __init__(self):
        '''Do initialization stuff'''
        self.logger = logging.getLogger(__name__)
        #self.logger.setLevel(logging.INFO)
        #self.logger.setLevel(logging.DEBUG)
        self.logger.setLevel(logging.WARNING)

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

        self.logger.debug("Finished Digesting pcap files ...")
        # print("Type : ", type(self.cap))

    def ingest(self, pcapFile):
        '''
        Take Packet Capture Object and read out the packets
        :param pcapFile:
        :return:
        '''

    def getPopulationLists(self, testName, testMetaPcapSeq, grndTruthMpcapSeq):
        self.populationSeqs['testSeq'] = testMetaPcapSeq
        self.populationSeqs['grndTruthSeq'] = grndTruthMpcapSeq

        self.logger.debug("Test against: %s" % testName)
        self.logger.debug("\t Ground Truth Population Seq Length: %i" % len(grndTruthMpcapSeq))
        self.logger.debug("\t Test Population Seq Length: %i" % len(testMetaPcapSeq))

        return self.populationSeqs




