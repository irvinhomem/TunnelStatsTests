from scapy.all import *
from collections import Counter
from scipy.stats import kstest
from scipy.stats import entropy, spearmanr, pearsonr
from scipy.spatial.distance import correlation, euclidean, minkowski, mahalanobis

import matplotlib.pyplot as plt
import math
import sklearn
import time


class PacketCapture(object):
    #fig = plt.figure()
    #fig.add_subplot
    #plt

    def __init__(self, pcapFilePath):
        '''Do initialization stuff'''
        self.pcapPath = pcapFilePath
        self.cap = rdpcap(self.pcapPath)
        #self.pktCharFreqDict = {}
        self.pktCharEntropySeq = []
        self.specificPktLens = []
        #self.fig, self.ax = plt.subplots()
        self.fig = plt.figure()
        self.ax = plt.axes()

        print("Finished initializing and reading pcap file ...")
        print("Type : ", type(self.cap))

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

    def getEquiSampleLen(self, testSeq, grndTruthSeq):
        '''
        - Determines the lengths of the two sequences
        - Selects 95% of the packets of the shorter sample
        :return:
        '''
        newSeqLen = (int(math.ceil(0.95 * len(testSeq)))
                     if len(testSeq) < len(grndTruthSeq)
                     else int(math.ceil(0.95 * len(grndTruthSeq))))
        print("New Equalized Sequence Length: ", newSeqLen)
        return newSeqLen

    def doSampling(self):
        '''
        Given the new equivalent sample length from getEquiSampleLen():
        - Randomly select a continuous sequence of values of the given length between Packet 1 and the length of the Packet
        - Returns 2 samples of the same length; one from the test sample and one from the "ground truth"
        :return:
        '''


    def calcKLDistance(self, testSeq, grndTruthSeq):
        '''
        Coincidentally the Kulback-Leibler Divergence (KL-distance) Test is actually somehow similar to Entropy
        where: entropy(pk, qk, base)
        NB: 'pk' and 'qk' must have the same length
        :return:
        '''
        kLdistResult = entropy(testSeq, grndTruthSeq)
        return kLdistResult

    def calcSpearman(self, testSeq, grndTruthSeq):
        '''
        Calculate
        :return:
        '''
        rho, pVal = spearmanr(testSeq, grndTruthSeq, axis=0)
        return spearmanr(testSeq, grndTruthSeq, axis=0)

    def calcPearson(self):
        '''
        Calculate
        :return:
        '''



    def doPlot(self, plotTitle, xlbl, ylbl):
        '''
        Plot the points given from the given sequence
        '''
        #plt.plot(perPktCharEntropySeq, marker="+", markeredgecolor="red", linestyle="solid", color="blue")
        self.ax = self.fig.add_subplot(1,1,1)
        self.ax.plot(self.pktCharEntropySeq, marker="+", markeredgecolor="red", linestyle="None", color="blue")
        #plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
        #self.fig.add_subplot()
        self.ax.set_title(plotTitle, size = 16)
        #self.fig.
        #self.fig.add_axes(xlabel=xlbl, ylabel=ylbl)
        self.ax.set_xlabel(xlbl, size=11)
        self.ax.set_ylabel(ylbl, size=11)
        #self.ax.xlabel("Packet Sequence (Time)", size=11)
        #self.ax.ylabel("Byte (Char) Entropy per packet", size=11)
        self.fig.show()
        self.fig.savefig()
        self.fig.waitforbuttonpress()
        #time.sleep(10)



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

    def getDNSPacketEntropy(self):
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




#if __name__ == "main":
# 1. Read pcap file
# 2. Get specific entropy function,
# 3. "do plot"
#httpCapture = PacketCapture("../scapy_tutorial/TestPcaps/HTTP.pcap")
httpCapture = PacketCapture("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTP.pcap")
httpOvrDnsCap = PacketCapture("../scapy_tutorial/NewPcaps/TunnelCaps_2011/HTTPoverDNS.pcap")
print("Intialized ... ")
httpCapture.getHttpReqEntropy()

## Calculate Kullback-Leibler Divergence
#compKsResult = httpCapture.calcKLDistance(httpOvrDnsCap.getHttpReqEntropy(), httpCapture.getHttpReqEntropy())
#print("Kullback-Leibler Distance result: ", compKsResult)

## Calculcate Spearman coefficient of correlation
#spearmanCoeff = httpCapture.calcSpearman(httpOvrDnsCap.getHttpReqEntropy(),httpCapture.getHttpReqEntropy())
#print("Spearman Correlation Coefficient: ", spearmanCoeff)

##
httpCapture.doSampleEqualizer(httpOvrDnsCap.getDNSPacketEntropy(), httpCapture.getHttpReqEntropy())

httpCapture.doPlot("HTTP Request Entropy", "Packet Sequence (Time)", "Byte (Char) Entropy per packet")




