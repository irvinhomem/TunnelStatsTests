from scapy.all import *
from collections import Counter, namedtuple
from scipy.stats import kstest
from scipy.stats import entropy, spearmanr, pearsonr
from scipy.spatial.distance import correlation, euclidean, minkowski, mahalanobis

import matplotlib.pyplot as plt
import math
import random
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
        #self.twoTestSamples = namedtuple("SampledSequences", ['x','y'])
        self.twoTestSamples= dict(testSeq=[],grndTruthSeq=[])

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

    def getTwoEquiLenSamples(self, testSeq, grndTruthSeq):
        '''
        Given the new equivalent sample length from getEquiSampleLen():
        - Randomly select a continuous sequence of values of the given length between Packet 1 and the length of the Packet
        - Returns 2 samples of the same length; one from the test sample and one from the "ground truth"
        :return: A Dictionary containing the 2 list/seq samples (testSeq,grndTruthSeq)
        '''
        newSeqLen = self.getEquiSampleLen(testSeq, grndTruthSeq)
        testSeqStart = random.randint(1, len(testSeq)-newSeqLen)
        grndTruthSeqStart = random.randint(1, len(grndTruthSeq)-newSeqLen)

        #self.twoTestSamples(
        #    x=testSeq[testSeqStart:testSeqStart+newSeqLen],
        #    y= grndTruthSeq[grndTruthSeqStart:grndTruthSeqStart+newSeqLen])
        newTestSeqList = testSeq[testSeqStart:testSeqStart+newSeqLen]
        newgrndTruthSeqList = grndTruthSeq[grndTruthSeqStart:grndTruthSeqStart+newSeqLen]

        # self.twoTestSamples.append(testSeq[testSeqStart:testSeqStart+newSeqLen])
        # self.twoTestSamples.append(testSeq[testSeqStart:testSeqStart+newSeqLen])
        self.twoTestSamples["testSeq"] = newTestSeqList
        self.twoTestSamples["grndTruthSeq"] = newgrndTruthSeqList


        #print("Test X: ", self.twoTestSamples["testSeq"])
        #print("Test Y: ", self.twoTestSamples["grndTruthSeq"])
        #0.00839789398451

        return self.twoTestSamples

    def calcStatMeasureAvg(self, stat_measure, twoSamples, sample_rounds):
        '''
        For the given stat_measure of choice (KL-Divergence, SpearmanR, Pearson) do a number of sampling rounds
        (given by 'sample_rounds') and get the average
        :return:
        '''
        #runningAvg = 0
        runningSum = 0

        for i in range(sample_rounds):
            # Check which statistical measure we are calculating
            if stat_measure == "KL-Divergence":
                runningSum += self.calcKLDistance(twoSamples)
                continue
            elif stat_measure == "SpearmanR":
                runningSum += self.calcSpearman()
                continue
            elif stat_measure == "Pearson":
                runningSum += self.calcPearson()
                continue

        avg =  runningSum/sample_rounds

        return avg

    def calcKLDistance(self, twoSamples):
        '''
        Coincidentally the Kulback-Leibler Divergence (KL-distance) Test is actually somehow similar to Entropy
        where: entropy(pk, qk, base)
        NB: 'pk' and 'qk' must have the same length
        :return:
        '''
        print("Type Sample X(testSeq): ", (twoSamples["testSeq"]))
        print("Type Sample Y(grndTruthSeq): ", (twoSamples["grndTruthSeq"]))
        #kLdistResult = entropy(twoTestSamples.x, twoTestSamples.y)
        kLdistResult = entropy(twoSamples["testSeq"], twoSamples["grndTruthSeq"])
        return kLdistResult

    def calcSpearman(self, twoSamples):
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
#compKsResult = httpCapture.calcKLDistance(httpOvrDnsCap.getDnsPktEntropy(), httpCapture.getHttpReqEntropy())
compKsResult = httpCapture.calcKLDistance(
    httpCapture.getTwoEquiLenSamples(httpOvrDnsCap.getDnsPktEntropy(), httpCapture.getHttpReqEntropy()))
print("Kullback-Leibler Distance result: ", compKsResult)

## Calculcate Spearman coefficient of correlation
#spearmanCoeff = httpCapture.calcSpearman(httpOvrDnsCap.getHttpReqEntropy(),httpCapture.getHttpReqEntropy())
#print("Spearman Correlation Coefficient: ", spearmanCoeff)

##
#httpCapture.doSampleEqualizer(httpOvrDnsCap.getDnsPktEntropy(), httpCapture.getHttpReqEntropy())

httpCapture.doPlot("HTTP Request Entropy", "Packet Sequence (Time)", "Byte (Char) Entropy per packet")




