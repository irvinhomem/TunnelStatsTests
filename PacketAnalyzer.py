# from scapy.all import *
# from collections import Counter, namedtuple

from scipy.stats import kstest
from scipy.stats import entropy, spearmanr, pearsonr, ks_2samp
from scipy.spatial.distance import correlation, euclidean, minkowski, mahalanobis

import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import math
import random

import sklearn
import time

# from PacketDigester import PacketDigester


class PacketAnalyzer(object):
    #fig = plt.figure()
    #fig.add_subplot
    #plt

    def __init__(self):
        '''Do initialization stuff'''

        self.fig = plt.figure()
        self.ax = plt.axes()
        print("Finished initializing Analysis stuff ...")
        # print("Type : ", type(self.cap))

    def getEquiSampleLen(self, fullTestSeq, fullGrndTruthSeq):
        '''
        - Determines the lengths of the two sequences
        - Selects 95% of the packets of the shorter sample
        :return:
        '''
        newSeqLen = (int(math.ceil(0.95 * len(fullTestSeq)))
                     if len(fullTestSeq) < len(fullGrndTruthSeq)
                     else int(math.ceil(0.95 * len(fullGrndTruthSeq))))
        # print("New Equalized Sequence Length: ", newSeqLen)
        return newSeqLen

    def getTwoEquiLenSamples(self, fullTestSeq, fullGrndTruthSeq):
        '''
        Given the new equivalent sample length from getEquiSampleLen():
        - Randomly select a continuous sequence of values of the given length between Packet 1 and the length of the Packet
        - Returns 2 samples of the same length; one from the test sample and one from the "ground truth"
        :return: A Dictionary containing the 2 list/seq samples (testSeq,grndTruthSeq)
        '''
        newSeqLen = self.getEquiSampleLen(fullTestSeq, fullGrndTruthSeq)
        testSeqStart = random.randint(1, len(fullTestSeq) - newSeqLen)
        grndTruthSeqStart = random.randint(1, len(fullGrndTruthSeq) - newSeqLen)

        # print("Sample Test Seq Starting Point: ", testSeqStart)
        # print("Ground Truth Seq Starting Point: ", grndTruthSeqStart)

        newTestSeqList = fullTestSeq[testSeqStart:testSeqStart + newSeqLen]
        newgrndTruthSeqList = fullGrndTruthSeq[grndTruthSeqStart:grndTruthSeqStart + newSeqLen]

        multiSampleSeq= dict(testSeq=[],grndTruthSeq=[])
        multiSampleSeq["testSeq"] = newTestSeqList
        multiSampleSeq["grndTruthSeq"] = newgrndTruthSeqList

        #print("Test X: ", self.twoTestSamples["testSeq"])
        #print("Test Y: ", self.twoTestSamples["grndTruthSeq"])

        return multiSampleSeq

    def choose_sampling_size(self):
        # To be fixed
        return


    def calcStatMeasureAvg(self, stat_measure, testPopulationSeqs, sampling_rounds):
        '''
        For the given stat_measure of choice (KL-Divergence, SpearmanR, Pearson) do a number of sampling rounds
        (given by 'sample_rounds') and get the average
        :return:
        '''
        # print("In calcStatMeasureAvg :: 'testPopulations length': ", len(testPopulationSeqs['testSeq']))

        #runningAvg = 0
        #runningSum = 0
        runningSum = []
        runningSum.clear()

        for i in range(sampling_rounds):
            twoSamples = self.getTwoEquiLenSamples(testPopulationSeqs['testSeq'], testPopulationSeqs['grndTruthSeq'])
            # Check which statistical measure we are calculating
            # print("Round: ", i)
            if stat_measure == "KL-Divergence":
                runningSum.append(self.calcKLDistance(twoSamples))
                #runningSum += self.calcKLDistance(twoSamples)
                continue
            elif stat_measure == "SpearmanR":
                runningSum.append(self.calcSpearman(twoSamples))
                #runningSum += self.calcSpearman()
                continue
            elif stat_measure == "Pearson":
                runningSum.append(self.calcPearson(twoSamples))
                #runningSum += self.calcPearson()
                continue
            elif stat_measure == "2Samp_KSmirnov":
                runningSum.append(self.calcKSmirnov_2Samp(twoSamples))
                #runningSum += self.calcPearson()
                continue

        #avg =  runningSum/sampling_rounds
        avg = np.average(runningSum)

        return avg, runningSum

    def calcKLDistance(self, twoSamples):
        '''
        Coincidentally the Kulback-Leibler Divergence (KL-distance) Test is actually somehow similar to Entropy
        where: entropy(pk, qk, base)
        NB: 'pk' and 'qk' must have the same length
        KlDiv of (pk||qk) is the amount of difference to approximate 'pk' on the model of 'qk'
        Scratch this --->'pk' is the known distribution; 'qk' is the unknown / model distribution
        :return:
        '''
        #print("Type Sample X(testSeq): ", (twoSamples["testSeq"]))
        #print("Type Sample Y(grndTruthSeq): ", (twoSamples["grndTruthSeq"]))
        #kLdistResult = entropy(twoTestSamples.x, twoTestSamples.y)
        kLdistResult = entropy(twoSamples["testSeq"],twoSamples["grndTruthSeq"])
        return kLdistResult

    def calcSpearman(self, twoSamples):
        '''
        Calculate
        :return:
        '''
        rho, pVal = spearmanr(twoSamples["testSeq"], twoSamples["grndTruthSeq"], axis=0)
        return spearmanr(twoSamples["testSeq"], twoSamples["grndTruthSeq"], axis=0)

    def calcPearson(self, twoSamples):
        '''
        Calculate
        :return:
        '''
        corrcoeff = pearsonr(twoSamples['testSeq'], twoSamples['grndTruthSeq'])
        return corrcoeff

    def calcKSmirnov_2Samp(self, twoSamples):
        '''

        :param twoSamples:
        :return:
        '''
        ks_stat, pval = ks_2samp(twoSamples['testSeq'], twoSamples['grndTruthSeq'])
        return ks_stat, pval


    def calcMahalanobis(self, twoSamples):
        inv_vector =[]
        mahalaDist = mahalanobis(twoSamples["testSeq"], twoSamples["grndTruthSeq"], inv_vector)
        #Missing the 3rd variable, so don't use this function yet
        return mahalaDist

    def doScatterPlot(self, yVariable, markercolor, plotTitle, xlbl, ylbl):
        '''
        Plot the points given from the given sequence
        '''
        #plt.plot(perPktCharEntropySeq, marker="+", markeredgecolor="red", linestyle="solid", color="blue")
        self.ax = self.fig.add_subplot(1,1,1)
        self.ax.plot(yVariable, marker="+", markeredgecolor=markercolor, linestyle="None", color="blue")
        #plt.scatter(perPktCharEntropySeq)  # missing 'y' value ... but actually it's the x value that we need
        #self.fig.add_subplot()
        self.ax.set_title(plotTitle, size = 16)
        #self.fig.
        #self.fig.add_axes(xlabel=xlbl, ylabel=ylbl)
        self.ax.set_xlabel(xlbl, size=11)
        self.ax.set_ylabel(ylbl, size=11)

        yVar_legend = ''
        self.ax.legend(handles=[yVar_legend], labels=[''])
        #self.ax.xlabel("Packet Sequence (Time)", size=11)
        #self.ax.ylabel("Byte (Char) Entropy per packet", size=11)
        self.fig.show()
        #self.fig.savefig()
        self.fig.waitforbuttonpress(timeout=-1)
        #time.sleep(10)

    def doOverlayPlot(self, varSet1, varSet2, markerclr1, markerclr2, plotTitle, xlbl, ylbl):
        myfig = plt.figure()
        #myaxes =  plt.axes()

        myaxes = myfig.add_subplot(1,1,1)
        myaxes.plot(varSet1, marker="+", markeredgecolor=markerclr1, linestyle="None", color="blue", label="test1")
        myaxes.plot(varSet2, marker="+", markeredgecolor=markerclr2, linestyle="None", color="blue", label="test2")

        myaxes.set_title(plotTitle, size = 16)
        myaxes.set_xlabel(xlbl, size=11)
        myaxes.set_ylabel(ylbl, size=11)

        blue_markers = mlines.Line2D([], [], color='red', linestyle='None', marker='+', markersize=7, label='Red stars')
        red_markers = mlines.Line2D([], [], color='blue', linestyle='None', marker='+', markersize=7, label='Blue stars')
        #myfig.legend(handles=[set1_leg,set2_leg], labels=['Label1', 'Label2'])
        markers = [blue_markers, red_markers]
        my_labels = [line.get_label() for line in markers]
        myfig.legend(handles=markers, labels=my_labels, loc='upper right')

        myfig.show()
        myfig.waitforbuttonpress(timeout=-1)

