from MetaCapLibrary import MetaCapLibrary
from PacketAnalyzer import PacketAnalyzer
from PacketDigester import PacketDigester

from terminaltables import AsciiTable
import logging
import sys

class ScoreBoard(object):

    def __init__(self):
        #Configure Logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        #logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        #self.logger.setLevel(logging.WARNING)

        self.handler = logging.FileHandler('scoreboard.log')
        self.handler.setLevel(logging.INFO)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.handler.setFormatter(formatter)

        self.grndTruthLib_list = []
        self.testSampleLib_list = []

        self.stats_list = ['Pearson','MeanDiff']
        # ['Pearson']
        # ['Pearson','MeanDiff']
        # ['SpearmanR','Pearson','MeanDiff']
        # ['KL-Divergence','SpearmanR','Pearson','2Samp_KSmirnov','MeanDiff']
        #self.scoreDict = dict(stat_measure='', av_score=0.0, grndLabel='')
        self.testScoreList = []

    def load_ground_truths(self):
        # Load GroundTruth library / base (Filtered)
        http_grndTruthLib = MetaCapLibrary()
        http_grndTruthLib.load_specific_proto_from_base('http-test-pico','http')
        self.grndTruthLib_list.append(http_grndTruthLib)

        ftp_grndTruthLib = MetaCapLibrary()
        ftp_grndTruthLib.load_specific_proto_from_base('ftp-test-pico', 'ftp')
        self.grndTruthLib_list.append(ftp_grndTruthLib)

        self.logger.debug("HTTP Ground Lib Len: %i " % len(http_grndTruthLib.get_packet_library()))
        self.logger.debug("FTP Ground Lib Len: %i " % len(ftp_grndTruthLib.get_packet_library()))
        self.logger.debug("Ground Lib List Len: %i " % len(self.grndTruthLib_list))

    def load_test_sample_pcaps(self):
        # Load Test-PCAP library / base (Filtered)
        HTovDns_testLib = MetaCapLibrary()
        HTovDns_testLib.load_specific_proto_from_base('http-test-pico','dns')
        self.testSampleLib_list.append(HTovDns_testLib)

        FTovDNS_testLib = MetaCapLibrary()
        FTovDNS_testLib.load_specific_proto_from_base('ftp-test-pico','dns')
        self.testSampleLib_list.append(FTovDNS_testLib)

        self.logger.debug("HTTP Test Lib Len: %i " % len(HTovDns_testLib.get_packet_library()))
        self.logger.debug("FTP Test Lib Len: %i " % len(FTovDNS_testLib.get_packet_library()))
        self.logger.debug("Test Lib List Len: %i " % len(self.testSampleLib_list))

    def getGrndTruthLib_list(self):
        return self.grndTruthLib_list

    def getTestSampleLib_list(self):
        return self.testSampleLib_list

    def getStats_list(self):
        return self.stats_list

    def calcAvgStatScores(self, stat_measure_name, test_cap, grndtruth_cap):
        pktDgstr = PacketDigester()
        pktAnlyzr = PacketAnalyzer()
        grnd_Req_Entropy_Seq = None
        avg_score_to_GRND = 0.0

        curr_grnd_proto_label = grndtruth_cap.get_proto_label()
        self.logger.debug('Current Grnd Protocol: %s' % curr_grnd_proto_label)

        if 'http'in curr_grnd_proto_label:
            grnd_Req_Entropy_Seq = grndtruth_cap.getHttpReqEntropy()    # httpMcap.get_ip_pkt_http_req_entropy()    # getHttpReqEntropy     # getCompressedHttpReqEntropy
        elif 'ftp' in curr_grnd_proto_label:
            grnd_Req_Entropy_Seq = grndtruth_cap.getFtpReqEntropy()      # ftpMcap.get_ip_pkt_ftp_req_entropy()      # getFtpReqEntropy      # getCompressedFtpReqEntropy

        if grnd_Req_Entropy_Seq != None:
            # Score against ** ANY ** GIVEN GROUND PROTOCOL
            avg_score_to_GRND, score_vals = pktAnlyzr.calcStatMeasureAvg(
                stat_measure_name,
                pktDgstr.getPopulationLists("ANY",
                    test_cap.getDnsReqDataEntropy_upstream(),   # getDnsPktEntropy
                    grnd_Req_Entropy_Seq),
                1000)
        else:
            self.logger.warning("Something wrong with protocol label ...")
            sys.exit('Something wrong with protocol label ...')

        # # Score against ** HTTP **
        # avg_score_to_HTTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        #     stat_measure_name,
        #     pktDgstr.getPopulationLists("HTTP",
        #         test_cap.getDnsReqDataEntropy_upstream(),   # getDnsPktEntropy
        #         grndtruth_cap.getHttpReqEntropy()),    # httpMcap.get_ip_pkt_http_req_entropy()    # getHttpReqEntropy     # getCompressedHttpReqEntropy
        #     1000)
        #
        # # Score against ** FTP **
        # avg_score_to_FTP, score_vals = pktAnlyzr.calcStatMeasureAvg(
        #     stat_measure_name,
        #     pktDgstr.getPopulationLists("FTP",
        #         test_cap.getDnsReqDataEntropy_upstream(),       #getDnsPktEntropy
        #         grndtruth_cap.getFtpReqEntropy()),
        #     1000)
        # return avg_score_to_HTTP, avg_score_to_FTP
        return stat_measure_name, avg_score_to_GRND, grndtruth_cap.get_proto_label()

class TestScores(object):

    def __init__(self, test_sample_name, all_ground_truth_scores_list):
        self.test_sample_pcap_name = test_sample_name
        self.ground_truth_aggregate_scores = all_ground_truth_scores_list

class SingleGroundTruthScores(object):

    def __init__(self, ground_truth_lbl, list_of_StatScores):
        self.ground_truth_label = ground_truth_lbl
        self.stat_scores = list_of_StatScores

class StatScore(object):

    def __init__(self, statName, statScore, grndLbl):
        self.stat_name = statName
        self.score = statScore
        self.ground_label = grndLbl

myScoreB = ScoreBoard()

# Load GroundTruth library / base (Filtered)
myScoreB.load_ground_truths()

# Load Test-PCAP library / base (Filtered)
myScoreB.load_test_sample_pcaps()
#test_against_grnd_dict = []
#grnd_comp_scores = dict(grnd_truth_lbl='', scoreDict={})
#grnd_truth_scores_aggr = []
all_scores =[]
# Generally: Pick a specific test-PCAP file and compare it against the Ground Truth Base files / Statistics
for sample_lib in myScoreB.testSampleLib_list:
    # There are 2 test sample libs at the moment: FTP and HTTP (Containing both 'plain' and 'over DNS')
    myScoreB.logger.debug('In Sample Lib: %s' % sample_lib.capbase.get_base_loc())
    for mpcap_test in sample_lib.get_packet_library():
        # Get a particular MetaPacketCap test sample
        myScoreB.logger.debug('===== Current Test MCap: %s ==============' % mpcap_test.pcapFilePath)
        #newTestScore = TestScores()
        all_ground_truth_scores = []
        for grnd_lib in myScoreB.grndTruthLib_list:
            # There are 2 Ground Truth libs at the moment (FTP and HTTP) corresponding to the test sample libs
            myScoreB.logger.debug('In Grnd Lib: %s' % grnd_lib.capbase.get_base_loc())
            for mpcap_grnd in grnd_lib.get_packet_library():
                # Get a particular ground truth MetaPacket cap to test against the given MetaPacketCap test sample
                myScoreB.logger.debug('---------- Current Ground Truth MCap:: %s ----------' % mpcap_grnd.pcapFileName)
                #scorelist_perGrnd = []
                score_set_perGrnd = []
                for stat in myScoreB.getStats_list():
                    myScoreB.logger.debug('--------------- Calculating Stat:: %s ----------' % stat)
                    stat_name, stat_score, grnd_label = myScoreB.calcAvgStatScores(stat, mpcap_test, mpcap_grnd)
                    currStat_score =  StatScore(stat_name, stat_score, grnd_label)
                    score_set_perGrnd.append(currStat_score)

                    myScoreB.logger.debug('Stat Name: %s' % stat_name)
                    myScoreB.logger.debug('Stats Score: {0:10.7f}'.format(stat_score))
                    myScoreB.logger.debug('Stats Score-Set Len per-Ground: %i' % len(score_set_perGrnd))

                one_ground_truth_scores = SingleGroundTruthScores(mpcap_grnd.pcapFileName, score_set_perGrnd)
                all_ground_truth_scores.append(one_ground_truth_scores)
                #grnd_comp_scores['grnd_truth_lbl'] = mpcap_grnd.pcapFileName
                #grnd_comp_scores['scoreDict']= scorelist_perGrnd
                myScoreB.logger.debug('Ground Truth Label being stored: %s' % one_ground_truth_scores.ground_truth_label)
                # Variable below (i.e. grnd_truth_scores_aggr) holds the test scores of a single test_cap against
                # all the ground_truth caps available
                #grnd_truth_scores_aggr.append(grnd_comp_scores)
                myScoreB.logger.debug('Per TestCap tests against all ground truth curr len: %i' % len(all_ground_truth_scores))
        test_cap_and_all_scores = TestScores(mpcap_test.pcapFileName, all_ground_truth_scores)
        all_scores.append(test_cap_and_all_scores)


myScoreB.logger.debug("Score List Len || No. of Test Samples: %i" % len(all_scores))

print("Test item (row) 1: ", all_scores[0].test_sample_pcap_name)

myScoreB.logger.debug("No. of Ground Truths: %i" % len(all_scores[0].ground_truth_aggregate_scores))

print("Ground Truth (Col) 1: ", all_scores[0].ground_truth_aggregate_scores[0].ground_truth_label)
print("Ground Truth (Col) 2: ", all_scores[0].ground_truth_aggregate_scores[1].ground_truth_label)

myScoreB.logger.debug("No. of Stats Tests per Test+Ground Truth Pair: %i" % len(all_scores[0].ground_truth_aggregate_scores[0].stat_scores))

print("Test Group 1 score stat 1: ", all_scores[0].ground_truth_aggregate_scores[0].stat_scores[0].stat_name)
print("Test Group 1 stat 1 score: ", all_scores[0].ground_truth_aggregate_scores[0].stat_scores[0].score)
print("Test Group 2 score stat 1: ", all_scores[0].ground_truth_aggregate_scores[1].stat_scores[0].stat_name)
print("Test Group 2 stat 1 score: ", all_scores[0].ground_truth_aggregate_scores[1].stat_scores[0].score)


table_data = []
header_row = []
header_row.append('')

for idx_r, row in enumerate(all_scores):
    myScoreB.logger.debug('Row: %i :: Test Cap: %s' % (idx_r, row.test_sample_pcap_name))
    single_row = []
    single_row.append(row.test_sample_pcap_name)
    for idx_c, col in enumerate(row.ground_truth_aggregate_scores):
        myScoreB.logger.debug('Row: %i :: Test Cap: %s :: Col: %i :: Ground Truth Label: %s'
                              % (idx_r, row.test_sample_pcap_name, idx_c, col.ground_truth_label))
        if col.ground_truth_label not in header_row:
            header_row.append(col.ground_truth_label)
        score_string = ''
        for idx_3, dim3 in enumerate(col.stat_scores):
            myScoreB.logger.debug('Row: %i :: Test Cap: %s :: Col: %i :: Ground Truth Label: %s ::'
                                  ' Stat: %i :: %s : %10.7f'
                              % (idx_r, row.test_sample_pcap_name, idx_c, col.ground_truth_label,
                                 idx_3, dim3.stat_name, dim3.score))
            score_string += str(dim3.stat_name + ' : ' + str(dim3.score) + '\n')
            myScoreB.logger.debug('Score String: %s' % score_string.replace('\n', ':::'))
        single_row.append(score_string)
        myScoreB.logger.debug('Current Length of Row: %i' % len(single_row))
        myScoreB.logger.debug('Row item 1: %s' % single_row[0])
        myScoreB.logger.debug('Row item 2: %s' % single_row[1])
    table_data.append(single_row)

myScoreB.logger.debug("Header Row Len : %i" % len(header_row))

table_data.append(header_row)

myTable = AsciiTable(table_data)
myTable.inner_row_border = True
print(myTable.table)


