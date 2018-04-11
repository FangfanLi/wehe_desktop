'''
#######################################################################################################
#######################################################################################################
Copyright 2018 Northeastern University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
       
       
USAGE:
    sudo python replay_analyzerServer.py --port=56565 --ConfigFile=configs_local.cfg 
    
    IMPORTANT NOTES: always run in sudo mode
#######################################################################################################
#######################################################################################################
''' 

import multiprocessing, json, datetime, logging, pickle, sys, traceback
import tornado.ioloop, tornado.web
from multiprocessing_logging import install_mp_handler
from python_lib import *
try:
    import db as DB
except:
    print '\n\nNO DATABASE AVAILABLE\n\n'
    DB = None
sys.path.append('testHypothesis')
import testHypothesis as TH
import finalAnalysis as FA

db     = None
POSTq  = multiprocessing.Queue()
logger = logging.getLogger('replay_analyzer')

def processResult(results):
    # Only if ks2ration > ks2Beta (this is the confidence interval) the ks2 result is trusted, otherwise only the area test is used
    # Default suggestion: areaThreshold 0.1, ks2Beta 95%, ks2Threshold 0.05
    # KS2:
    # ks2Threshold is the threshold for p value in the KS2 test, if p greater than it, then we cannot
    # reject the hypothesis that the distributions of the two samples are the same
    # If ks2pvalue suggests rejection (i.e., p < ks2Threshold), where accept rate < (1 - ks2Beta), the two distributions are not the same (i.e., differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Area:
    # if area_test > areaThreshold, the two distributions are not the same (i.e., Differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Return result score, 0  : both suggests no differentiation
    #                      1  : inconclusive conclusion from two methods (Considered as no differentiation so far)
    #                      2  : both suggests differentiation
    #                      if target trace has less throughput, return negative value respectively, e.g., -1 means target trace is throttled
    #        result rate: differentiated rate = (normal - throttled)/throttled

    # Should only be one result since unique (userID, historyCount, testID)
    result = results[0]
    areaT = Configs().get('areaThreshold')
    ks2Beta  = Configs().get('ks2Beta')
    ks2T  = Configs().get('ks2Threshold')

    outres = {'userID'    : result['userID'],
              'historyCount': result['historyCount'],
              'replayName'  : result['replayName'],
              'date'        : result['date'],
              'xput_avg_original' : result['xput_avg_original'],
              'xput_avg_test': result['xput_avg_test'],
              'area_test' : result['area_test'],
              'ks2pVal': result['ks2pVal']}

    outres['against'] = 'test'

    Negative = False
    # if the controlled flow has less throughput
    if result['xput_avg_test'] < result['xput_avg_original']:
        Negative = True

    # ks2_ratio test is problematic, sometimes does not give the correct result even in the obvious cases, not using it so far
    # 1.Area test does not pass and 2.With confidence level ks2Beta that the two distributions are the same
    # Then there is no differentiation
    if (result['area_test'] < areaT) and (result['ks2pVal'] > ks2T):
        outres['diff'] = 0
        outres['rate'] = 0
    # 1.Area test does pass and 2.With confidence level ks2Beta that the two distributions are not the same
    # Then there is differentiation
    elif (result['area_test'] > areaT) and (result['ks2pVal'] < ks2T):
        outres['diff'] = 2
        outres['rate'] = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])
    # Else inconclusive
    else:
        outres['diff'] = 1
        outres['rate'] = 0

    if Negative:
        outres['diff'] = - outres['diff']
        outres['rate'] = - outres['rate']
        
    return outres

# Logic:
# 1. Analyze with the throughput info sent by client (which would create a client decision file for the GET handle to answer client request)
# 2. Insert client analysis result to the database
# 3. Use the tcpdump trace to perform server side analysis (if tcpdump enabled)
# 4. Insert server side analysis results
def analyzer(args, resultsFolder, xputBuckets, alpha):
    global db
    
    LOG_ACTION(logger, 'analyzer:'+str(args))
    args = json.loads(args)
    clientAnalysisStarts = time.time()

    resObjClient = FA.finalAnalyzer(args['userID'][0], args['historyCount'][0], args['testID'][0], resultsFolder, xputBuckets, alpha, side='Client')
    clientAnalysisEnds = time.time()

    # LOG_ACTION(logger, 'Took {} seconds for the client side analysis for UserID {} and historyCount {} testID {} ***'.format(
    #     clientAnalysisEnds - clientAnalysisStarts, args['userID'][0], args['historyCount'][0], args['testID'][0]))

    clientInsertStarts = time.time()

    try:
        # Insert result into a database
        # if resObjClient != None:
        #     LOG_ACTION(logger, 'Insertion Client result:' + str(resObjClient.tuplify()))
        #     db.insertResult(resObjClient, table='testResultc')
        print '\r\n CILENT SKIP INSERTING FOR NOW', args['userID'][0], args['historyCount'][0], args['testID'][0]
    except Exception as e:
        LOG_ACTION(logger, 'Insertion exception:'+str(e), level=logging.ERROR)

    clientInsertEnds = time.time()

    # We only need to worry this time difference if it is larger than 1 seconds
    # LOG_ACTION(logger, 'Took {} seconds to insert client side analysis into the database for UserID {} and historyCount {} testID {} ***'.format(
    #     clientInsertEnds - clientInsertStarts, args['userID'][0], args['historyCount'][0], args['testID'][0]))

    serverAnalysisStarts = time.time()

    resObjServer = FA.finalAnalyzer(args['userID'][0], args['historyCount'][0], args['testID'][0], resultsFolder, xputBuckets, alpha, side='Server')

    serverAnalysisEnds = time.time()
    cpuPercent, memPercent, diskPercent, upLoad = getSystemStat()

    if (serverAnalysisEnds - serverAnalysisStarts) > 1:
        LOG_ACTION(logger, 'Took {} seconds for server side analysis and cleaning up for UserID {} and historyCount {} testID {} *** CPU {}% MEM {}% DISK {}% UPLOAD {}Mbps'.format(
                serverAnalysisEnds - serverAnalysisStarts, args['userID'][0], args['historyCount'][0], args['testID'][0],cpuPercent, memPercent, diskPercent, upLoad ))

    serverInsertStarts = time.time()
    try:
        # TODO ADD THE database back
        # if resObjClient != None:
        #     LOG_ACTION(logger, 'Insertion Client result:' + str(resObjServer.tuplify()))
        #     db.insertResult(resObjServer, table='testResults')
        print '\r\n SERVER SKIP INSERTING FOR NOW', args['userID'][0], args['historyCount'][0], args['testID'][0]
    except Exception as e:
        LOG_ACTION(logger, 'Insertion exception:'+str(e), level=logging.ERROR)
    serverInsertEnds = time.time()
    # LOG_ACTION(logger, 'Took {} seconds to insert server side analysis into the database for UserID {} and historyCount {} testID {} ***'.format(
    #     serverInsertEnds - serverInsertStarts, args['userID'][0], args['historyCount'][0], args['testID'][0]))
    
def jobDispatcher(q, processes=4):
    resultsFolder = Configs().get('resultsFolder')
    xputBuckets  = Configs().get('xputBuckets')
    alpha         = Configs().get('alpha')
    pool = multiprocessing.Pool(processes=processes)
    while True:
        args = q.get()
        # print '\r\n GOING TO ANALYZER',args
        pool.apply_async(analyzer, args=(args, resultsFolder, xputBuckets, alpha,))

class myJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            obj = obj.isoformat()
        else:
            obj = super(myJsonEncoder, self).default(obj)
        return obj    

def getHandler(args):
    '''
    Handles GET requests.
    
    Basically gets a request (i.e. MySQL job), does appropriate DB lookup, and returns results.
    
    If something wrong with the job, returns False. 
    '''
    global db
    
    try:
        command = args['command'][0]
    except:
        return json.dumps({'success':False, 'error':'command not provided'})
    
    try:
        userID       = args['userID'][0]
    except KeyError as e:
        return json.dumps({'success':False, 'missing':str(e)})
    
    if command == 'singleResult':
        try:
            historyCount = int(args['historyCount'][0])
            testID = int(args['testID'][0])
        except Exception as e:
            return json.dumps({'success':False, 'error':str(e)})

        # LOG_ACTION(logger, 'Client asks for the result for UserID {} and historyCount {} testID {} ***'.format(
        #     userID, historyCount, testID))
        # First try loading the local results:
        resultFile = ('/data/RecordReplay/ReplayDumps/' + userID + '/decisions/' + 'results_{}_{}_{}_{}.json').format(userID, 'Client',
                                                                                                historyCount, testID)

        replayInfoFile = ('/data/RecordReplay/ReplayDumps/' + userID + '/replayInfo/' + 'replayInfo_{}_{}_{}.json').format(userID, historyCount, testID)


        if os.path.isfile(resultFile) and os.path.isfile(replayInfoFile):
            results = json.load(open(resultFile, 'r'))
            info = json.load(open(replayInfoFile, 'r'))

            realID = info[2]
            replayName = info[4]
            extraString = info[5]
            incomingTime = info[0]
            # incomingTime = strftime("%Y-%m-%d %H:%M:%S", gmtime())
            areaTest = str(results[0])
            ks2ratio = str(results[1])
            xputAvg1 = str(results[4][2])
            xputAvg2 = str(results[5][2])
            ks2dVal = str(results[9])
            ks2pVal = str(results[10])

            return json.dumps({'success': True,
                               'response' : {'replayName':replayName,'date':incomingTime, 'userID':userID, 'extraString':extraString, 'historyCount': str(historyCount),'testID': str(testID),'area_test': areaTest, 'ks2_ratio_test': ks2ratio, 'xput_avg_original': xputAvg1, 'xput_avg_test': xputAvg2, 'ks2dVal': ks2dVal, 'ks2pVal': ks2pVal}}, cls=myJsonEncoder)
        else:

            # provide raw result to the client, let client decide whether differentiation,
            # give flexibility in setting parameters
            responseS = db.getSingleResult(userID, historyCount, testID)
            # Should only be one result since unique (userID, historyCount, testID)
            if not responseS:
               return json.dumps({'success': False, 'error': 'No result found'})
            # If we have client side results, send it, otherwise, send server side results
            responseC = db.getSingleResult(userID, historyCount, testID, table='testResultc')
            if responseC:
                return json.dumps({'success': True, 'response': responseC[0]}, cls=myJsonEncoder)
            else:
                return json.dumps({'success': False, 'error': 'No result found'})

    # Return the latest threshold for both area test and ks2 test
    elif command == 'defaultSetting':
        # Default setting for the client
        areaThreshold = 0.1
        ks2Threshold = 0.05
        ks2Ratio = 0.95
        return json.dumps({'success':True, 'areaThreshold':str(areaThreshold), 'ks2Threshold':str(ks2Threshold),
                           'ks2Ratio':str(ks2Ratio)}, cls=myJsonEncoder)
    
    else:
        return json.dumps({'success':False, 'error':'unknown command'})
    
def postHandler(args):
    '''
    Handles POST requests.
    
    Basically puts the job on the queue and return True.
    
    If something wrong with the job, returns False. 
    '''
    try:
        command = args['command'][0]
    except:
        return json.dumps({'success':False, 'error':'command not provided'})
    
    try:
        userID       = args['userID'][0]
        historyCount = int(args['historyCount'][0])
        testID = int(args['testID'][0])
    except KeyError as e:
        return json.dumps({'success':False, 'missing':str(e)})
    
    if command == 'analyze':
        POSTq.put(json.dumps(args))
    else:
        return json.dumps({'success':False, 'error':'unknown command'})

    LOG_ACTION(logger, 'Returning for POST UserID {} and historyCount {} testID {} ***'.format(
        userID, historyCount, testID))
    
    return json.dumps({'success':True})

class Results(tornado.web.RequestHandler):
    
    @tornado.web.asynchronous
    def get(self):
        pool = self.application.settings.get('GETpool')
        args = self.request.arguments
        LOG_ACTION(logger, 'GET:'+str(args))
        pool.apply_async(getHandler, (args,), callback=self._callback)

    @tornado.web.asynchronous
    def post(self):
        # args = self.request.arguments
        # LOG_ACTION(logger, 'POST:'+str(args))
        # self.write( postHandler(args) )
        pool = self.application.settings.get('POSTpool')
        args = self.request.arguments
        LOG_ACTION(logger, 'POST:' + str(args))
        pool.apply_async(postHandler, (args,), callback=self._callback)
        
    @tornado.web.asynchronous
    def post_old(self):
        pool = self.application.settings.get('POSTpool')
        args = self.request.arguments
        pool.apply_async(postHandler, (args,), callback=self._callback)
    
    def _callback(self, response):
        LOG_ACTION(logger, '_callback:'+str(response))
        self.write(response)
        self.finish()

def main():
    
    global db
    
    # PRINT_ACTION('Checking tshark version', 0)
    # TH.checkTsharkVersion('1.8')
    
    configs = Configs()
    configs.set('GETprocesses' , 16)
    configs.set('ANALprocesses', 16)
    configs.set('POSTprocesses', 16)
    configs.set('xputInterval' , 0.25)
    configs.set('alpha'        , 0.95)
    configs.set('mainPath'     , '/data/RecordReplay/')
    configs.set('resultsFolder', 'ReplayDumps/')
    configs.set('logsPath'     , 'logs/')
    configs.set('analyzerLog'  , 'analyzerLog.log')
    configs.read_args(sys.argv)
    configs.check_for(['analyzerPort'])
    
    PRINT_ACTION('Configuring paths', 0)
    configs.set('resultsFolder' , configs.get('mainPath')+configs.get('resultsFolder'))
    configs.set('logsPath'      , configs.get('mainPath')+configs.get('logsPath'))
    configs.set('analyzerLog'   , configs.get('logsPath')+configs.get('analyzerLog'))
    
    PRINT_ACTION('Setting up logging', 0)
    if not os.path.isdir(configs.get('logsPath')):
        os.makedirs(configs.get('logsPath'))

    createRotatingLog_multip(logger, configs.get('analyzerLog'))
    # This is for multi-processing safe logging
    # install_mp_handler()
    configs.show_all()

    if Configs().get('UseDB'):
        db = DB.DB()
    else:
        db = None
    LOG_ACTION(logger, 'Starting server. Configs: '+str(configs), doPrint=False)
    
    p = multiprocessing.Process(target=jobDispatcher, args=(POSTq,), kwargs={'processes':configs.get('ANALprocesses')})
    p.start()
    
    application = tornado.web.Application([(r"/Results", Results),
                                           ])
    
    # application.settings = {'GETpool'  : multiprocessing.Pool(processes=configs.get('GETprocesses')),
    #                         'debug': True,
    #                         }

    application.settings = {'GETpool'  : multiprocessing.Pool(processes=configs.get('GETprocesses')),
                            'POSTpool'  : multiprocessing.Pool(processes=configs.get('POSTprocesses')),
                            'debug': True,
                            }
    
    application.listen(configs.get('analyzerPort'))
    
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()
