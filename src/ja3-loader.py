#!/usr/bin/env python3
import PyAnalyticsCommon as analytics
import json
import functools
import os, sys
from threatgraph import Gaffer
import gaffer
import datetime
import time
import threading
import queue
import pickle

#############################################################################
# Setup AMQP etc.
#############################################################################

sys.stdout.write("Create AMQP connections...\n")
sys.stdout.flush()

broker=broker=os.getenv("AMQP_BROKER", "amqp")

in_ex=os.getenv("AMQP_INPUT_EXCHANGE", "default")
in_key=os.getenv("AMQP_INPUT_ROUTING_KEY", "ja3-window.key")
in_queue=os.getenv("AMQP_INPUT_QUEUE", "worker.ja3-loader.in")

analytics.setup('ja3-loader')
con = analytics.Subscriber(broker=broker, queue=in_queue, routing_key=in_key,
                           exchange=in_ex)

# Expire cache on 3 days.
expiry_period=86400*3

# Internal FIFO spreading load across threads.  Helps lubricate things out
# when requests take a while to process.
q = queue.Queue(maxsize=50)

# Concurrency lock
lock=threading.Lock()

# Gaffer API client
gaffer_url = os.getenv("GAFFER_URL", "http://gaffer-threat:8080")
#gaffer_url = os.getenv("GAFFER_URL", "http://gaffer:8080")

if gaffer_url != None:
    sys.stdout.write("Will use Gaffer at: %s" % gaffer_url)
    sys.stdout.flush()


#############################################################################
# Callback, called to handle an input message.
# Input messages are a ja3digest dict created by ja3-window and
# puts it on a worker queue
#############################################################################

# Handler, called for each incoming message.
def callback(body):

    try:
        # Get input data, a Python object.
        start, obj = pickle.loads(body)
        q.put(obj)

    except Exception as e:
        sys.stderr.write("call back exception: %s\n" % e)
        sys.stderr.flush()


class Processor(threading.Thread):       

    # Constructor: Call thread initialisation
    def __init__(self):
        threading.Thread.__init__(self)  
        if gaffer_url != None:
            self.gr = Gaffer(gaffer_url)
        else:
            self.gr = None                      

    # Thread body
    def run(self):

        lock.acquire()
        sys.stdout.write("Processor starting...\n")
        sys.stdout.flush()
        lock.release()
        
        while True:

            obj = q.get()
            lock.acquire()
            ja3entitiesandedges = []

            for ja3key, values in obj.items():
                earliest = getEarliestSeenTime(values["times"])
                count = values["count"]
                device = ja3key[0]

                jobj = json.loads(ja3key[1])
                srcipport = jobj["src"]

                ja3digest = jobj["ja3digest"]

                #add ja3 entity
                ja3entitiesandedges.append(createJA3DigestEntity(ja3digest, earliest))
                #add ja3 isemitting edge
                ja3entitiesandedges.append(createIsEmitingEdge(device, ja3digest, earliest, count))

            
            # If Gaffer is in use, write to Gaffer.
            if self.gr != None:

                # Turn element list into a Gaffer operation
                elts = {
                    "class": "uk.gov.gchq.gaffer.operation.impl.add.AddElements",
                    "validate": True,
                    "skipInvalidElements": False,
                    "input": ja3entitiesandedges
                }

                # Execute Gaffer insert
                url = "/rest/v2/graph/operations/execute"
                try:
                    data = json.dumps(elts)
                    response = self.gr.post(url, data)
                    # If status code is bad, output error and ignore.
                    if response.status_code != 200:
                        sys.stdout.write("Gaffer error: %s\n" % response.text)                                                
                        sys.stdout.flush()

                except Exception as e:
                    # If exception, output error and ignore.
                    sys.stderr.write("Exception: %s\n" % e)
                    sys.stdout.flush()

            lock.release()

def getEarliestSeenTime(times):
    '''
    getEarliestSeenTime
    Find earliest time in list of times
    '''
    sorted_times = list(times)
    sorted_times.sort()
    return sorted_times[0]

def createJA3DigestEntity(ja3digest, time):
    '''
    createJA3DigestEntity
    Generate entity to add to threat graph.
    Format is as follows:
    {
        "class": "uk.gov.gchq.gaffer.data.element.Entity",
        "vertex": ja3digest,
        "group": "ja3",
        "properties" : {
            "time": <timestamp>
        }
    }
    '''
    

    entity = {
        "class" : "uk.gov.gchq.gaffer.data.element.Entity",
        "vertex": ja3digest,
        "group" : "ja3",
        "properties" : {
            "time": {
                    "uk.gov.gchq.gaffer.time.RBMBackedTimestampSet": {
                        "timeBucket": "HOUR",
                        "timestamps": [time]
                    }
            }
        }
    }

    return entity

def createIsEmitingEdge(src, ja3digest, time, count):
    '''
    createIsEmitingEdge
    Generate edge to add to threat graph.
    Format is as follows:
    {
        "class" : "uk.gov.gchq.gaffer.data.element.Edge",
        "group" : "isemitting",
        "source" : <device-name>,
        "destination" : ja3digest,
        "directed" : true,
        "properties" : {
            "count" : 1,
            "time": <timestamp>
        }
    }
    '''

    edge = {
        "class" : "uk.gov.gchq.gaffer.data.element.Edge",
        "group" : "isemitting",
        "source" : src,
        "destination" : ja3digest,
        "directed" : True,
        "properties" : {
            "count" : count,
            "time": {
                    "uk.gov.gchq.gaffer.time.RBMBackedTimestampSet": {
                        "timeBucket": "HOUR",
                        "timestamps": [time]
                    }
            }
        }
    }

    return edge

#############################################################################
# main
#############################################################################

# Start threads.
thrs = []
for i in range(0, 5):
    thr = Processor()
    thr.start()
    thrs.append(thr)

# Consume from queue
sys.stdout.write("Initialised, start consuming...\n")
sys.stdout.flush()

con.consume(callback)