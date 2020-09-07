# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_turgen_dehashed
# Purpose:      Spiderfoot plugin to gather compromised emails,
#               passwords, hashes, and other data from Dehashed.
#
# Author:      Sidharth V <sidharthv96@gmail.com>
#
# Created:     07-09-2020
# Copyright:   (c) Sidharth V
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import base64
import json
from urllib.parse import urlencode


class sfp_turgen_dehashed(SpiderFootPlugin):

    meta = {
        'name': "Turgen Dehashed",
        'summary': "Identify popular hashes in leaked passwords.",
        'flags': [""],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {
        'email': '',
        'api_key': '',
        'max_pages': ''
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        'email': "Email for accessing Dehashed API",
        'api_key': "Dehashed API Key.",
        'max_pages': "Maximum number of pages to query"
    }

    eventMap = {
        "email": "EMAILADDR_COMPROMISED",
        "username": "USERNAME",
        "password": "PASSWORD_COMPROMISED",
        "hashed_password": "HASH_COMPROMISED",
        "name": "HUMAN_NAME",
        "address": "PHYSICAL_ADDRESS",
        "ip_address": "IP_ADDRESS",
        "phone": "PHONE_NUMBER",
    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["EMAILADDR", "PHONE_NUMBER", "USERNAME"]

    # What events this module produces
    def producedEvents(self):
        events = []
        for event in self.eventMap.values():
            events.extend(event.split(","))
        return events

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def query(self, qry, currentPage):
        b64_auth = base64.b64encode(
            (self.opts['email'] + ":" + self.opts['api_key']).encode("utf-8"))
        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + b64_auth.decode("utf-8")
        }
        self.sf.debug(str(headers))

        query = {
            "page": currentPage,
            "query": qry
        }

        res = self.sf.fetchUrl("https://api.dehashed.com/search?" + urlencode(query),
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        self.sf.debug(str(res))
        self.sf.debug("CONTENT : ::::::::" + str(res.get('content')))
        if res.get('code') == '401':
            return None
        if res.get('content') is None:
            self.sf.debug("No Dehashed info found for " + qry)
            return None

        # Always always always process external data with try/except since we cannot
        # trust the data is as intended.
        try:
            info = json.loads(res.get('content'))
        except Exception as e:
            self.sf.error(
                "Error processing JSON response from Dehashed.", False)
            return None

        return info

    # Handle events sent to this module
    def handleEvent(self, event):
        self.sf.debug("Testing Dehashed . ")
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return None

        # Log this before complaining about a missing API key so we know the
        # event was received.
        self.sf.debug("Received event, " + eventName +
                      ", from " + srcModuleName)

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key'] == "" or self.opts['email'] == "":
            self.sf.error(
                "You enabled sfp_dehashed but did not set an email or API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        # Fetch Dehashed data for incoming data (email)
        self.sf.debug("Starting querying from DeHashed")
        currentPage = 1
        entries = []
        self.sf.debug("Current Page : " + str(currentPage))
        self.sf.debug("Max Pages : " + self.opts['max_pages'])
        while currentPage <= int(self.opts['max_pages']):
            self.sf.debug("Looking for page : " + str(currentPage))
            jsonData_temp = self.query(eventData, currentPage)
            if jsonData_temp is None:
                self.sf.error("No Data receieved")
                break
            else:
                self.sf.debug("Received : " + str(entries))
                entries.extend(jsonData_temp.get('entries'))
            # Dehashed returns 5000 results for each query
            if len(entries) >= 5000 * currentPage:
                currentPage += 1
            else:
                break

        if entries == []:
            return None

        produced = []

        for entry in entries:

            self.sf.debug("Process : " + str(entry))
            if self.checkForStop():
                return None

            breachSource = ""

            if not (entry.get('obtained_from') is None or str(entry.get('obtained_from')).strip() == ''):
                breachSource = entry.get('obtained_from')

            for key, value in entry.items():
                if value is None or value.strip() == '' or value in produced:
                    continue
                produced.append(value)
                events = self.eventMap.get(key)
                if events is None:
                    continue
                events = events.split(",")
                for e in events:
                    self.notifyListeners(SpiderFootEvent(
                        e, value + ("[" + breachSource + "]" if "_COMPROMISED" in e else ""), self.__name__, event))

            # Pass the JSON object as RAW_RIR_DATA
            evt = SpiderFootEvent("RAW_RIR_DATA", str(
                entry), self.__name__, event)
            self.notifyListeners(evt)

        return None

# End of sfp_dehashed class
