# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_people_data_labs
# Purpose:      Looks up data from People Data Labs.
#
# Author:      Sidharth V <sidharthv96@gmail.com>
#
# Created:     2020-06-09
# Copyright:   (c) Sidharth V
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import itertools
from urllib.parse import urlencode
from netaddr import IPNetwork
from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_people_data_labs(SpiderFootPlugin):

    meta = {
        'name': "People Data Labs",
        'summary': "This looks up data from People Data Labs",
        'flags': ["tool", "apikey"],
        'useCases': ["Passive"],
        'categories': ["Real World"],
        'toolDetails': {
            'name': "People Data Labs",
            'description': "A dataset of resume, contact, social, and demographic information for over 1.5 Billion unique individuals, delivered to you at the scale you need it.",
            'website': 'https://peopledatalabs.com',
            'repository': 'https://peopledatalabs.com'
        },
        'dataSource': {
            'website': "https://api.peopledatalabs.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.peopledatalabs.com/docs"
            ],
            'apiKeyInstructions': [
                "Visit https://peopledatalabs.com",
                "Register a free account",
                "Click on 'Account Settings'",
                "Click on 'Developer'",
                "The API key is listed under 'Your API Key'"
            ],
            'favIcon': "https://www.peopledatalabs.com/favicon.ico",
            'logo': "https://www.peopledatalabs.com/static/media/pdl_white_logo.75f13a03.png",
            'description': "A dataset of resume, contact, social, and demographic information for over 1.5 Billion unique individuals, delivered to you at the scale you need it.",
        }
    }

    opts = {
        'api_key': '',
    }

    optdescs = {
        "api_key": "People Data Source API Key.",
    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None
    produced = None
    data = None

    combinations = [
        ["phone"],
        ["profile"],
        ["company", "name"],
        ["email"]
    ]

    eventMap = {
        "EMAILADDR": "email",
        "HUMAN_NAME": "name",
        "PHONE_NUMBER": "phone",
        "SOCIAL_MEDIA": "profile",
        "COMPANY_NAME": "company"
    }

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        # self.tempStorage() basically returns a dict(), but we use self.tempStorage()
        # instead since on SpiderFoot HX, different mechanisms are used to persist
        # data for load distribution, avoiding excess memory consumption and fault
        # tolerance. This keeps modules transparently compatible with both versions.
        self.results = self.tempStorage()
        self.data = self.tempStorage()
        self.produced = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        for field in self.eventMap.values():
            self.data[field] = []

    # What events is this module interested in for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["EMAILADDR", "HUMAN_NAME", "PHONE_NUMBER", "SOCIAL_MEDIA", "COMPANY_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR", "HUMAN_NAME", "PHONE_NUMBER", "SOCIAL_MEDIA", "COMPANY_NAME", "DATE_HUMAN_DOB", "PHYSICAL_ADDRESS", "USERNAME"]

    PDL_VERSION = "v4"
    PDL_URL = f"https://api.peopledatalabs.com/{PDL_VERSION}/person?"

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def query(self, qry):

        qry['api_key'] = self.opts['api_key']

        res = self.sf.fetchUrl(self.PDL_URL + urlencode(qry),
                               timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot")

        if res['content'] is None or res['code'] != '200':
            self.sf.info("No info PDL found for " + str(qry))
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error(
                f"Error processing JSON response from SHODAN: {e}", False)
            return None

        return info

    def isValidQuery(self, fields):
        for field in fields:
            if self.data[field] == []:
                return False
        return True

        # Handle events sent to this module
    def handleEvent(self, event):
        # The three most used fields in SpiderFootEvent are:
        # event.eventType - the event type, e.g. INTERNET_NAME, IP_ADDRESS, etc.
        # event.module - the name of the module that generated the event, e.g. sfp_dnsresolve
        # event.data - the actual data, e.g. 127.0.0.1. This can sometimes be megabytes in size (e.g. a PDF)
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventType = self.eventMap[eventName]
        # Once we are in this state, return immediately.
        if self.errorState:
            return None

        # Log this before complaining about a missing API key so we know the
        # event was received.
        self.sf.debug(
            f"Received event, {eventName}, {eventType}, from {srcModuleName}")

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key'] == "":
            self.sf.error(
                "You enabled sfp_people_data_labs but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None
        else:
            # If eventData might be something large, set the key to a hash
            # of the value instead of the value, to avoid memory abuse.
            self.results[eventData] = True

        self.data[eventType].append(eventData)

        query_list = []

        for combination in self.combinations:
            if eventType in combination and self.isValidQuery(combination):
                new_dict = {}
                for field in combination:
                    new_dict[field] = self.data[field]

                keys, values = zip(*new_dict.items())

                query_dicts = [dict(zip(keys, v))
                               for v in itertools.product(*values)]

                query_list.extend(query_dicts)

        for query in query_list:
            # Whenever operating in a loop, call this to check whether the user
            # requested the scan to be aborted.
            if self.checkForStop():
                return None

            rec = self.query(query)
            self.createEvents(rec, event)

            self.notifyListeners(SpiderFootEvent(
                "RAW_RIR_DATA", str(rec), self.__name__, event))

    def createEvents(self, rec, event):

        mappings = {
            "names": [{
                "field": "name",
                "event": "HUMAN_NAME"
            }],
            "emails": [{
                "field": "address",
                "event": "EMAILADDR"
            }],
            "profiles": [
                {
                    "field": "url",
                    "event": "SOCIAL_MEDIA"
                },
                {
                    "field": "username",
                    "event": "USERNAME"
                }
            ],
            "experience": [{
                "field": "company.name",
                "event": "COMPANY_NAME"
            }],
            "locations": [{
                "field": "name",
                "event": "PHYSICAL_ADDRESS"
            }],
            "birth_date": [{
                "type": "single",
                "event": "DATE_HUMAN_DOB"
            }]

        }

        data = rec['data']

        for field in list(data.keys()):
            metas = mappings.get(field)

            if metas is None:
                continue

            for meta in metas:
                items = data.get(field)
                if items is None:
                    continue
                if meta.get("type") == "single":
                    self.sendEvent(meta['event'], items, event)
                elif items is not None and items != []:
                    for item in items:
                        info = item
                        for k in meta['field'].split("."):
                            info = info.get(k)
                        if info is None:
                            continue
                        self.sendEvent(meta['event'], info, event)

    def sendEvent(self, event_type, data, event):
        info_key = f"{event_type}-{data}"
        if info_key not in self.produced:
            evt = SpiderFootEvent(
                event_type, data, self.__name__, event)
            self.produced[info_key] = True
            self.notifyListeners(evt)
