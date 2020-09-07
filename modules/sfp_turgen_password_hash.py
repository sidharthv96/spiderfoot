# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_turgen_password_hash
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying hashes
#
# Author:      Sidharth V <sidharthv96@gmail.com>
#
# Created:     07-09-2020
# Copyright:   (c) Sidharth V
# Licence:     GPL
# -------------------------------------------------------------------------------

import bcrypt
import hashlib

from passlib.hash import pbkdf2_sha256
from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_turgen_password_hash(SpiderFootPlugin):

    meta = {
        'name': "Passowrd Hashes",
        'summary': "Identify popular hashes in leaked passwords.",
        'flags': [""],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {
        # options specific to this module
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["PASSWORD_COMPROMISED"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["HASH"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        hashes = {}
        hashes["bcrypt"] = bcrypt.hashpw(
            bytes(eventData, encoding='utf-8'), bcrypt.gensalt())
        hashes["sha1"] = hashlib.sha1(
            bytes(eventData, encoding='utf-8')).hexdigest()
        hashes["sha3"] = hashlib.sha3_224(
            bytes(eventData, encoding='utf-8')).hexdigest()
        hashes["md5"] = hashlib.md5(
            bytes(eventData, encoding='utf-8')).hexdigest()
        hashes["pbkdf2"] = pbkdf2_sha256.hash(
            bytes(eventData, encoding='utf-8'))

        for hashAlgo, hashval in hashes.items():
            evt = SpiderFootEvent(
                "HASH", "[" + hashAlgo + "] " + str(hashval), self.__name__, event)
            self.notifyListeners(evt)

        return None
