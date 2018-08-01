#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
from exitstatus import ExitStatus
# deviating from standard style to remove circular dependency problem.
import webbreaker.webinspect.common.helper
from webbreaker.webinspect.authentication import WebInspectAuth
from webbreaker.common.confighelper import Config
from webbreaker.webinspect.webinspect_config import WebInspectConfig

from webbreaker.common.webbreakerlogger import Logger

from multiprocessing.dummy import Pool as ThreadPool
try:  # python 3
    import queue
except ImportError:  # python 2
    import Queue as queue


class WebInspectJitScheduler(object):
    def __init__(self, server_size_needed='large', username=None, password=None, timeout=30):
        """
        The Just-In-Time Scheduler is meant to take in a list of endpoints (either passed in from a user or from a
            config) and return one that is not busy running scans.

            The servers are designed to be two different sizes and the user is allowed to choose if they want a large
            medium, or small server (default is large).

            JIT filters the list of endpoints for servers of that size and makes an api call to that server for it's
            running scans. It does this multi-threaded so whoever responds back quickest wins.

            It will timeout if no server responds back within 30 seconds - though this number is arbitrary right now.

        :param endpoints: different possible endpoints to use to scan, is a list of [['url', size], ... ]
        :param server_size_needed: size of server you want to run a scan on, passed from a cli
        :param username:
        :param password:
        """
        self.endpoints = WebInspectConfig().endpoints

        auth_config = WebInspectAuth()
        self.username, self.password = auth_config.authenticate(username, password)

        self.server_size_needed = self._convert_server_size_needed_to_int(server_size_needed)

        Logger.app.debug("endpoints: {}".format(self.endpoints))
        Logger.app.debug("username: {}".format(self.username))

        Logger.app.debug("server_size_needed: {}".format(self.server_size_needed))

        # used for multi threading the _is_available API call
        self._results_queue = queue.Queue()
        self.timeout = timeout

    def get_endpoint(self):
        """
        public method for finding an endpoint that is: the size required, not at max capacity
        :return: an endpoint that you can run webinspect commands on. None if no available endpoints
        """

        # Logger.app.debug("Searching for an available endpoint")
        try:
            endpoint = self._get_available_endpoint()
            Logger.app.info("WebBreaker has selected: {} as your WebInspect Server.".format(endpoint[0]))
            return endpoint[0]
        except (NoServersAvailableError, UnboundLocalError) as e:
            Logger.app.error("The JIT Scheduler found no available servers for this request: {}".format(e))
            sys.exit(ExitStatus.failure)

    def _get_available_endpoint(self):
        """
        Private method that handles filtering endpoints of the right size, parallely asking those endpoints if they're
        available and handling what they find out.
        :return: an endpoint that a scan can be ran on or raise a NoServersAvailableError
        """
        Logger.app.debug("Searching for appropriately sized servers")

        correct_sized_endpoints = self._get_endpoints_of_the_right_size()
        # correct_sized_endpoints = random.shuffle(correct_sized_endpoints)
        Logger.app.debug("correct_sized_endpoints: {}".format(correct_sized_endpoints))

        # if there are no endpoints of that size.
        if len(correct_sized_endpoints) == 0:
            Logger.app.error("No servers of that size are available.")
            raise NoServersAvailableError

        pool = ThreadPool(len(correct_sized_endpoints))

        # start some threads - first to finish adds to a queue and that is what we return.
        pool.imap_unordered(self._is_endpoint_available, correct_sized_endpoints)

        try:
            correct_sized_endpoint = self._results_queue.get(block=True, timeout=self.timeout)
        except queue.Empty as e:  # if queue is still empty after timeout period this is raised.
            Logger.app.error("The search has timed out after {} seconds.".format(self.timeout))
            raise NoServersAvailableError

        Logger.app.debug("We have an endpoint: {}".format(correct_sized_endpoint))

        # kill all running threads
        pool.terminate()

        return correct_sized_endpoint

    def _get_endpoints_of_the_right_size(self):
        """
        Given the provided max_concurrent_scans value, return a list of endpoints that are capable of running
        exactly than many scans. This does NOT take into consideration how many scans are currently running,
        it's just to determine if it's possible.
        :return: return all endpoints that are the size required
        """
        possible_endpoints = []


        for endpoint in self.endpoints:

            # endpoint[1] is either 1 or 2 aka max concurrent scans - it's also a string so need to cast as int.
            try:  # verify endpoint[1] is a int
                if int(endpoint[1]) == self.server_size_needed:
                    possible_endpoints.append(endpoint)

            except ValueError as e:
                Logger.app.error("There was a problem with the config.ini server|endpoint: {}".format(e))
        return possible_endpoints

    def _is_endpoint_available(self, webinspect_endpoint):
        """
        Determine if the provided endpoint is available. (i.e. are there less than max_concurrent_scans
        with a Status of Running on the endpoints
        :param endpoint: The endpoint to evaluate
        :param max_concurrent_scans:  The max number of allowed scans to be running on the endpoint
        """

        # Doing it kind of ugly - it removes a circular dependency issue, it's functionally the same as other uses of
        #  WebInspectAPIHelper.
        api = webbreaker.webinspect.common.helper.WebInspectAPIHelper(host=webinspect_endpoint[0], username=self.username, password=self.password, silent=True)

        # list_running_scans is in version 1.0.31 webinspectapi
        response = api.list_running_scans()
        if response.success:
            # response.data is amount of running scans. endpoint[1] is either 1 or 2,
            #                                               aka how many scans it can handle at once.
            if len(response.data) < int(webinspect_endpoint[1]):

                Logger.app.debug("Server '{}' is available!".format(webinspect_endpoint[0]))
                # the first thread that gets to this wins and gets to run the scan.
                self._results_queue.put(webinspect_endpoint, False)
                return
            else:
                Logger.app.debug("Server '{}' is not available".format(webinspect_endpoint[0]))
                return

    @staticmethod
    def _convert_server_size_needed_to_int(server_size_needed):
        """
        converts the cli large/medium/small into the value set in the config for a [large|medium|small]_server_max_concurrent_scans
            by default this is large = 2, medium = 1, small = 1 but can be changed.
        :param server_size_needed:
        :return:
        """
        # default is large.
        try:  # if value in config is not an integer will fail.
            if server_size_needed.lower() in ['large']:
                Logger.app.info("A large server will be selected to handle this request.")
                large_server_max_concurrent_scans = Config().conf_get('webinspect', 'large_server_max_concurrent_scans')
                return int(large_server_max_concurrent_scans)  # by default 2

            # medium exists for some backwards compatibility.
            if server_size_needed.lower() in ['medium']:
                Logger.app.info("A medium server will be selected to handle this request.")
                medium_server_max_concurrent_scans = Config().conf_get('webinspect', 'medium_server_max_concurrent_scans')
                return int(medium_server_max_concurrent_scans)  # by default 1

            if server_size_needed.lower() in ['small']:
                Logger.app.info("A small server will be selected to handle this request.")
                small_server_max_concurrent_scans = Config().conf_get('webinspect', 'small_server_max_concurrent_scans')
                return int(small_server_max_concurrent_scans)  # by default 1
            else:
                Logger.app.error("Size doesn't exist! Valid sizes are 'small' or 'large'")
                sys.exit(ExitStatus.failure)
        except TypeError as e:
            Logger.app.error("value in config for [large/small]_server_max_concurrent_scans is not an integer. "
                             "{}".format(e))
            sys.exit(ExitStatus.failure)


class NoServersAvailableError(Exception):
    def __init__(self):
        super(NoServersAvailableError, self).__init__("The JIT Scheduler found no available servers for this request.")
        #super(NoServersAvailableError, self).__init__("WebBreaker found no available WebInspect Servers for scanning, "
        #                                              "verify your config.ini!")

