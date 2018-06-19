#!/usr/bin/env python
# -*-coding:utf-8-*-

import os
import json
import ntpath
import sys
from exitstatus import ExitStatus
from pybreaker import CircuitBreaker
from webinspectapi.webinspect import WebInspectApi


from webbreaker.common.webbreakerlogger import Logger
from webbreaker.common.logexceptionhelper import LogExceptionHelper

from webbreaker.webinspect.common.loghelper import WebInspectLogHelper
import webbreaker.webinspect.webinspect_json as webinspectjson


logexceptionhelper = LogExceptionHelper()
webinspect_logexceptionhelp = WebInspectLogHelper()


class WebInspectAPIHelper(object):
    def __init__(self, host=None, username=None, password=None, webinspect_setting_overrides=None, silent=False):
        # If a host is passed then we are doing a download or a list,  otherwise a scan.
        self.host = host
        self.username = username
        self.password = password

        # if - we are running a webinspect scan
        if webinspect_setting_overrides is not None:
            self.setting_overrides = webinspect_setting_overrides
            # set the host to be the available endpoint
            self.host = self.setting_overrides.endpoint
        else:
            self.setting_overrides = None

        self._set_api()

        self.silent = silent

        if self.silent is False:  # want to be able to hide this output for multithreading
            webinspect_logexceptionhelp.log_info_using_webinspect_server(self.host)

    def _set_api(self):
        self.api = WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)


    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def create_scan(self):
        """
        Launches and monitors a scan
        :return: If scan was able to launch, scan_id. Otherwise none.
        """
        try:
            Logger.app.debug("Creating Scan in webinspect client")
            overrides = json.dumps(webinspectjson.formatted_settings_payload(self.setting_overrides.settings,
                                                                             self.setting_overrides.scan_name,
                                                                             self.setting_overrides.runenv,
                                                                             self.setting_overrides.scan_mode,
                                                                             self.setting_overrides.scan_scope,
                                                                             self.setting_overrides.login_macro,
                                                                             self.setting_overrides.scan_policy,
                                                                             self.setting_overrides.scan_start,
                                                                             self.setting_overrides.start_urls,
                                                                             self.setting_overrides.workflow_macros,
                                                                             self.setting_overrides.allowed_hosts))
            response = self.api.create_scan(overrides)

            logger_response = json.dumps(response, default=lambda o: o.__dict__, sort_keys=True)
            Logger.app.debug("Request sent to {0}:\n{1}".format(self.setting_overrides.endpoint, overrides))
            Logger.app.debug("Response from {0}:\n{1}\n".format(self.setting_overrides.endpoint, logger_response))

            scan_id = response.data['ScanId']
            webinspect_logexceptionhelp.log_info_scan_start(self.setting_overrides.endpoint, scan_id)
            return scan_id

        except (ValueError, UnboundLocalError) as e:
            webinspect_logexceptionhelp.log_error_scan_start_failed(e)
            sys.exit(ExitStatus.failure)

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def export_scan_results(self, scan_id, extension, scan_name=None):
        """
        Save scan results to file, if you pass a scan name it will have that name, otherwise it will read from the
            overrides for the scan name
        :param scan_id:
        :param extension:
        :param scan_name: name of scan to be saved locally
        :return:
        """
        # Export scan as a xml for Threadfix or other Vuln Management System
        Logger.app.info('Exporting scan: {} as {}'.format(scan_id, extension))
        detail_type = 'Full' if extension == 'xml' else None
        response = self.api.export_scan_format(scan_id, extension, detail_type)
        #APIHelper().check_for_response_errors(response)

        # setting_overrides is on a webinspect scan
        if scan_name == None:
            scan_name = self.setting_overrides.scan_name

        try:
            with open('{0}.{1}'.format(scan_name, extension), 'wb') as f:
                f.write(response.data)
                webinspect_logexceptionhelp.log_info_successful_scan_export(scan_name, extension)
        except (UnboundLocalError, IOError) as e:
            webinspect_logexceptionhelp.log_error_failed_scan_export(e)

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def get_policy_by_guid(self, policy_guid):
        response = self.api.get_policy_by_guid(policy_guid)
        #APIHelper().check_for_response_errors(response)

        return response.data

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def get_policy_by_name(self, policy_name):
        response = self.api.get_policy_by_name(policy_name)
        #APIHelper().check_for_response_errors(response)

        return response.data

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def get_scan_by_name(self, scan_name):
        """
        Search Webinspect server for a scan matching scan_name
        :param scan_name:
        :return: List of search results
        """
        # scan_name = self._trim_ext(scan_name)

        response = self.api.get_scan_by_name(scan_name)
        #APIHelper().check_for_response_errors(response)

        return response.data

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def get_scan_status(self, scan_guid):
        """
        Get scan status from the Webinspect server
        :param scan_guid:
        :return: Current status of scan
        """
        try:
            response = self.api.get_current_status(scan_guid)
            #APIHelper().check_for_response_errors(response)

            status = json.loads(response.data_json())['ScanStatus']
            return status
        except (ValueError, TypeError, UnboundLocalError) as e:
            webinspect_logexceptionhelp.log_error_get_scan_status(e)
            return None

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def list_scans(self):
        """
        List all scans found on host
        :return: response.data from the Webinspect server
        """
        try:
            response = self.api.list_scans()
            #APIHelper().check_for_response_errors(response)

            return response.data

        except (ValueError, UnboundLocalError, NameError) as e:
            webinspect_logexceptionhelp.log_error_list_scans(e)

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def list_running_scans(self):
        """
        List all running scans on host
        :return:
        """
        response = self.api.list_running_scans()

        return response

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def policy_exists(self, policy_guid):
        # true if policy exists
        response = self.api.get_policy_by_guid(policy_guid)
        #APIHelper().check_for_response_errors(response)
        return response.success

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def stop_scan(self, scan_guid):
        response = self.api.stop_scan(scan_guid)
        #APIHelper().check_for_response_errors(response)
        return response.success

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def upload_policy(self):
        # if a policy of the same name already exists, delete it prior to upload
        try:
            # bit of ugliness here. I'd like to just have the policy name at this point but I don't
            # so find it in the full path
            # TODO: Verify split here
            response = self.api.get_policy_by_name(ntpath.basename(self.setting_overrides.webinspect_upload_policy).split('.')[0])
            #APIHelper().check_for_response_errors(response)

            if response.success and response.response_code == 200:  # the policy exists on the server already
                response = self.api.delete_policy(response.data['uniqueId'])
                #APIHelper().check_for_response_errors(response)

                Logger.app.debug("Deleted policy {} from server".format(
                    ntpath.basename(self.setting_overrides.webinspect_upload_policy).split('.')[0]))
        except (ValueError, UnboundLocalError, TypeError) as e:
            webinspect_logexceptionhelp.log_error_policy_deletion(e)

        try:
            response = self.api.upload_policy(self.setting_overrides.webinspect_upload_policy)
            #APIHelper().check_for_response_errors(response)
            Logger.console.debug("Uploaded policy {} to server.".format(self.setting_overrides.webinspect_upload_policy))

        except (ValueError, UnboundLocalError, TypeError, NameError) as e:
            webinspect_logexceptionhelp.log_error_uploading("policy", e)
            webinspect_logexceptionhelp.log_no_webinspect_server_found(e)

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def upload_settings(self):

        try:
            response = self.api.upload_settings(self.setting_overrides.webinspect_upload_settings)
            #APIHelper().check_for_response_errors(response)

            Logger.console.debug("Uploaded settings {} to server.".format(self.setting_overrides.webinspect_upload_settings))

        except (ValueError, UnboundLocalError, NameError) as e:
            webinspect_logexceptionhelp.log_error_uploading("settings", e)
            webinspect_logexceptionhelp.log_no_webinspect_server_found(e)

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def upload_webmacros(self):
        try:
            for webmacro in self.setting_overrides.webinspect_upload_webmacros:
                response = self.api.upload_webmacro(webmacro)
                #APIHelper().check_for_response_errors(response)
                Logger.console.debug("Uploaded webmacro {} to server.".format(webmacro))

        except (ValueError, UnboundLocalError) as e:
            webinspect_logexceptionhelp.log_error_uploading("webmacro", e)
            webinspect_logexceptionhelp.log_no_webinspect_server_found(e)

    @CircuitBreaker(fail_max=5, reset_timeout=60)
    def verify_scan_policy(self, config):
        try:
            if self.setting_overrides.scan_policy:
                # two happy paths: either the provided policy refers to an existing builtin policy, or it refers to
                # a local policy we need to first upload and then use.

                built_in = self._check_if_built_in(config)

                if built_in:
                    idx = self._get_index(config)

                    policy_guid = config.mapped_policies[idx[0]][1]
                    Logger.app.info(
                        "scan_policy {} with policyID {} has been selected.".format(self.setting_overrides.scan_policy,
                                                                                    policy_guid))
                    Logger.app.info("Checking to make sure a policy with that ID exists in WebInspect.")
                    if not self.policy_exists(policy_guid):
                        Logger.app.error(
                            "Scan policy {} cannot be located on the WebInspect server. Stopping".format(
                                self.setting_overrides.scan_policy))
                        sys.exit(ExitStatus.failure)
                    else:
                        Logger.app.info("Found policy {} in WebInspect.".format(policy_guid))
                else:
                    # Not a builtin. Assume that caller wants the provided policy to be uploaded
                    Logger.app.info("Provided scan policy is not built-in, so will assume it needs to be uploaded.")
                    self.upload_policy()
                    policy = self.get_policy_by_name(self.setting_overrides.scan_policy)
                    if policy:
                        policy_guid = policy['uniqueId']
                    else:
                        Logger.app.error("The policy name is either incorrect or not available in {}."
                                         .format('.webbreaker/etc/webinspect/policies'))
                        sys.exit(ExitStatus.failure)

                # Change the provided policy name into the corresponding policy id for scan creation.
                policy_id = self.get_policy_by_guid(policy_guid)['id']
                self.setting_overrides.scan_policy = policy_id
                Logger.app.debug("New scan policy has been set")

            else:
                Logger.app.debug("No WebInspect Scan Override Policy was selected: {}!".format
                                 (self.setting_overrides.scan_policy))

        except (UnboundLocalError, NameError) as e:
            webinspect_logexceptionhelp.log_no_webinspect_server_found(e)

    def _check_if_built_in(self, config):
        """
        check if scan policy is a built in, this is abstracted from verify_scan_policy so it can be mocked.
        :param config:
        :return:
        """
        if str(self.setting_overrides.scan_policy).lower() in [str(x[0]).lower() for x in
                                                               config.mapped_policies]:
            return True
        else:
            return False

    def _get_index(self, config):
        """
        # wow what a list comprehension. not a single comment - this was added posthumously.
        this was abstracted from verify_scan_policy so mocking could occur.
        :param config:
        :return:
        """
        index = [x for x, y in enumerate(config.mapped_policies) if
                 y[0] == str(self.setting_overrides.scan_policy).lower()]

        return index
