#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Brandon Spruth (brandon.spruth2@target.com), Jim Nelson (jim.nelson2@target.com)," \
             "Matt Dunaj (matthew.dunaj@target.com), Kyler Witting (Kyler.Witting@target.com)"
__copyright__ = "(C) 2018 Target Brands, Inc."
__contributors__ = ["Brandon Spruth", "Jim Nelson", "Matthew Dunaj", "Kyler Witting", "Matthew Fevold"]
__status__ = "Production"
__license__ = "MIT"

try:
    from signal import *
    from urlparse import urlparse
    import urllib
except ImportError:  # Python3
    import html.entities as htmlentitydefs
    from urllib.parse import urlparse
    import html.parser as HTMLParser
    import urllib.request as urllib

import click
import sys

from webbreaker import __version__ as version
from webbreaker.common.authorization import auth_prompt
from webbreaker.common.secretclient import SecretClient
from webbreaker.common.webbreakerlogger import Logger
from webbreaker.common.webbreakerhelper import WebBreakerHelper
from webbreaker.fortify.authentication import FortifyAuth
from webbreaker.fortify.download import FortifyDownload
from webbreaker.fortify.list import FortifyList
from webbreaker.fortify.upload import FortifyUpload
from webbreaker.common.logexceptionhelper import LogExceptionHelper
from webbreaker.webinspect.authentication import WebInspectAuth
from webbreaker.webinspect.download import WebInspectDownload
from webbreaker.webinspect.wiswag import WebInspectWiswag
from webbreaker.webinspect.list_scans import WebInspectListScans
from webbreaker.webinspect.list_servers import WebInspectListServers
from webbreaker.webinspect.proxy import WebInspectProxy
from webbreaker.webinspect.scan import WebInspectScan
from webbreaker.threadfix.list import ThreadFixList
from webbreaker.threadfix.teams import ThreadFixTeams
from webbreaker.threadfix.create import ThreadFixCreate
from webbreaker.threadfix.scans import ThreadFixScans
from webbreaker.threadfix.upload import ThreadFixUpload
from webbreaker.fortify.common.loghelper import FortifyLogHelper

fortifyloghelper = FortifyLogHelper()

loghelper = LogExceptionHelper()
# loginfohelper = LogInfoHelper()

try:
    from git.exc import GitCommandError
except ImportError as e:  # module will fail if git is not installed
    logexceptionhelper.log_error_git_command(e)

handle_scan_event = None


class Config(object):
    def __init__(self):
        self.debug = False


pass_config = click.make_pass_decorator(Config, ensure=True)


def fortify_prompt():
    fortify_user = click.prompt('Fortify user')
    fortify_password = click.prompt('Fortify password', hide_input=True)
    return fortify_user, fortify_password


@click.group(help=WebBreakerHelper().webbreaker_desc())
def cli():
    # Show something pretty to start
    webbreaker_ascii = WebBreakerHelper.ascii_motd()
    b = WebBreakerHelper.banner(text=(webbreaker_ascii))

    sys.stdout.write(str("{0}\nVersion {1}\n".format(b, version)))
    sys.stdout.write(str("Logging to files: {}\n".format(Logger.app_logfile)))
    SecretClient().verify_secret()


@cli.group(short_help="Interaction with Webinspect RESTFul API",
           help=WebBreakerHelper().webinspect_desc(),
           )
def webinspect():
    pass


@webinspect.command(name='scan',
                    short_help="Launch a WebInspect scan",
                    help=WebBreakerHelper().webinspect_scan_desc()
                    )
@click.option('--username',
              help="Specify the username for your WebInspect Basic Authentication to the Sensor")
@click.option('--password',
              help="Specify the password for your WebInspect Basic Authentication to the Sensor")
@click.option('--allowed_hosts',
              multiple=True,
              help="Override host(s) from start_urls option")
@click.option('--fortify_user',
              help="Authenticate Fortify user to upload WebInspect scan")
@click.option('--login_macro',
              help="Assign an override for a login webmacro for application authentication")
@click.option('--scan_name',
              type=str,
              help="Assign a name for the WebInspect scan")
@click.option('--scan_mode',
              type=click.Choice(['crawl', 'scan', 'all']),
              help="Assign an override setting scan mode value")
@click.option('--scan_policy',
              help="Assign an override for a WebInspect policy,")
@click.option('--scan_scope',
              help="Assign an override of either all, strict, children, OR ancestors")
@click.option('--scan_start',
              type=click.Choice(['url', 'macro']),
              help="Assign type of scan to be performed")
@click.option('--settings',
              type=str,
              default='Default',
              required=False,
              help="Specify setting file")
@click.option('--size',
              type=click.Choice(['small', 'medium', 'large']),
              default='large',
              help="Specify scanner size")
@click.option('--start_urls',
              multiple=True,
              help="Assign starting url(s)")
# Deprecated as of 2.1.9, these options are set from scan via git repo. ^.^
@click.option('--upload_policy',
              help="Upload policy file to WebInspect")
@click.option('--upload_settings',
              help="Upload .xml settings file")
@click.option('--upload_webmacros',
              help="Upload webmacro to WebInspect")
@click.option('--workflow_macros',
              multiple=True,
              help="Assign workflow macro(s)")
# Added since 2.2.1
@click.option('--stop',
              type=str,
              help="Stop a scan with a Scan ID, must include the scan ID GUID!")
def webinspect_scan(**kwargs):
    # handle deprecated click option warnings
    if kwargs['upload_policy']:
        Logger.app.critical("--upload_policy is a deprecated option because of underuse, if you believe there is a "
                         "valid use for this please make a github issue")

    if kwargs['upload_webmacros']:
        Logger.app.critical("--upload_webmacros is a deprecated option because of underuse, if you believe there is a "
                         "valid use for this please make a github issue")

    if kwargs['upload_settings']:
        Logger.app.critical("--upload_settings is a deprecated option because of underuse, if you believe there is a "
                         "valid use for this please make a github issue")

    WebInspectScan(kwargs.copy())



@webinspect.command(name='list',
                    short_help="List current and past WebInspect scans",
                    help=WebBreakerHelper().webinspect_list_desc())
@click.option('--scan_name',
              help="The WebInspect scan name")
@click.option('--server',
              multiple=True,
              help="Assign WebInspect server URL(S)")
@click.option('--username',
              help="WebInspect Sensor username, if not configured in config.ini")
@click.option('--password',
              help="WebInspect Sensor password, if not configured in config.ini")
def webinspect_list_scans(scan_name, server, username, password):
    WebInspectListScans(scan_name, server, username, password)


@webinspect.command(name='servers',
                    short_help="List all WebInspect Sensors configured in config.ini",
                    help=WebBreakerHelper().webinspect_servers_desc())
def webinspect_list_servers():
    WebInspectListServers()


@webinspect.command(name='download',
                    short_help="Download a WebInspect scan",
                    help=WebBreakerHelper().webinspect_download_desc())
@click.option('--server',
              required=True,
              help="Specify WebInspect Sensor URL with port")
@click.option('--scan_name',
              required=True,
              help="WebInspect scan name to download")
@click.option('--scan_id',
              help="WebInspect scan ID to download")
@click.option('-x',
              default="fpr",
              help="Assign scan extension, default is .fpr")
@click.option('--username',
              help="WebInspect Sensor username, if not configured in config.ini")
@click.option('--password',
              help="WebInspect Sensor password, if not configured in config.ini")
def webinspect_download_scan(server, scan_name, scan_id, x, username, password):
    WebInspectDownload(server, scan_name, scan_id, x, username, password)


@webinspect.command(name='proxy',
                    short_help="Interact with WebInspect proxy",
                    help=WebBreakerHelper().webinspect_proxy_desc())
@click.option('--download',
              is_flag=True,
              help="Flag to specify download")
@click.option('--list',
              is_flag=True,
              help="List WebInspect proxies currently available")
@click.option('--port',
              help="Assign WebInspect proxy port")
@click.option('--proxy_name',
              help="Assign WebInspect proxy ID")
@click.option('--setting',
              is_flag=True,
              help="Flag to download setting file from proxy_name")
@click.option('--server',
              help="Optional URL of specific WebInspect server(s)")
@click.option('--start',
              is_flag=True,
              help="Start a WebInspect proxy service")
@click.option('--stop',
              is_flag=True,
              help="Stop & delete a WebInspect proxy service")
@click.option('--upload',
              help="Webmacro file path to upload")
@click.option('--webmacro',
              is_flag=True,
              help="Flag to download webmacro file from proxy_name")
@click.option('--username',
              help="Specify WebInspect username")
@click.option('--password',
              help="Specify WebInspect password")
def webinspect_proxy(download, list, port, proxy_name, setting, server, start, stop, upload, webmacro, username,
                     password):
    WebInspectProxy(download, list, port, proxy_name, setting, server, start, stop, upload, webmacro, username,
                    password)


@webinspect.command(name='wiswag',
                    short_help="Create a swagger WebInspect setting file for scanning.",
                    help=WebBreakerHelper().webinspect_wiswag_desc())
@click.option('--url',
              required=True,
              help="Json file path")
@click.option('--wiswag_name',
              help="Name of wiswag setting file")
@click.option('--username',
              help="Specify WebInspect username")
@click.option('--password',
              help="Specify WebInspect password")
@click.option('--server',
              help="Optional URL of specific WebInspect server(s)")
def webinspect_wiswag(url, wiswag_name, username, password, server):
    WebInspectWiswag(url, wiswag_name, username, password, server)

@cli.group(short_help="Interaction with Fortify API",
           help=WebBreakerHelper().fortify_desc(),
           )
def fortify():
    pass


@fortify.command(name='list',
                 short_help="List Fortify application versions",
                 help=WebBreakerHelper().fortify_list_desc())
@click.option('--fortify_user',
              help="Specify Fortify SSC username, if not configured in the config.ini")
@click.option('--fortify_password',
              help="Specify Fortify SSC password, if not configured in the config.ini")
@click.option('--application',
              help="Specify Fortify app name"
              )
def fortify_list_application_versions(fortify_user, fortify_password, application):
    FortifyList(fortify_user, fortify_password, application)


@fortify.command(name='download',
                 short_help="Download Fortify .fpr scan",
                 help=WebBreakerHelper().fortify_download_desc())
@click.option('--fortify_user',
              help="Specify Fortify SSC username, if not configured in the config.ini")
@click.option('--fortify_password',
              help="Specify Fortify SSC password, if not configured in the config.ini")
@click.option('--application',
              help="Override the Fortify SSC Application or Project name specified in the config.ini"
              )
@click.option('--version',
              required=True,
              help="Specify Fortify app version")
def fortify_download_scan(fortify_user, fortify_password, application, version):
    FortifyDownload(fortify_user, fortify_password, application, version)


@fortify.command(name='upload',
                 short_help="Upload WebInspect scan to Fortify",
                 help=WebBreakerHelper().fortify_upload_desc())
@click.option('--fortify_user',
              help="Specify Fortify username")
@click.option('--fortify_password',
              help="Specify Fortify password")
@click.option('--application',
              help="Assign Fortify app name"
              )
@click.option('--version',
              required=True,
              help="Assign Fortify app version"
              )
@click.option('--scan_name',
              help="Specify name if file name is different than version")
@click.option('--custom_value',
              help="Specify custom value for creating a new Application Version.")
def fortify_upload_scan(fortify_user, fortify_password, application, version, scan_name, custom_value):

    FortifyUpload(fortify_user, fortify_password, application, version, scan_name, custom_value)


@cli.group(short_help="Manage credentials & notifiers",
           help=WebBreakerHelper().admin_desc(),
           )
def admin():
    pass


@admin.command(name='credentials',
               short_help="Create and delete Fortify and WebInspect credentials",
               help=WebBreakerHelper().admin_credentials_desc()
               )
@click.option('--fortify',
              is_flag=True,
              help="Set your Fortify credentials in config.ini")
@click.option('--webinspect',
              is_flag=True,
              help="Set your WebInspect credentials in config.ini")
@click.option('--clear',
              is_flag=True,
              help="Clear config.ini Fortify or WebInspect credentials")
@click.option('--username',
              help="Specify username")
@click.option('--password',
              help="Specify username")
def admin_credentials(fortify, webinspect, clear, username, password):
    if fortify:
        fortify_auth = FortifyAuth()
        if clear:
            fortify_auth.clear_credentials()
            fortifyloghelper.log_info_credentials_clear_success()
        else:
            if username and password:
                try:
                    fortify_auth.write_credentials(username, password)
                    loghelper.log_info_credentials_store_success()

                except ValueError:
                    fortifyloghelper.log_error_credentials_not_stored()

            else:
                username, password = auth_prompt("Fortify")
                try:
                    fortify_auth.write_credentials(username, password)
                    loghelper.log_info_credentials_store_success()
                except ValueError:
                    fortifyloghelper.log_error_credentials_not_stored()

    elif webinspect:
        webinspect_auth = WebInspectAuth()
        if clear:
            webinspect_auth.clear_credentials()
            loghelper.log_info_webinspect_credential_clear_success()
        else:
            if username and password:
                try:
                    webinspect_auth.write_credentials(username, password)
                    loghelper.log_info_credentials_store_success()

                except ValueError:
                    fortifyloghelper.log_error_credentials_not_stored()

            else:
                username, password = auth_prompt("WebInspect")
                try:
                    webinspect_auth.write_credentials(username, password)
                    loghelper.log_info_credentials_store_success()

                except ValueError:
                    fortifyloghelper.log_error_credentials_not_stored()
    else:
        sys.stdout.write(str("Please specify either the --fortify or --webinspect options,\n"
                             "if you wish to re-set your credentals append --clear"))


@admin.command(name='secret',
               short_help="Generate & update encryption key",
               help=WebBreakerHelper().admin_secret_desc()
               )
@click.option('-f', '--force',
              required=False,
              is_flag=True,
              help="No interactive prompt.")
def admin_secret(force):
    secret_client = SecretClient()
    if secret_client.secret_exists():
        if not force:
            if click.confirm('All stored credentials will be deleted. Do you want to continue?'):
                secret_client.wipe_all_credentials()
                secret_client.write_secret(overwrite=True)
            else:
                sys.stdout.write(str("New secret was not written\n"))
        else:
            secret_client.wipe_all_credentials()
            secret_client.write_secret(overwrite=True)
    else:
        secret_client.write_secret()


@cli.group(short_help="Interaction with ThreadFix RESTFul API",
           help=WebBreakerHelper().threadfix_desc()
           )
def threadfix():
    pass


@threadfix.command(name='teams',
                   short_help="List all ThreadFix teams",
                   help=WebBreakerHelper().threadfix_team_desc()
                   )
def threadfix_list_teams():
    ThreadFixTeams()


@threadfix.command(name='create',
                   short_help="Create application in ThreadFix",
                   help=WebBreakerHelper().threadfix_create_desc()
                   )
@click.option('--team_id',
              help="Assign ThreadFix team ID")
@click.option('--team',
              help="Assign ThreadFix team name")
@click.option('--application',
              required=True,
              help="Assign a name")
@click.option('--url',
              default=None,
              help="Assign an Option URL")
def threadfix_create_application(team_id, team, application, url):
    ThreadFixCreate(team_id, team, application, url)


@threadfix.command(name='scans',
                   short_help="List ThreadFix scans",
                   help=WebBreakerHelper().threadfix_scan_desc())
@click.option('--app_id',
              required=True,
              help="ThreadFix Application ID")
def threadfix_list_scans(app_id):
    ThreadFixScans(app_id)

@threadfix.command(name='upload',
                   short_help="Upload local scan to ThreadFix",
                   help=WebBreakerHelper().threadfix_upload_desc()
                   )
@click.option('--app_id',
              help="Assign ThreadFix Application ID")
@click.option('--application',
              help="Assign ThreadFix Application name")
@click.option('--scan_file',
              required=True,
              help="Assign file to upload")
def threadfix_upload_scan(app_id, application, scan_file):
    ThreadFixUpload(app_id, application, scan_file)


@threadfix.command(name='list',
                   short_help="List all ThreadFix applications",
                   help=WebBreakerHelper().threadfix_list_desc()
                   )
@click.option('--team',
              default=None,
              help="Specify team name to list")
@click.option('--application',
              default=None,
              help="Specify application name to list")
def threadfix_list_applications(team, application):
    ThreadFixList(team, application)


if __name__ == '__main__':
    cli()
