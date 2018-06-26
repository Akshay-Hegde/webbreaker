# WebBreaker Documentation

## Table of Contents
[Introduction](#introduction)

- [Description: `description`](#description)

[User Guide](#user-guide)

- [Installation `installation`](#installation)
- [Supported Features `supported_features`](#supported-features)
- [Logging `logging`](#logging)
- [Docker `docker`](#docker)
- [Testing `testing`](#testing)
- [Notifications `notifications`](#notifications)

[Configuration](#configuration)
- [WebBreaker `webbreaker_config`](#webbreaker-config)

[Usage](#usage)
- [Commands `commands`](#commands)
- [WebInspect Scan `webinspect_scan`](#webinspect-scan)
- [WebInspect List `webinspect_list`](#webinspect-list)
- [WebInspect Download `webinspect_download`](#webinspect-download)
- [WebInspect Proxy `webinspect_proxy`](#webinspect-proxy)
- [WebInspect Swagger `webinspect_swagger`](#webinspect-swagger)
- [Fortify List `fortify_list`](#fortify-list)
- [Fortify Upload `fortify_upload`](#fortify-upload)
- [Fortify Download `fortify_download`](#fortify-download)
- [ThreadFix List `threadfix_list`](#threadfix-list)
- [ThreadFix Upload `threadfix_upload`](#threadfix-upload)
- [WebBreaker Administrative `webbreaker_administrative`](#webbreaker-administrative)

[Results](#results)
- [Summary of Scan Results `summary_of_scan_results`](#summary-of-scan-results)
- [JSON Scan File `json_scan_file`](#json-scan-file)

## Introduction `introduction`

### Description `description`
Build non-functional security testing, into your software development and release cycles! WebBreaker provides the capabilities to automate and orchestrate Dynamic Application Security Testing (DAST) from a single client.

## User Guide `user-guide`

### Installation: `installation`

#### Quick Local Installation 
Install WebBreaker from source.
* ```git clone https://github.com/target/webbreaker```
* ```cd webbreaker```
* ```pip install -r requirements.txt```
* ```python setup.py install```

Install WebBreaker with Linux/MacOS pyinstaller.
* ```git clone https://github.com/target/webbreaker```
* ```cd webbreaker```
* ```python setup.py pyinstaller```

Install WebBreaker with Windows pyinstaller.
* ```git clone https://github.com/target/webbreaker```
* ```cd webbreaker```
* ```Set-ExecutionPolicy Unrestricted```
* ```Powershell.exe -executionpolicy unrestricted -command build.ps1```
* ```python setup.py windows```

#### Package Install
WebBreaker releases are packaged on github.com and can be installed locally.
* ```pip install -e git+https://github.com/target/webbreaker.git#egg=webbreaker```

### Supported Features: `supported_features`

* _Jenkins global environmental variable inheritance with scan options._
* _WebInspect REST API support for v9.30 and above._
* _Export both XML and FPR WebInspect formats to Fortify Software Security Center (SSC) or other compatible vulnerability management web applications for vulnerability analysis/triage._
* _Ability to automatically upload scan results to Fortify SSC or other third-party vulnerability management software._
* _Centrally administer all configurations required to launch WebInspect scans from a [GIT](https://github.com/webbreaker/webinspect) repository._
* _Configurable ~/.webbreaker/config.ini property file to support your Fortify, WebInspect, and ThreadFix orchestration._
* _Enterprise scalability with configurable Just-In-Time (JIT) scheduling to distribute your WebInspect scans between two (2) or greater servers._
* _ChatOps extensibility and [email notifications](.webbreaker/config.ini) on scan start and completion._
* _Local [logging](.webbreaker/log) of WebInspect scan state._

### Logging `logging`
WebBreaker local logs may be found under `~/.webbreaker/logs` and can be implemented with Elastic Stack for log aggregation. Recommended compenents include Filebeat agents installed on all WebInspect servers, forwarding to Logstash, and visualized in Kibana. General implementation details are [here](https://qbox.io/blog/welcome-to-the-elk-stack-elasticsearch-logstash-kibana/).  A recommended approach is to tag log events and queries with ```WebInspect``` and ```webbreaker```, but remember 
queries are case sensitive.

### Docker `docker`
Run WebBreaker in Docker from the repository's root directory, the pre-configured virtualenv environments are `venv27` for Python 2.7 or `venv36` for Python 3.6.  Examples are illustrated below.

```
docker build -t test_env:centos . \
&& docker create -it --name test_env test_env:centos  \
&& docker start test_env \
&& docker exec -it test_env bash
```
To remove the environment gracefully, perform the following command:
```
docker stop test_env && docker rm test_env
```

### Testing `testing`
Our automated testing is performed with tox and detox on Python 3.6 and 2.7.

#### Requirements
1. Be in your project root to run tests. 
    * ```pip install -rrequirements.txt```
2. Python2.7 and Python3.6 are currently tested in our tox.ini file
    * If you want to test it against your current version python, you can the other ways to test. Tox is 
    suggested though. 
    
#### Tox
We use detox instead of tox for the speed of concurrent testing. With the speed of testing, comes a lack of 
coverage output
* ```detox```

Tox will allow you to see the coverage.py results.
* ```tox```

#### Other ways to test
These can test against your version of python without creating seperate virtualenv. For isolation of issues 
and ease of use it is suggested that you use tox. 
```
python setup.py install
pytest
```
```
python setup.py install
python setup.py test
```

### Notifications
WebBreaker provides notifications or email for start-scan and end-scan events. 

The email notifier merges the provided event data into an HTML email message and sends the message. All SMTP-related 
settings are managed under your user's home directory within the `~.webbreaker/config.ini`, and read during the webbreaker execution.

If an error occurs on behalf of the notifiers at any point during the process of creating or sending 
notifications, the event will be logged, without any interruption of WebBreaker execution or the WebInspect scan.

## Configuration

Below is the default config.ini that is set at first time install, once you execute `webbreaker` for the first time.  All subsequent installs and updates will not update your `~/.webbreaker/config.ini` unless it is deleted.  You will need to modify the appropriate sections to your environment specifications.

##### WebBreaker Config `webbreaker_config`

### Default 
````
[fortify]
# Fortify SSC URL
ssc_url = https://fortify.example.com/ssc

# Values will be created from the `webbreaker admin credentials --fortify` command
username =
password =

# Default Fortify SSC Project Template to associate the Project /Version
project_template = Prioritized High Risk Issue Template

# Fortify SSC Project or Application default value for uploading, downloading, or listing
# May be overriden on command-line
application_name = WEBINSPECT

# Fortify SSC Application Version default values, with an optional custom attribute.
business_risk_ranking = High
development_phase = Active
development_strategy = Internal
accessibility = externalpublicnetwork

# Fortify SSC custom attribute name, custom_attribute_value may be overridden on command line
custom_attribute_name =
custom_attribute_value =

# Enforce validation of CA Certificate
verify_ssl = False

[threadfix]
# Threadfix URL and API Key created by a User
host = https://threadfix.example.com:8443/threadfix

# Threadfix API Key created from a user by accessing your browser the Threadfix UI
api_key = <Key Required>

[webinspect]
# WebInspect logical server lanes for load balancing between the maximum concurrent scans per server
large_server_max_concurrent_scans = 2
medium_server_max_concurrent_scans = 1
small_server_max_concurrent_scans = 1

# WebInspect server(s) hosting RESTFul API endpoints
server_01 = https://webinspect-server-1.example.com:8083

# WebInspect server interpolated from above, configured to a dedicated large server lane.
endpoint_01 = %(server_01)s|%(large_server_max_concurrent_scans)s

# GIT repo for centrally managed WebInspect configurations of settings, policies, and webmacros.
git_repo = https://github.com/webbreaker/webinspect.git

# WebInspect basic API authentication for access to scanning.
# Not enabled by default, set `authenticate = true` to enable
# Values will be created from the `webbreaker admin credentials --webinspect` command
authenticate = false
username =
password =

# Built-in policies with all webinspect releases, custom policies may be appended
[webinspect_policy]
aggressivesqlinjection = 032b1266-294d-42e9-b5f0-2a4239b23941
allchecks = 08cd4862-6334-4b0e-abf5-cb7685d0cde7
apachestruts = 786eebac-f962-444c-8c59-7bf08a6640fd
application = 8761116c-ad40-438a-934c-677cd6d03afb
assault = 0a614b23-31fa-49a6-a16c-8117932345d8
blank = adb11ba6-b4b5-45a6-aac7-1f7d4852a2f6
criticalsandhighs = 7235cf62-ee1a-4045-88f8-898c1735856f
crosssitescripting = 49cb3995-b3bc-4c44-8aee-2e77c9285038
development = 9378c6fa-63ec-4332-8539-c4670317e0a6
mobile = be20c7a7-8fdd-4bed-beb7-cd035464bfd0
nosqlandnode.js = a2c788cc-a3a9-4007-93cf-e371339b2aa9
opensslheartbleed = 5078b547-8623-499d-bdb4-c668ced7693c
owasptop10applicationsecurityrisks2013 = 48cab8a0-669e-438a-9f91-d26bc9a24435
owasptop10applicationsecurityrisks2007 = ece17001-da82-459a-a163-901549c37b6d
owasptop10applicationsecurityrisks2010 = 8a7152d5-2637-41e0-8b14-1330828bb3b1
passivescan = 40bf42fb-86d5-4355-8177-4b679ef87518
platform = f9ae1fc1-3aba-4559-b243-79e1a98fd456
privilegeescalation = bab6348e-2a23-4a56-9427-2febb44a7ac4
qa = 5b4d7223-a30f-43a1-af30-0cf0e5cfd8ed
quick = e30efb2a-24b0-4a7b-b256-440ab57fe751
safe = def6a5b3-d785-40bc-b63b-6b441b315bf0
soap = a7eb86b8-c3fb-4e88-bc59-5253887ea5b1
sqlinjection = 6df62f30-4d47-40ec-b3a7-dad80d33f613
standard = cb72a7c2-9207-4ee7-94d0-edd14a47c15c
transportlayersecurity = 0fa627de-3f1c-4640-a7d3-154e96cda93c

# smnp email host, port and email addresses required for email functionality.
[emailer]
smtp_host = smtp.example.com
smtp_port = 25
from_address = webbreaker-no-reply@example.com
to_address = webbreaker-activity@example.com
default_to_address =
chatroom =
email_template =
        <html>
        <head></head>
        <body>
        <p>Hello,<br/><br/>
            The following scan has logged new activity:
        <ul>
            <li>Attack traffic source: {0}</li>
            <li>Attack traffic target(s):</li>
            <ul>
                {4}
            </ul>
            <li>Scan name: {1}</li>
            <li>Scan ID: {2}</li>
            <li><b>Action: {3}</b></li>
        </ul>
        </p>
        <p>
            Questions? Concerns? Please chat us on our channel, &quot;WebBreaker&quot;,
            or <a href="mailto:webbreaker-team@example.com">email us</a>.
        </p>

        <p>
            Want to manage your subscription to these emails? Use <a
                href="http://wiki.example.com/index.php/GroupID">GroupID</a>, and
            add/remove yourself from webbreaker-activity.
        </p>
        </body>
        </html>
````

## Usage 
Webbreaker utilizes a structure of upper-level and lower-level commands to enable interaction with multiple 3rd party platforms. The three Products currently supported are WebInspect, ThreadFix, and Fortfiy and they can be accessed using their respective upper-level commands. Webbreaker supports multiple functions for each Product which are accessed via lower-level commands. The current command structure is listed below.

- webbreaker
    - webinspect
        - scan
        - servers
        - list
        - download
        - proxy
        - wiswag
    - fortify
        - list
        - upload
        - scan
        - download
    - admin
        - credentials
        - clear
    - threadfix
        - list
        - teams
        - applications
        - upload

A proper Webbreaker command utilizes the structure 'webbreaker [webinspect|fortify|threadfix|admin] [lower-level command] [OPTIONS]'

### FAQs `faqs`
_Question:_ Why would I receive a 401 error that I am NOT authorized to perform WebInspect scan?

_Answer:_ Either your credentials are not valid, or you need to configure the `[webinspect]` config.ini section with the following:
    
    authenticate = true
    
Now follow these two steps.
1. `webbreaker admin credentials --webinspect --clear`
1. `webbreaker admin credentials --webinspect`
    
### Commands `commands`
Below are common command-line usage of webbreaker, command structure includes the supported webbreaker Product (i.e. webinspect, fortify, threadfix, and admin) followed by an action you wish to take on the Product, typically scan, upload, download, or list.  We used WebInspect [Zero Bank](http://zero.webappsecurity.com/) for our examples below.

##### WebInspect Scan `webinspect_scan`
    # WebInspect scan with settings from a GIT repo or a current working directory, .xml extension is not required, but supported.
    webbreaker webinspect scan --settings zerobank

    # Basic WebInspect scan with credentials (only needed if authentication is enable in config.ini):
    webbreaker webinspect scan --settings zerobank --username $WEBINSPECT_USER --password $WEBINSPECT_PASSWORD

    # WebInspect Scan with overrides:
    webbreaker webinspect scan --settings zerobank --allowed_hosts zero.webappsecurity.com --allowed_hosts legacy.webappsecurity.com

    # Scan with absolute path to your local WebInspect settings:
    webbreaker webinspect scan --settings /Users/Matt/Documents/zerobank
    
    # Scan with load-balancing declared in your ~/.webbreaker/config.ini:
    webbreaker webinspect scan --settings zerobank --size small

##### WebInspect List `webinspect_list`
    # List all WebInspect servers configured in config.ini:
    webbreaker webinspect servers

    # List all WebInspect scans on webinspect-1.example.com and webinspect-2.example.com:
    webbreaker webinspect list --server webinspect-1.example.com:8083 --server webinspect-2.example.com:8083

    # List all WebInspect scans on webinspect-1.example.com and webinspect-2.example.com matching "zerobank":
    webbreaker webinspect list --server webinspect-1.example.com:8083 --server webinspect-2.example.com:8083 --scan_name zerobank

    # List all WebInspect scans on all servers:
    webbreaker webinspect list

    # List all WebInspect scans on all servers matching "zerobank":
    webbreaker webinspect list --scan_name zerobank

    # List all WebInspect scans on all servers using command line auth credentials:
    webbreaker webinspect list --username $WEBINSPECT_USER --password $WEBINSPECT_PASSWORD

##### WebInspect Download `webinspect_download`
    # Download WebInspect scan from server or sensor:
    webbreaker webinspect download --server webinspect-2.example.com:8083 --scan_name zerobank

    # Download WebInspect scan from server with credentials (only needed if authentication is enable in config.ini):
    webbreaker webinspect download --server webinspect-2.example.com:8083 --scan_name zerobank --username $WEBINSPECT_USER --password $WEBINSPECT_PASSWORD

    # Download WebInspect scan as XML:
    webbreaker webinspect download --server webinspect-2.example.com:8083 --scan_name zerobank -x xml

    # Download WebInspect scan by ID:
    webbreaker webinspect download --server webinspect-2.example.com:8083 --scan_name zerobank --scan_id my_important_scans_id

##### WebInspect Proxy `webinspect_proxy`
    # Start a WebInspect proxy called test-proxy on port 9001:
    webbreaker webinspect proxy --start --proxy_name zerobank_proxy --port 9001
    
    NOTE: Output from the command will contain the Proxy Address and Port to configure your browser's network settings. 
    Once complete, perform the desired base case actions for the WebInspect scan, such as authenticating, if your website
    has authentication, or submit a form or complete an optional workflow.  Upon completion, follow the step below to stop
    and download your WebInspect webmacro and setting file for scanning.
    
    # Stop and download webmacro workflow and WebInspect setting file for scanning:
    webbreaker webinspect proxy --stop --proxy_name zerobank_proxy

    # List all the WebInspect proxies:
    webbreaker webinspect proxy --list

    # Download the WebInspect proxy webmacro called test-proxy:
    webbreaker webinspect proxy --download --webmacro zerobank_proxy --proxy_name zerobank_proxy

    # Download the WebInspect proxy settings file called test-proxy:
    webbreaker webinspect proxy --download --setting zerobank_proxy --proxy_name zerobank_proxy

    # Upload a WebInspect webmacro proxy for a scan override called:
    webbreaker webinspect proxy --upload zerobank_proxy.webmacro --proxy_name zerobank_proxy

##### WebInspect Swagger `webinspect_swagger`
    # Ingest, create, and download a WebInspect setting file from a OpenAPI swagger.json URL:
    webbreaker webinspect wiswag --url http://petstore.swagger.io/v2/swagger.json

    # Ingest, create, and download a named WebInspect setting file from a OpenAPI swagger.json specification:
    webbreaker webinspect wiswag --url http://petstore.swagger.io/v2/swagger.json --wiswag_name petstore-swagger-test

##### Fortify List `fortify_list`
    # List Fortify SSC Applications:
    webbreaker fortify list

    # List Fortify SSC versions by application, `application` value is case sensitive:
    webbreaker fortify list --application WEBINSPECT

##### Fortify Upload `fortify_upload`
    # Upload a scan to Fortify SSC with Application from config.ini and new or existing Version:
    webbreaker fortify upload --version zerobank --scan_name zerobank.fpr

    # Upload a scan to Fortify SSC with application/project & version name, .fpr is not required:
    webbreaker fortify upload --application my_other_app --version zerobank --scan_name zerobank.fpr

    # Upload a scan to a new Fortify SSC Application & Version, with a custom attribute:
    webbreaker fortify upload --application my_other_app --version zerobank --scan_name auth_scan --custom_value ABC1234567

##### Fortify Download `fortify_download`
    # Download lastest .fpr scan from Fortify SSC from a specific application/project & version name:
    webbreaker fortify download --application ZERO_BANK --version zerobank

    # Download lastest .fpr scan from Fortify SSC with application configured in config.ini (Default is WEBINSPECT):
    webbreaker fortify download --version zerobank

    # Download lastest .fpr scan from Fortify SSC with application/ version name and command-line authentication:
    webbreaker fortify download --fortify_user $FORT_USER --fortify_password $FORT_PASS --application ZERO_BANK --version zerobank

##### ThreadFix List `threadfix_list`
    # List all applications for all teams found in ThreadFix:
    webbreaker threadfix list

    # List all applications with application containing et for all teams with names containing 'Marketing':
    webbreaker threadfix list --team Marketing --application zerobank

    # List all ThreadFix applications for the Marketing team:
    webbreaker threadfix list --team Marketing

##### ThreadFix Upload `threadfix_upload`
    # Upload the local scan file 'zerobank.xml' to the 'zero_bank' application:
    webbreaker threadfix upload --application zero_bank --scan_file zerobank.xml

    # Upload the local file 'zerobank.xml' as a scan to the 'zero_bank' application
    webbreaker threadfix upload --application zero_bank --scan_file zerobank.xml

    # Create a new application, with a given name and url, in ThreadFix under the Marketing team:
    webbreaker threadfix create --team Marketing --application zero_bank --url http://zero.webappsecurity.com/

##### WebBreaker Administrative `webbreaker_administrative`
    # Encrypt and store new Fortify SSC credentials. User will be prompted for username and password:
    webbreaker admin credentials --fortify

    # Encrypt and store WebInspect credentials. User will be prompted for username and password:
    webbreaker admin credentials --webinspect

    # Encrypt and store Fortify credentials as environment variables:
    webbreaker admin credentials --fortify --username $FORT_USER --password $FORT_PASS

    # Clear cuurent stored Fortify credentials:
    webbreaker admin credentials --fortify --clear

## Results
Scan results are provided in three (3) file formats and a scan summary printed to your screen.  The following sections illustrate both the scan result summary printed to your screen and the WebBreaker json file. 

##### Summary of Scan Results `summary-of-scan-results`
Upon scan completion the WebBreaker WebInspect scan file is read and a summary of the results are printed to the terminal.  Below is an example of the output from the vulnerability's `Payload URL`, `Severity`, `Vulnerability`, and `CWE`.


```
Webbreaker WebInpsect scan zero_bank results:


Payload URL  Severity   Vulnerability  CWE
------------ ---------- -------------- -----
< insert results here />
```

##### JSON Scan File `json_scan_file`

The two (2) WebInspect proprietary formats are `.fpr` and `.xml` file types.  WebBreaker parses or reads the `.xml` file creating a third and limited scan content into a `.json` format.  Below is an example of the `.json` structured WebInspect file `zero_bank.json`, illustrating a single vulnerability.

``` js
{
      "scan_start_time": "2018-06-21 21:21:53",  
      "scan_end_time": "2018-06-21 21:24:01", 
      "scan_name": "webinspect-3CY6F",
      "scan_id": "db80cb63-efd1-473b-945b-618f45ef640c",  
      "findings": 
  {
    {
      "webinspect_id": 
      {
        "id": "06103bc8-612f-4cda-8182-578ebf87cd17" 
      },
      "cwe": 
      [
        "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)",
        "CWE-116: Improper Encoding or Escaping of Output",
        "CWE-352: Cross-Site Request Forgery (CSRF)",
        "CWE-811: OWASP Top Ten 2010 Category A2 - Cross-Site Scripting (XSS)",
        "Input Validation and Representation",
        "Cross-Site Scripting: Reflected"  
      ],
      "severity": "2",  
      "vulnerability_name": "Cross-Site Scripting: Reflected",
      "payload_url": "http://zero.webappsecurity.com:80/forgotten-password-send.html"
    }
  }
}
```
