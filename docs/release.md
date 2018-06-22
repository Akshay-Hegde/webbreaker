# Release 2.2.0

| Category | Feature |
| -------- | ------- |
| Runtime Support | WebInspect XML scan file parsing, to a structured JSON file providing a summary of the Vulnerabilities | 

# Release 2.1.23

| Category | Feature |
| -------- | ------- |
| API Support | Improved performance and reliability on WebInspect, Fortify SSC, and ThreadFix connections. |
| API Support | Added WebInspect `wiswag` API scan support for RESTFul Swagger `.json` ingestion |
| API Support | Added Fortify SSC application creation attributes on `config.ini` and `--custom_value` |
| Runtime Support | Added Circuit Breaker logic from the `pybreaker` module for greater API reliability | 
| Runtime Support | Refactored load-balancing options extending logical lanes of 2 or greater WebInspect scan servers |
| Runtime Support | Configurable SSL validation on `verify_ssl` with WebInspect, Fortify SSC, and ThreadFix |
| Runtime Support | Multi-threading for WebInspect JITScheduler, improving load balancing performance |
| Product Support | Increase test coverage to greater than 50% |
| Administration | Re-write User Guide and CLI help menu content. 

# Release 1.99

| Category | Feature |
| -------- | ------- |
| Product Support | Command-line (CLI) scan administration of WebInspect with Foritfy SSC products. |
| Integration |  [Jenkins](https://jenkins.io) Environmental Variable & String Parameter support (i.e. $BUILD_TAG) |
| Integration | Docker container v17.x support |
| Integration | Custom email alerting or notifications for scan launch and completion. |
| Administration | Extensible event logging for scan administration and scan results. |
| API Support | [WebInspect REST API](https://pypi.python.org/pypi/webinspectapi) support for v9.30 and later. |
| API Support | [Fortify Software Security Center (SSC) REST API](https://pypi.python.org/pypi/fortifyapi) support for v16.10 and later. |
| Administratin | WebInspect scan cluster support between two (2) or greater WebInspect servers/sensors. |
| Administration | Capabilities for extensible scan telemetry with ELK and Splunk. |
| Integration | GIT support for centrally managing [WebInspect scan configurations](https://github.com/automationdomination/Webinspect). |
| Product Support | Replaces most functionality of Fortify's `fortifyclient` |
| Runtime Support | Python versions 2.6 and 3.x |
| Security | Provides AES 128-bit key management for all secrets from the [Fernet encryption](https://pypi.python.org/pypi/cryptography/) Python library. |
