# Sucuri API Wrapper

This API wrapper is used to interact with Sucuri's public API. It can be used to add/delete sites on their scanner, query scan results, create malware removal requests, etc.

The configuration file requires an API key, and Sucuri login credentials. The article below details how to retrieve your API key. You will need to use your "Dashboard API" api key, rather than the "Scanning API". 

https://kb.sucuri.net/monitoring/scanning-api

## Methods

#### login()
&nbsp;&nbsp;&nbsp;&nbsp; Login to Sucuri. This is done automatically when necessary.

#### add_site(*String domain*)
&nbsp;&nbsp;&nbsp;&nbsp; Add site to Sucuri's site scanner. 

#### del_site(*String domain*)
&nbsp;&nbsp;&nbsp;&nbsp; Delete site from Sucuri's site scanner.

#### grep_domain(*String domain*)
&nbsp;&nbsp;&nbsp;&nbsp; Check if provided domain exists in Sucuri's site scanner.

#### run_scan(*String domain*)
&nbsp;&nbsp;&nbsp;&nbsp; Force Sucuri to run a new site scan on the provided domain.

#### query(*String domain*)
&nbsp;&nbsp;&nbsp;&nbsp; Query Sucuri site scanner for scan results on the most recent scan. Returns 'result', 'status', and 'query'.

#### ticket_exists(*String domain*)
&nbsp;&nbsp;&nbsp;&nbsp; Checks for an existing "Waiting on your reply" or "In review" malware removal request ticket.

#### create_ticket(*String domain, String host, String username, String password*)
&nbsp;&nbsp;&nbsp;&nbsp; Create a malware removal request with the provided FTP Hostname, username, and password.
