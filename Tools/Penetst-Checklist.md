# Bug Bounty Checklist

## 1. Reconnaissance Techniques

### 1.1 Information Gathering<br />

1. **Google Dorking**: Use advanced search operators to find sensitive information.
<br />[Google Search](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[Bing Search](#)&emsp;&emsp;&emsp; 
[DuckDuckGo](#)&emsp;&emsp;&emsp;<br /><br />

2. **WHOIS Lookup**: Gather domain registration details.
<br />[WHOIS](#)&emsp;&emsp;&emsp; 
[Domaintools](#)&emsp;&emsp;&emsp; 
[WhoisXML API](#)&emsp;&emsp;&emsp; 
[ARIN WHOIS](#)&emsp;&emsp;&emsp; 
[RIPE NCC](#)&emsp;&emsp;&emsp;<br /><br />

3. **Reverse WHOIS Lookup**: Find domains associated with a specific registrant.
<br />[WhoisXML API](#)&emsp;&emsp;&emsp; 
[DomainTools](#)&emsp;&emsp;&emsp; 
[ReverseWHOIS](#)&emsp;&emsp;&emsp; 
[Robtex](#)&emsp;&emsp;&emsp; 
[SecurityTrails](#)&emsp;&emsp;&emsp;<br /><br />

4. **DNS Enumeration**: Identify DNS records like A, MX, NS, TXT, SOA.
<br />[dnsenum](#)&emsp;&emsp;&emsp; 
[dnsrecon](#)&emsp;&emsp;&emsp; 
[dnspython](#)&emsp;&emsp;&emsp; 
[dnsutils](#)&emsp;&emsp;&emsp; 
[fierce](#)&emsp;&emsp;&emsp; 
[dnsmap](#)&emsp;&emsp;&emsp; 
[dnsx](#)&emsp;&emsp;&emsp; 
[sublist3r](#)&emsp;&emsp;&emsp; 
[theHarvester](#)&emsp;&emsp;&emsp; 
[crt.sh](#)&emsp;&emsp;&emsp;<br /><br />

5. **IP Geolocation**: Find the geographical location of IP addresses.
<br />[ipinfo](#)&emsp;&emsp;&emsp; 
[ipapi](#)&emsp;&emsp;&emsp; 
[geoip](#)&emsp;&emsp;&emsp; 
[maxmind](#)&emsp;&emsp;&emsp; 
[ipstack](#)&emsp;&emsp;&emsp; 
[IPLocation.net](#)&emsp;&emsp;&emsp; 
[ipgeolocation.io](#)&emsp;&emsp;&emsp; 
[GeoIP2](#)&emsp;&emsp;&emsp; 
[IPinfo](#)&emsp;&emsp;&emsp; 
[DB-IP](#)&emsp;&emsp;&emsp;<br /><br />

6. **Public Records Search**: Access public records related to the target.
<br />[Pipl](#)&emsp;&emsp;&emsp; 
[Spokeo](#)&emsp;&emsp;&emsp; 
[PeopleFinder](#)&emsp;&emsp;&emsp; 
[Intelius](#)&emsp;&emsp;&emsp; 
[LinkedIn](#)&emsp;&emsp;&emsp; 
[Facebook](#)&emsp;&emsp;&emsp; 
[Whitepages](#)&emsp;&emsp;&emsp; 
[PublicRecords.com](#)&emsp;&emsp;&emsp; 
[ZabaSearch](#)&emsp;&emsp;&emsp; 
[BeenVerified](#)&emsp;&emsp;&emsp;<br /><br />

7. **Search Engine Queries**: Use search engines to gather information.
<br />[Google](#)&emsp;&emsp;&emsp; 
[Bing](#)&emsp;&emsp;&emsp; 
[DuckDuckGo](#)&emsp;&emsp;&emsp; 
[Yandex](#)&emsp;&emsp;&emsp; 
[Startpage](#)&emsp;&emsp;&emsp; 
[Searx](#)&emsp;&emsp;&emsp; 
[Blekko](#)&emsp;&emsp;&emsp; 
[Qwant](#)&emsp;&emsp;&emsp; 
[MetaCrawler](#)&emsp;&emsp;&emsp; 
[WebCrawler](#)&emsp;&emsp;&emsp;<br /><br />

8. **Breach Data Search**: Check for data breaches with services like Have I Been Pwned.
<br />[Have I Been Pwned](#)&emsp;&emsp;&emsp; 
[BreachDirectory](#)&emsp;&emsp;&emsp; 
[DeHashed](#)&emsp;&emsp;&emsp; 
[Leaks.ovh](#)&emsp;&emsp;&emsp; 
[SpyCloud](#)&emsp;&emsp;&emsp; 
[Pwned Passwords](#)&emsp;&emsp;&emsp; 
[BreachAlarm](#)&emsp;&emsp;&emsp; 
[Hacked Emails](#)&emsp;&emsp;&emsp; 
[HackNotice](#)&emsp;&emsp;&emsp; 
[BreachAuth](#)&emsp;&emsp;&emsp;<br /><br />

9. **Social Engineering Techniques**: Use social tactics to gather information.
<br />[Social Engineering Toolkit](#)&emsp;&emsp;&emsp; 
[Recon-ng](#)&emsp;&emsp;&emsp; 
[Maltego](#)&emsp;&emsp;&emsp; 
[OSINT Framework](#)&emsp;&emsp;&emsp; 
[Hunter.io](#)&emsp;&emsp;&emsp; 
[Email Hunter](#)&emsp;&emsp;&emsp; 
[EmailPermutator](#)&emsp;&emsp;&emsp; 
[LinkedIn](#)&emsp;&emsp;&emsp; 
[Facebook](#)&emsp;&emsp;&emsp; 
[Twitter](#)&emsp;&emsp;&emsp;<br /><br />

10. **Publicly Available APIs**: Analyze APIs for exposed information.
 &emsp;&emsp; [Postman](#)&emsp;&emsp;&emsp; 
 [Insomnia](#)&emsp;&emsp;&emsp; 
 [Swagger](#)&emsp;&emsp;&emsp; 
 [APIsec](#)&emsp;&emsp;&emsp; 
 [RapidAPI](#)&emsp;&emsp;&emsp; 
 [Shodan API](#)&emsp;&emsp;&emsp; 
 [Censys API](#)&emsp;&emsp;&emsp; 
 [Google Maps API](#)&emsp;&emsp;&emsp; 
 [IPinfo API](#)&emsp;&emsp;&emsp; 
 [VirusTotal API](#)&emsp;&emsp;&emsp;<br /><br />

11. **Certificate Transparency Logs**: Monitor public logs for SSL certificates.
 &emsp;&emsp; [crt.sh](#)&emsp;&emsp;&emsp; 
 [CertSpotter](#)&emsp;&emsp;&emsp; 
 [Google Certificate Transparency](#)&emsp;&emsp;&emsp; 
 [SSL Labs](#)&emsp;&emsp;&emsp; 
 [PassiveTotal](#)&emsp;&emsp;&emsp; 
 [CertStream](#)&emsp;&emsp;&emsp; 
 [Certificate Transparency Logs](#)&emsp;&emsp;&emsp; 
 [Symantec CT](#)&emsp;&emsp;&emsp; 
 [Cloudflare CT Logs](#)&emsp;&emsp;&emsp; 
 [HackerOne CT Logs](#)&emsp;&emsp;&emsp;<br /><br />

12. **Domain History Analysis**: Use tools to analyze historical domain data.
 &emsp;&emsp; [DomainTools](#)&emsp;&emsp;&emsp; 
 [WhoisXML API](#)&emsp;&emsp;&emsp; 
 [Wayback Machine](#)&emsp;&emsp;&emsp; 
 [Archive.org](#)&emsp;&emsp;&emsp; 
 [DNS History](#)&emsp;&emsp;&emsp; 
 [Historical WHOIS](#)&emsp;&emsp;&emsp; 
 [Netcraft](#)&emsp;&emsp;&emsp; 
 [Robtex](#)&emsp;&emsp;&emsp; 
 [SecurityTrails](#)&emsp;&emsp;&emsp; 
 [BuiltWith](#)&emsp;&emsp;&emsp;

### 1.2 Subdomain and Domain Discovery<br /><br />

1. **Subdomain Enumeration**: Discover subdomains using tools like Sublist3r or Amass.
<br />[Sublist3r](#)&emsp;&emsp;&emsp; 
[Amass](#)&emsp;&emsp;&emsp; 
[Subfinder](#)&emsp;&emsp;&emsp; 
[Findomain](#)&emsp;&emsp;&emsp; 
[Subjack](#)&emsp;&emsp;&emsp; 
[Assetfinder](#)&emsp;&emsp;&emsp; 
[Knockpy](#)&emsp;&emsp;&emsp; 
[Subzy](#)&emsp;&emsp;&emsp; 
[Subdomainizer](#)&emsp;&emsp;&emsp; 
[CRT.sh](#)&emsp;&emsp;&emsp;<br /><br />

2. **Reverse IP Lookup**: Identify other domains hosted on the same IP.
<br />[Reverse IP Lookup](#)&emsp;&emsp;&emsp; 
[Robtex](#)&emsp;&emsp;&emsp; 
[SecurityTrails](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[Netcraft](#)&emsp;&emsp;&emsp; 
[DNSdumpster](#)&emsp;&emsp;&emsp; 
[Spyse](#)&emsp;&emsp;&emsp; 
[ThreatMiner](#)&emsp;&emsp;&emsp; 
[Webscan](#)&emsp;&emsp;&emsp;<br /><br />

3. **DNS Dumpster Diving**: Extract information about DNS records.
<br />[dnsdumpster](#)&emsp;&emsp;&emsp; 
[dnsrecon](#)&emsp;&emsp;&emsp; 
[dnstracer](#)&emsp;&emsp;&emsp; 
[dnsutils](#)&emsp;&emsp;&emsp; 
[DNSMap](#)&emsp;&emsp;&emsp; 
[Fierce](#)&emsp;&emsp;&emsp; 
[Netcraft](#)&emsp;&emsp;&emsp; 
[Google DNS](#)&emsp;&emsp;&emsp; 
[SecurityTrails](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp;<br /><br />

4. **Zone Transfers**: Attempt DNS zone transfers to gather records.
<br />[dig](#)&emsp;&emsp;&emsp; 
[nslookup](#)&emsp;&emsp;&emsp; 
[dnsrecon](#)&emsp;&emsp;&emsp; 
[Fierce](#)&emsp;&emsp;&emsp; 
[DNSMap](#)&emsp;&emsp;&emsp; 
[dnstracer](#)&emsp;&emsp;&emsp; 
[dnsscan](#)&emsp;&emsp;&emsp; 
[Zone Transfer Scanner](#)&emsp;&emsp;&emsp; 
[Recon-ng](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp;

### 1.3 Technology and Service Identification<br /><br />

1. **Website Footprinting**: Identify technologies, server details, and software versions.
<br />[Wappalyzer](#)&emsp;&emsp;&emsp; 
[WhatWeb](#)&emsp;&emsp;&emsp; 
[BuiltWith](#)&emsp;&emsp;&emsp; 
[Netcraft](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[HTTP Headers](#)&emsp;&emsp;&emsp; 
[Wappalyzer](#)&emsp;&emsp;&emsp; 
[WhatCMS](#)&emsp;&emsp;&emsp; 
[Gau](#)&emsp;&emsp;&emsp;<br /><br />

2. **Shodan Search**: Find internet-connected devices and their details.
<br />[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[ZoomEye](#)&emsp;&emsp;&emsp; 
[BinaryEdge](#)&emsp;&emsp;&emsp; 
[Fofa](#)&emsp;&emsp;&emsp; 
[Rapid7](#)&emsp;&emsp;&emsp; 
[GreyNoise](#)&emsp;&emsp;&emsp; 
[Pulsedive](#)&emsp;&emsp;&emsp; 
[ThreatQuotient](#)&emsp;&emsp;&emsp; 
[RATelnet](#)&emsp;&emsp;&emsp;<br /><br />

3. **Censys Search**: Identify and analyze devices and systems.
<br />[Censys](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[ZoomEye](#)&emsp;&emsp;&emsp; 
[BinaryEdge](#)&emsp;&emsp;&emsp; 
[Fofa](#)&emsp;&emsp;&emsp; 
[Rapid7](#)&emsp;&emsp;&emsp; 
[GreyNoise](#)&emsp;&emsp;&emsp; 
[Pulsedive](#)&emsp;&emsp;&emsp; 
[ThreatQuotient](#)&emsp;&emsp;&emsp; 
[RATelnet](#)&emsp;&emsp;&emsp;<br /><br />

4. **SSL/TLS Certificate Analysis**: Review certificates for associated domains.
<br />[SSLLabs](#)&emsp;&emsp;&emsp; 
[CertSpotter](#)&emsp;&emsp;&emsp; 
[crt.sh](#)&emsp;&emsp;&emsp; 
[SSL Certificate Checker](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[SecurityTrails](#)&emsp;&emsp;&emsp; 
[SSL Labs](#)&emsp;&emsp;&emsp; 
[CertStream](#)&emsp;&emsp;&emsp; 
[SSL Checker](#)&emsp;&emsp;&emsp;<br /><br />

5. **Web Application Framework Identification**: Determine the frameworks used on a website.
<br />[Wappalyzer](#)&emsp;&emsp;&emsp; 
[WhatWeb](#)&emsp;&emsp;&emsp; 
[BuiltWith](#)&emsp;&emsp;&emsp; 
[Netcraft](#)&emsp;&emsp;&emsp; 
[CMS Detector](#)&emsp;&emsp;&emsp; 
[Framework Scanner](#)&emsp;&emsp;&emsp; 
[HTTP Headers](#)&emsp;&emsp;&emsp; 
[Wappalyzer](#)&emsp;&emsp;&emsp; 
[WebTech](#)&emsp;&emsp;&emsp; 
[AppDetective](#)&emsp;&emsp;&emsp;<br /><br />

6. **Netcraft Site Reports**: Analyze site reports for server details and technologies.
<br />[Netcraft](#)&emsp;&emsp;&emsp; 
[BuiltWith](#)&emsp;&emsp;&emsp; 
[Wappalyzer](#)&emsp;&emsp;&emsp; 
[WhatWeb](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[SecurityTrails](#)&emsp;&emsp;&emsp; 
[SSL Labs](#)&emsp;&emsp;&emsp; 
[Wayback Machine](#)&emsp;&emsp;&emsp; 
[Webscreenshot](#)&emsp;&emsp;&emsp;

### 1.4 Metadata and Historical Data<br /><br />

1. **FOCA**: Extract metadata from documents and images.
<br />[FOCA](#)&emsp;&emsp;&emsp; 
[ExifTool](#)&emsp;&emsp;&emsp; 
[Metadata Extractor](#)&emsp;&emsp;&emsp; 
[ExifPilot](#)&emsp;&emsp;&emsp; 
[Metagoofil](#)&emsp;&emsp;&emsp; 
[DocScraper](#)&emsp;&emsp;&emsp; 
[PDF-Analyzer](#)&emsp;&emsp;&emsp; 
[X1](#)&emsp;&emsp;&emsp; 
[Metagoofil](#)&emsp;&emsp;&emsp; 
[ExifTool](#)&emsp;&emsp;&emsp;<br /><br />

2. **ExifTool**: Extract metadata from files and images.
<br />[ExifTool](#)&emsp;&emsp;&emsp; 
[FOCA](#)&emsp;&emsp;&emsp; 
[Metadata Extractor](#)&emsp;&emsp;&emsp; 
[ExifPilot](#)&emsp;&emsp;&emsp; 
[DocScraper](#)&emsp;&emsp;&emsp; 
[PDF-Analyzer](#)&emsp;&emsp;&emsp; 
[X1](#)&emsp;&emsp;&emsp; 
[Metagoofil](#)&emsp;&emsp;&emsp; 
[ExifTool](#)&emsp;&emsp;&emsp; 
[Metadata++](#)&emsp;&emsp;&emsp;<br /><br />

3. **Wayback Machine**: Retrieve historical versions of web pages.
<br />[Wayback Machine](#)&emsp;&emsp;&emsp; 
[Archive.org](#)&emsp;&emsp;&emsp; 
[Oldweb.today](#)&emsp;&emsp;&emsp; 
[WebCite](#)&emsp;&emsp;&emsp; 
[PageFreezer](#)&emsp;&emsp;&emsp; 
[Google Cache](#)&emsp;&emsp;&emsp; 
[Bing Cache](#)&emsp;&emsp;&emsp; 
[Yandex Cache](#)&emsp;&emsp;&emsp; 
[Wayback Machine API](#)&emsp;&emsp;&emsp; 
[Netarchive](#)&emsp;&emsp;&emsp;<br /><br />

4. **Github Repository Search**: Look for sensitive information in code repositories.
<br />[Github Search](#)&emsp;&emsp;&emsp; 
[GitHub Code Search](#)&emsp;&emsp;&emsp; 
[GitHound](#)&emsp;&emsp;&emsp; 
[TruffleHog](#)&emsp;&emsp;&emsp; 
[Repo-Extractor](#)&emsp;&emsp;&emsp; 
[GitSecrets](#)&emsp;&emsp;&emsp; 
[Gitleaks](#)&emsp;&emsp;&emsp; 
[GitRob](#)&emsp;&emsp;&emsp; 
[GitGuardian](#)&emsp;&emsp;&emsp; 
[GitGraber](#)&emsp;&emsp;&emsp;<br /><br />

5. **Metadata Analysis**: Analyze file and document metadata.
<br />[ExifTool](#)&emsp;&emsp;&emsp; 
[FOCA](#)&emsp;&emsp;&emsp; 
[Metadata Extractor](#)&emsp;&emsp;&emsp; 
[DocScraper](#)&emsp;&emsp;&emsp; 
[PDF-Analyzer](#)&emsp;&emsp;&emsp; 
[Metagoofil](#)&emsp;&emsp;&emsp; 
[X1](#)&emsp;&emsp;&emsp; 
[Metagoofil](#)&emsp;&emsp;&emsp; 
[ExifTool](#)&emsp;&emsp;&emsp; 
[Metadata++](#)&emsp;&emsp;&emsp;

### 1.5 Network and Traffic Analysis<br /><br />

1. **Network Mapping**: Map out network topology with tools like Nmap.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Zenmap](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Angry IP Scanner](#)&emsp;&emsp;&emsp; 
[Unicornscan](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[Advanced IP Scanner](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Netdiscover](#)&emsp;&emsp;&emsp;<br /><br />

2. **Network Traffic Analysis**: Analyze network traffic for service and system information.
<br />[Wireshark](#)&emsp;&emsp;&emsp; 
[tcpdump](#)&emsp;&emsp;&emsp; 
[Tshark](#)&emsp;&emsp;&emsp; 
[Kismet](#)&emsp;&emsp;&emsp; 
[NetworkMiner](#)&emsp;&emsp;&emsp; 
[Zeek](#)&emsp;&emsp;&emsp; 
[EtherApe](#)&emsp;&emsp;&emsp; 
[Snort](#)&emsp;&emsp;&emsp; 
[NetFlow](#)&emsp;&emsp;&emsp; 
[Colasoft Capsa](#)&emsp;&emsp;&emsp;<br /><br />

3. **IP Range Scanning**: Identify IP ranges associated with the target.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Unicornscan](#)&emsp;&emsp;&emsp; 
[Netdiscover](#)&emsp;&emsp;&emsp; 
[Angry IP Scanner](#)&emsp;&emsp;&emsp; 
[Advanced IP Scanner](#)&emsp;&emsp;&emsp; 
[Fping](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp;<br /><br />

4. **Network Enumeration**: Use traceroute to identify network paths.
<br />[Traceroute](#)&emsp;&emsp;&emsp; 
[MTR](#)&emsp;&emsp;&emsp; 
[PingPlotter](#)&emsp;&emsp;&emsp; 
[PathPing](#)&emsp;&emsp;&emsp; 
[Tracert](#)&emsp;&emsp;&emsp; 
[NetworkMiner](#)&emsp;&emsp;&emsp; 
[TraceRoute](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Hping](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp;

## 2. Enumeration Techniques

### 2.1 Service and Port Enumeration<br /><br />

1. **Service Enumeration**: Identify active services and their versions.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Service Scanner](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[TCP Port Scanner](#)&emsp;&emsp;&emsp;<br /><br />

2. **Port Scanning**: Identify open ports and services running on the target.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Unicornscan](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Angry IP Scanner](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[PortQry](#)&emsp;&emsp;&emsp; 
[Fping](#)&emsp;&emsp;&emsp;<br /><br />

3. **Banner Grabbing**: Obtain service banners to determine versions.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Telnet](#)&emsp;&emsp;&emsp; 
[BannerGrab](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Telnet](#)&emsp;&emsp;&emsp; 
[WhatWeb](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[BannerGrabber](#)&emsp;&emsp;&emsp;<br /><br />

4. **FTP Enumeration**: List files and directories on FTP servers.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[ftp](#)&emsp;&emsp;&emsp; 
[NcFTP](#)&emsp;&emsp;&emsp; 
[WinSCP](#)&emsp;&emsp;&emsp; 
[FileZilla](#)&emsp;&emsp;&emsp; 
[FTPScan](#)&emsp;&emsp;&emsp; 
[Hydra](#)&emsp;&emsp;&emsp; 
[FTPEnum](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp;<br /><br />

5. **HTTP Methods Testing**: Check for supported HTTP methods.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp; 
[OWASP ZAP](#)&emsp;&emsp;&emsp; 
[Nikto](#)&emsp;&emsp;&emsp; 
[HTTP Methods](#)&emsp;&emsp;&emsp; 
[Wapiti](#)&emsp;&emsp;&emsp; 
[WhatWeb](#)&emsp;&emsp;&emsp; 
[Dirb](#)&emsp;&emsp;&emsp; 
[Gau](#)&emsp;&emsp;&emsp; 
[HTTPX](#)&emsp;&emsp;&emsp;<br /><br />

6. **WebDAV Enumeration**: Explore WebDAV services for vulnerabilities.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp; 
[OWASP ZAP](#)&emsp;&emsp;&emsp; 
[Nikto](#)&emsp;&emsp;&emsp; 
[WebDAV Scanner](#)&emsp;&emsp;&emsp; 
[dirb](#)&emsp;&emsp;&emsp; 
[Wapiti](#)&emsp;&emsp;&emsp; 
[Gau](#)&emsp;&emsp;&emsp; 
[HTTPX](#)&emsp;&emsp;&emsp; 
[WebDAV](#)&emsp;&emsp;&emsp;<br /><br />

7. **NFS Enumeration**: Identify Network File System shares and permissions.
<br />[showmount](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[rpcinfo](#)&emsp;&emsp;&emsp; 
[nfsstat](#)&emsp;&emsp;&emsp; 
[nmap -p 2049](#)&emsp;&emsp;&emsp; 
[nfs-common](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Hydra](#)&emsp;&emsp;&emsp;

### 2.2 User and Resource Enumeration<br /><br />

1. **User Enumeration**: Find valid usernames using tools like Hydra or Medusa.
<br />[Hydra](#)&emsp;&emsp;&emsp; 
[Medusa](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[Snmpwalk](#)&emsp;&emsp;&emsp; 
[SMBclient](#)&emsp;&emsp;&emsp; 
[LDAP Enumeration](#)&emsp;&emsp;&emsp; 
[Kerberos Enumeration](#)&emsp;&emsp;&emsp; 
[Fuzzdb](#)&emsp;&emsp;&emsp;<br /><br />

2. **SMB Enumeration**: Extract information from SMB shares using tools like enum4linux.
<br />[enum4linux](#)&emsp;&emsp;&emsp; 
[SMBclient](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[SMBMap](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[SMBScanner](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp;<br /><br />

3. **NetBIOS Enumeration**: Gather NetBIOS information with nbtstat.
<br />[nbtstat](#)&emsp;&emsp;&emsp; 
[NetBIOS Scanner](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[SMBclient](#)&emsp;&emsp;&emsp; 
[NetView](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Hydra](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Smbclient](#)&emsp;&emsp;&emsp;<br /><br />

4. **SNMP Enumeration**: Extract SNMP data with snmpwalk.
<br />[snmpwalk](#)&emsp;&emsp;&emsp; 
[nmap](#)&emsp;&emsp;&emsp; 
[onesixtyone](#)&emsp;&emsp;&emsp; 
[snmpenum](#)&emsp;&emsp;&emsp; 
[snmpcheck](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[SolarWinds](#)&emsp;&emsp;&emsp; 
[SolarWinds SNMP Walk](#)&emsp;&emsp;&emsp;<br /><br />

5. **LDAP Enumeration**: Query LDAP servers for user and group details.
<br />[ldapsearch](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[LDAP Enumeration](#)&emsp;&emsp;&emsp; 
[LDAPScan](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Ldapdomaindump](#)&emsp;&emsp;&emsp;<br /><br />

6. **SMTP Enumeration**: Discover email configurations using tools like SMTPSend.
<br />[smtp-user-enum](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[SMTPSend](#)&emsp;&emsp;&emsp; 
[SMTPScan](#)&emsp;&emsp;&emsp; 
[SMTP Enumeration](#)&emsp;&emsp;&emsp; 
[Harvester](#)&emsp;&emsp;&emsp; 
[Snmpwalk](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp; 
[EmailHunter](#)&emsp;&emsp;&emsp;<br /><br />

7. **Kerberos Enumeration**: Enumerate Kerberos tickets and services.
<br />[Kerberoast](#)&emsp;&emsp;&emsp; 
[Rubeus](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Evil-WinRM](#)&emsp;&emsp;&emsp; 
[GetNPUsers](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[BloodHound](#)&emsp;&emsp;&emsp;<br /><br />

8. **RPC Enumeration**: Identify RPC services and versions.
<br />[rpcinfo](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[SMBclient](#)&emsp;&emsp;&emsp; 
[Hydra](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[RPCScan](#)&emsp;&emsp;&emsp;<br /><br />

9. **LDAP Injection Testing**: Test for LDAP injection vulnerabilities.
<br />[LDAPInjection](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp; 
[OWASP ZAP](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Sqlmap](#)&emsp;&emsp;&emsp; 
[LDAPi](#)&emsp;&emsp;&emsp; 
[Fuzzdb](#)&emsp;&emsp;&emsp; 
[DirBuster](#)&emsp;&emsp;&emsp; 
[Gf](#)&emsp;&emsp;&emsp;<br /><br />

10. **Kerberoasting**: Extract and crack service tickets from Kerberos.
 &emsp;&emsp; [Rubeus](#)&emsp;&emsp;&emsp; 
 [Impacket](#)&emsp;&emsp;&emsp; 
 [Kerberoast](#)&emsp;&emsp;&emsp; 
 [Metasploit](#)&emsp;&emsp;&emsp; 
 [CrackMapExec](#)&emsp;&emsp;&emsp; 
 [PowerView](#)&emsp;&emsp;&emsp; 
 [BloodHound](#)&emsp;&emsp;&emsp; 
 [GetNPUsers](#)&emsp;&emsp;&emsp; 
 [Kerbrute](#)&emsp;&emsp;&emsp; 
 [Kerbrute](#)&emsp;&emsp;&emsp;

## 3. Scanning Techniques

### 3.1 Network and Service Scanning<br /><br />

1. **Network Scanning**: Discover live hosts and network services.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Unicornscan](#)&emsp;&emsp;&emsp; 
[Netdiscover](#)&emsp;&emsp;&emsp; 
[Angry IP Scanner](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Advanced IP Scanner](#)&emsp;&emsp;&emsp;<br /><br />

2. **Port Scanning**: Identify open ports with detailed options.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Unicornscan](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Angry IP Scanner](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[PortQry](#)&emsp;&emsp;&emsp; 
[Fping](#)&emsp;&emsp;&emsp;<br /><br />

3. **Service Scanning**: Determine services running on open ports.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Unicornscan](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[TCP Port Scanner](#)&emsp;&emsp;&emsp;<br /><br />

4. **Operating System Fingerprinting**: Identify the operating system using tools like Nmap or p0f.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[p0f](#)&emsp;&emsp;&emsp; 
[Xprobe2](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[OS Fingerprinter](#)&emsp;&emsp;&emsp; 
[P0f](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp;<br /><br />

5. **Web Application Scanning**: Detect vulnerabilities in web applications using tools like OWASP ZAP or Burp Suite.
<br />[OWASP ZAP](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp; 
[Nikto](#)&emsp;&emsp;&emsp; 
[Wapiti](#)&emsp;&emsp;&emsp; 
[Arachni](#)&emsp;&emsp;&emsp; 
[Acunetix](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[W3af](#)&emsp;&emsp;&emsp; 
[SQLMap](#)&emsp;&emsp;&emsp;<br /><br />

6. **DNS Scanning**: Scan DNS records and identify potential misconfigurations.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[dnsenum](#)&emsp;&emsp;&emsp; 
[dnsrecon](#)&emsp;&emsp;&emsp; 
[dnsutils](#)&emsp;&emsp;&emsp; 
[dnsmap](#)&emsp;&emsp;&emsp; 
[fierce](#)&emsp;&emsp;&emsp; 
[DNSEnum](#)&emsp;&emsp;&emsp; 
[DNSRecon](#)&emsp;&emsp;&emsp; 
[DNSMap](#)&emsp;&emsp;&emsp; 
[Fierce](#)&emsp;&emsp;&emsp;<br /><br />

7. **SSL/TLS Scanning**: Check SSL/TLS configurations and vulnerabilities using tools like Qualys SSL Labs.
<br />[Qualys SSL Labs](#)&emsp;&emsp;&emsp; 
[SSLLabs](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[OpenSSL](#)&emsp;&emsp;&emsp; 
[SSLScan](#)&emsp;&emsp;&emsp; 
[TestSSL](#)&emsp;&emsp;&emsp; 
[SSLYze](#)&emsp;&emsp;&emsp; 
[Cipherscan](#)&emsp;&emsp;&emsp; 
[SSLStrip](#)&emsp;&emsp;&emsp; 
[Hardenize](#)&emsp;&emsp;&emsp;

### 3.2 Vulnerability and Protocol Scanning<br /><br />

1. **Vulnerability Scanning**: Identify known vulnerabilities using tools like Nessus or OpenVAS.
<br />[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Qualys](#)&emsp;&emsp;&emsp; 
[Rapid7 InsightVM](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp; 
[Acunetix](#)&emsp;&emsp;&emsp; 
[Wapiti](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Arachni](#)&emsp;&emsp;&emsp; 
[AppScan](#)&emsp;&emsp;&emsp;<br /><br />

2. **Port Sweeping**: Scan a range of ports to identify open services.
<br />[Nmap](#)&emsp;&emsp;&emsp; 
[Masscan](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Unicornscan](#)&emsp;&emsp;&emsp; 
[Fping](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Angry IP Scanner](#)&emsp;&emsp;&emsp; 
[PortQry](#)&emsp;&emsp;&emsp; 
[Zmap](#)&emsp;&emsp;&emsp; 
[Netdiscover](#)&emsp;&emsp;&emsp;<br /><br />

3. **Application Scanning**: Identify vulnerabilities in applications and services.
<br />[OWASP ZAP](#)&emsp;&emsp;&emsp; 
[Burp Suite](#)&emsp;&emsp;&emsp; 
[Nessus](#)&emsp;&emsp;&emsp; 
[OpenVAS](#)&emsp;&emsp;&emsp; 
[Acunetix](#)&emsp;&emsp;&emsp; 
[AppScan](#)&emsp;&emsp;&emsp; 
[Wapiti](#)&emsp;&emsp;&emsp; 
[Arachni](#)&emsp;&emsp;&emsp; 
[AppSpider](#)&emsp;&emsp;&emsp; 
[Nikto](#)&emsp;&emsp;&emsp;<br /><br />

4. **Network Protocol Analysis**: Analyze network protocols for weaknesses.
<br />[Wireshark](#)&emsp;&emsp;&emsp; 
[tcpdump](#)&emsp;&emsp;&emsp; 
[Tshark](#)&emsp;&emsp;&emsp; 
[Kismet](#)&emsp;&emsp;&emsp; 
[NetFlow](#)&emsp;&emsp;&emsp; 
[Snort](#)&emsp;&emsp;&emsp; 
[Zeek](#)&emsp;&emsp;&emsp; 
[Colasoft Capsa](#)&emsp;&emsp;&emsp; 
[NetworkMiner](#)&emsp;&emsp;&emsp; 
[Suricata](#)&emsp;&emsp;&emsp;<br /><br />

5. **Wireless Scanning**: Identify and analyze wireless networks and their security settings.
<br />[Kismet](#)&emsp;&emsp;&emsp; 
[Aircrack-ng](#)&emsp;&emsp;&emsp; 
[Wireshark](#)&emsp;&emsp;&emsp; 
[Reaver](#)&emsp;&emsp;&emsp; 
[Fern Wifi Cracker](#)&emsp;&emsp;&emsp; 
[Wifite](#)&emsp;&emsp;&emsp; 
[NetStumbler](#)&emsp;&emsp;&emsp; 
[InSSIDer](#)&emsp;&emsp;&emsp; 
[Airodump-ng](#)&emsp;&emsp;&emsp; 
[WPS Cracker](#)&emsp;&emsp;&emsp;

## 4. OSINT Techniques
<br /><br />

1. **Social Media Analysis**: Collect information from social media platforms.
<br />[Maltego](#)&emsp;&emsp;&emsp; 
[Social-Engineer Toolkit](#)&emsp;&emsp;&emsp; 
[Recon-ng](#)&emsp;&emsp;&emsp; 
[Spokeo](#)&emsp;&emsp;&emsp; 
[Pipl](#)&emsp;&emsp;&emsp; 
[LinkedIn](#)&emsp;&emsp;&emsp; 
[Facebook](#)&emsp;&emsp;&emsp; 
[Twitter](#)&emsp;&emsp;&emsp; 
[Instagram](#)&emsp;&emsp;&emsp; 
[Social Mapper](#)&emsp;&emsp;&emsp;<br /><br />

2. **Public Records Search**: Access public records and databases.
<br />[Pipl](#)&emsp;&emsp;&emsp; 
[Spokeo](#)&emsp;&emsp;&emsp; 
[PeopleFinder](#)&emsp;&emsp;&emsp; 
[Intelius](#)&emsp;&emsp;&emsp; 
[LinkedIn](#)&emsp;&emsp;&emsp; 
[Facebook](#)&emsp;&emsp;&emsp; 
[Whitepages](#)&emsp;&emsp;&emsp; 
[PublicRecords.com](#)&emsp;&emsp;&emsp; 
[ZabaSearch](#)&emsp;&emsp;&emsp; 
[BeenVerified](#)&emsp;&emsp;&emsp;<br /><br />

3. **Domain and IP Lookup**: Investigate domain and IP address information.
<br />[WHOIS](#)&emsp;&emsp;&emsp; 
[DomainTools](#)&emsp;&emsp;&emsp; 
[ipinfo](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[Shodan](#)&emsp;&emsp;&emsp; 
[Google Search](#)&emsp;&emsp;&emsp; 
[Bing Search](#)&emsp;&emsp;&emsp; 
[dnsenum](#)&emsp;&emsp;&emsp; 
[dnsrecon](#)&emsp;&emsp;&emsp; 
[ipapi]&emsp;&emsp; <br /><br />

4. **Historical Data Search**: Access historical data on websites and domains.
<br />[Wayback Machine](#)&emsp;&emsp;&emsp; 
[Archive.org](#)&emsp;&emsp;&emsp; 
[Oldweb.today](#)&emsp;&emsp;&emsp; 
[WebCite](#)&emsp;&emsp;&emsp; 
[PageFreezer](#)&emsp;&emsp;&emsp; 
[Google Cache](#)&emsp;&emsp;&emsp; 
[Bing Cache](#)&emsp;&emsp;&emsp; 
[Yandex Cache](#)&emsp;&emsp;&emsp; 
[Netarchive](#)&emsp;&emsp;&emsp; 
[Wayback Machine API](#)&emsp;&emsp;&emsp;<br /><br />

5. **Code Repository Search**: Look for sensitive information in public code repositories.
<br />[Github Search](#)&emsp;&emsp;&emsp; 
[GitHub Code Search](#)&emsp;&emsp;&emsp; 
[GitHound](#)&emsp;&emsp;&emsp; 
[TruffleHog](#)&emsp;&emsp;&emsp; 
[Repo-Extractor](#)&emsp;&emsp;&emsp; 
[GitSecrets](#)&emsp;&emsp;&emsp; 
[Gitleaks](#)&emsp;&emsp;&emsp; 
[GitRob](#)&emsp;&emsp;&emsp; 
[GitGuardian](#)&emsp;&emsp;&emsp; 
[GitGraber](#)&emsp;&emsp;&emsp;<br /><br />

6. **Online People Search**: Find personal details and professional backgrounds.
<br />[Pipl](#)&emsp;&emsp;&emsp; 
[Intelius](#)&emsp;&emsp;&emsp; 
[Spokeo](#)&emsp;&emsp;&emsp; 
[PeopleFinders](#)&emsp;&emsp;&emsp; 
[LinkedIn](#)&emsp;&emsp;&emsp; 
[Facebook](#)&emsp;&emsp;&emsp; 
[Whitepages](#)&emsp;&emsp;&emsp; 
[BeenVerified](#)&emsp;&emsp;&emsp; 
[ZabaSearch](#)&emsp;&emsp;&emsp; 
[PublicRecords.com](#)&emsp;&emsp;&emsp;<br /><br />

7. **Technical Analysis**: Analyze publicly available technical data.
<br />[Shodan](#)&emsp;&emsp;&emsp; 
[Censys](#)&emsp;&emsp;&emsp; 
[Google Search](#)&emsp;&emsp;&emsp; 
[Bing Search](#)&emsp;&emsp;&emsp; 
[CVE Details](#)&emsp;&emsp;&emsp; 
[Exploit-DB](#)&emsp;&emsp;&emsp; 
[Mitre ATT&CK](#)&emsp;&emsp;&emsp; 
[Common Vuln. Scoring System (CVSS)](#)&emsp;&emsp;&emsp; 
[NVD](#)&emsp;&emsp;&emsp; 
[OSINT Framework](#)&emsp;&emsp;&emsp;

## 5. Active Directory Enumeration
<br /><br />

1. **Domain Enumeration**: Gather information about the domain structure.
<br />[BloodHound](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[ADRecon](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[LDAP Enumeration](#)&emsp;&emsp;&emsp; 
[Kerberos Enumeration](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp;<br /><br />

2. **User Enumeration**: Identify domain users.
<br />[BloodHound](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[ADRecon](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Kerberos Enumeration](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[NetUser](#)&emsp;&emsp;&emsp; 
[ADfind](#)&emsp;&emsp;&emsp;<br /><br />

3. **Group Enumeration**: Discover groups and their memberships.
<br />[BloodHound](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[ADRecon](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Kerberos Enumeration](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[NetGroup](#)&emsp;&emsp;&emsp; 
[ADfind](#)&emsp;&emsp;&emsp;<br /><br />

4. **Domain Trust Enumeration**: Identify domain trusts and relationships.
<br />[BloodHound](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[ADRecon](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Kerberos Enumeration](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[Netdom](#)&emsp;&emsp;&emsp; 
[TrustInspector](#)&emsp;&emsp;&emsp;<br /><br />

5. **ACL Enumeration**: Review Access Control Lists for misconfigurations.
<br />[BloodHound](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[ADRecon](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Kerberos Enumeration](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[NetDom](#)&emsp;&emsp;&emsp; 
[Dcom](#)&emsp;&emsp;&emsp;<br /><br />

6. **Kerberoasting**: Extract service tickets to crack passwords.
<br />[Kerberoast](#)&emsp;&emsp;&emsp; 
[Rubeus](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[BloodHound](#)&emsp;&emsp;&emsp; 
[GetNPUsers](#)&emsp;&emsp;&emsp; 
[Kerbrute](#)&emsp;&emsp;&emsp; 
[Kerberoast](#)&emsp;&emsp;&emsp; 
[GetUserSPNs](#)&emsp;&emsp;&emsp;<br /><br />

7. **SPN Enumeration**: Discover Service Principal Names.
<br />[Kerberoast](#)&emsp;&emsp;&emsp; 
[Rubeus](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[BloodHound](#)&emsp;&emsp;&emsp; 
[GetNPUsers](#)&emsp;&emsp;&emsp; 
[Kerbrute](#)&emsp;&emsp;&emsp; 
[GetUserSPNs](#)&emsp;&emsp;&emsp; 
[Kerberoast](#)&emsp;&emsp;&emsp;<br /><br />

8. **Kerberos Ticket Extraction**: Obtain Kerberos tickets for analysis.
<br />[Rubeus](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[Kerberoast](#)&emsp;&emsp;&emsp; 
[GetNPUsers](#)&emsp;&emsp;&emsp; 
[CrackMapExec](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[BloodHound](#)&emsp;&emsp;&emsp; 
[Kerbrute](#)&emsp;&emsp;&emsp; 
[Kerberoast](#)&emsp;&emsp;&emsp; 
[Mimikatz](#)&emsp;&emsp;&emsp;

## 6. Privilege Escalation Techniques

### 6.1 Linux Privilege Escalation<br /><br />

1. **SUID/SGID Files**: Identify files with SUID or SGID permissions.
<br />[find](#)&emsp;&emsp;&emsp; 
[LinPeas](#)&emsp;&emsp;&emsp; 
[Linux Exploit Suggester](#)&emsp;&emsp;&emsp; 
[GTFOBins](#)&emsp;&emsp;&emsp; 
[LinEnum](#)&emsp;&emsp;&emsp; 
[Pspy](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[RogueMaster](#)&emsp;&emsp;&emsp;<br /><br />

2. **Kernel Exploits**: Check for vulnerabilities in the Linux kernel.
<br />[uname](#)&emsp;&emsp;&emsp; 
[Kernel Exploits](#)&emsp;&emsp;&emsp; 
[Linux Exploit Suggester](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp;<br /><br />

3. **Cron Jobs**: Identify misconfigured cron jobs.
<br />[crontab](#)&emsp;&emsp;&emsp; 
[LinPeas](#)&emsp;&emsp;&emsp; 
[Linux Exploit Suggester](#)&emsp;&emsp;&emsp; 
[GTFOBins](#)&emsp;&emsp;&emsp; 
[LinEnum](#)&emsp;&emsp;&emsp; 
[Pspy](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[RogueMaster](#)&emsp;&emsp;&emsp;<br /><br />

4. **Writable Directories**: Check for directories where files can be written.
<br />[find](#)&emsp;&emsp;&emsp; 
[LinPeas](#)&emsp;&emsp;&emsp; 
[Linux Exploit Suggester](#)&emsp;&emsp;&emsp; 
[GTFOBins](#)&emsp;&emsp;&emsp; 
[LinEnum](#)&emsp;&emsp;&emsp; 
[Pspy](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[RogueMaster](#)&emsp;&emsp;&emsp;<br /><br />

5. **Environment Variables**: Inspect environment variables for sensitive data.
<br />[env](#)&emsp;&emsp;&emsp; 
[printenv](#)&emsp;&emsp;&emsp; 
[LinPeas](#)&emsp;&emsp;&emsp; 
[Linux Exploit Suggester](#)&emsp;&emsp;&emsp; 
[GTFOBins](#)&emsp;&emsp;&emsp; 
[LinEnum](#)&emsp;&emsp;&emsp; 
[Pspy](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[RogueMaster](#)&emsp;&emsp;&emsp;<br /><br />

6. **SetUID Binaries**: Check for binaries with SetUID permissions.
<br />[find](#)&emsp;&emsp;&emsp; 
[LinPeas](#)&emsp;&emsp;&emsp; 
[Linux Exploit Suggester](#)&emsp;&emsp;&emsp; 
[GTFOBins](#)&emsp;&emsp;&emsp; 
[LinEnum](#)&emsp;&emsp;&emsp; 
[Pspy](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[RogueMaster](#)&emsp;&emsp;&emsp;<br /><br />

7. **Sudo Permissions**: Inspect sudo permissions and configurations.
<br />[sudo -l](#)&emsp;&emsp;&emsp; 
[LinPeas](#)&emsp;&emsp;&emsp; 
[Linux Exploit Suggester](#)&emsp;&emsp;&emsp; 
[GTFOBins](#)&emsp;&emsp;&emsp; 
[LinEnum](#)&emsp;&emsp;&emsp; 
[Pspy](#)&emsp;&emsp;&emsp; 
[Enum4linux](#)&emsp;&emsp;&emsp; 
[RogueMaster](#)&emsp;&emsp;&emsp;

### 6.2 Windows Privilege Escalation<br /><br />

1. **Unquoted Service Paths**: Identify unquoted service paths that can be exploited.
<br />[wmic](#)&emsp;&emsp;&emsp; 
[PowerShell](#)&emsp;&emsp;&emsp; 
[Sysinternals](#)&emsp;&emsp;&emsp; 
[Accesschk](#)&emsp;&emsp;&emsp; 
[Procmon](#)&emsp;&emsp;&emsp; 
[Autoruns](#)&emsp;&emsp;&emsp; 
[WinPEAS](#)&emsp;&emsp;&emsp; 
[Windows Exploit Suggester](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp;<br /><br />

2. **Insecure File Permissions**: Check for files with insecure permissions.
<br />[icacls](#)&emsp;&emsp;&emsp; 
[Accesschk](#)&emsp;&emsp;&emsp; 
[WinPEAS](#)&emsp;&emsp;&emsp; 
[Sysinternals](#)&emsp;&emsp;&emsp; 
[PowerShell](#)&emsp;&emsp;&emsp; 
[Windows Exploit Suggester](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Dirbuster](#)&emsp;&emsp;&emsp;<br /><br />

3. **Local Privilege Escalation Vulnerabilities**: Look for known local privilege escalation vulnerabilities.
<br />[WinPEAS](#)&emsp;&emsp;&emsp; 
[Windows Exploit Suggester](#)&emsp;&emsp;&emsp; 
[PowerShell](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[Exploit-DB](#)&emsp;&emsp;&emsp; 
[CVE Details](#)&emsp;&emsp;&emsp; 
[MSFvenom](#)&emsp;&emsp;&emsp; 
[MSFconsole](#)&emsp;&emsp;&emsp;<br /><br />

4. **Scheduled Tasks**: Check for tasks that can be exploited for privilege escalation.
<br />[schtasks](#)&emsp;&emsp;&emsp; 
[PowerShell](#)&emsp;&emsp;&emsp; 
[Sysinternals](#)&emsp;&emsp;&emsp; 
[WinPEAS](#)&emsp;&emsp;&emsp; 
[Accesschk](#)&emsp;&emsp;&emsp; 
[Task Scheduler](#)&emsp;&emsp;&emsp; 
[Scheduled Tasks Explorer](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp;<br /><br />

5. **Kerberos Ticket Extraction**: Obtain Kerberos tickets to elevate privileges.
<br />[Rubeus](#)&emsp;&emsp;&emsp; 
[Mimikatz](#)&emsp;&emsp;&emsp; 
[PowerView](#)&emsp;&emsp;&emsp; 
[Impacket](#)&emsp;&emsp;&emsp; 
[GetNPUsers](#)&emsp;&emsp;&emsp; 
[Kerberoast](#)&emsp;&emsp;&emsp; 
[Kerbrute](#)&emsp;&emsp;&emsp; 
[BloodHound](#)&emsp;&emsp;&emsp; 
[PowerSploit](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp;<br /><br />

6. **Service Account Misconfigurations**: Identify misconfigured service accounts.
<br />[PowerView](#)&emsp;&emsp;&emsp; 
[BloodHound](#)&emsp;&emsp;&emsp; 
[WinPEAS](#)&emsp;&emsp;&emsp; 
[Nmap](#)&emsp;&emsp;&emsp; 
[Netcat](#)&emsp;&emsp;&emsp; 
[PowerShell](#)&emsp;&emsp;&emsp; 
[Service Account Finder](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[Windows Exploit Suggester](#)&emsp;&emsp;&emsp; 
[Sysinternals](#)&emsp;&emsp;&emsp;<br /><br />

7. **DLL Hijacking**: Exploit DLL hijacking vulnerabilities for privilege escalation.
<br />[DLL Hijacking](#)&emsp;&emsp;&emsp; 
[PowerShell](#)&emsp;&emsp;&emsp; 
[Sysinternals](#)&emsp;&emsp;&emsp; 
[Metasploit](#)&emsp;&emsp;&emsp; 
[WinPEAS](#)&emsp;&emsp;&emsp; 
[Accesschk](#)&emsp;&emsp;&emsp;
