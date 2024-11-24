IP:10.10.11.35

```bash
❯ nmap 10.10.11.35
PORT     STATE SERVICE
53/tcp   open  domain - DNS # not useful
88/tcp   open  kerberos-sec - Authentication # probably not useful
135/tcp  open  msrpc - Microsoft RPC # could be useful
139/tcp  open  netbios-ssn - NetBIOS Session Service
389/tcp  open  ldap - Light weight directory access protocol # probalky not useful
445/tcp  open  microsoft-ds - Microsoft Windows file sharing # protocol used by SMB over IP
593/tcp  open  http-rpc-epmap - Reverse proxy for RPC
636/tcp  open  ldapssl - Light weight directory access protocol
3268/tcp open  globalcatLDAP -  #possible not useful
3269/tcp open  globalcatLDAPssl #possible not useful
5985/tcp open  wsman - Web Services for Management
```

```bash
❯ sudo nmap -sV --version-intensity 5 10.10.11.35
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-23 17:40 MST
Nmap scan report for 10.10.11.35
Host is up (0.060s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-24 07:41:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.74 seconds
```

see if this LDAP server is vulnerable to a NULL base or anonymous bind. We will search for all Distinguished Names (DN) in the tree.

```
ldapsearch -x -b "dc=acme,dc=com" "*" -h 10.10.11.35 | awk '/dn: / {print $2}'
```

LDAP server pentesting: https://medium.com/@minimalist.ascent/pentesting-ldap-servers-25577bde675b

Feels like globalcatLDAP and globalcatLDAPssl are most likely the issues.

# HTTP

```bash
❯ gobuster dir -u http://10.10.11.35:5985 -w common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.35:5985
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

# Microsoft DS

https://support.microsoft.com/en-us/topic/ms08-068-vulnerability-in-smb-could-allow-remote-code-execution-cdd08c90-10d4-ca87-68d3-4841472ba1ec

```bash
❯ echo "exit" | smbclient -L 10.10.11.35
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Password for [WORKGROUP\tom]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DEV             Disk
        HR              Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
```

```bash
❯ smbclient -L 10.10.11.35 -N -d 3
lp_load_ex: refreshing parameters
Initialising global parameters
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
added interface en0 ip=2601:282:2280:f8b0::7590 bcast= netmask=ffff:ffff:ffff:ffff::
added interface en0 ip=2601:282:2280:f8b0:49f:e030:249a:d9e0 bcast= netmask=ffff:ffff:ffff:ffff::
added interface en0 ip=2601:282:2280:f8b0:1417:6714:efcf:7cd1 bcast= netmask=ffff:ffff:ffff:ffff::
added interface en0 ip=10.0.0.120 bcast=10.0.0.255 netmask=255.255.255.0
Client started (version 4.21.1).
Connecting to 10.10.11.35 at port 445
Connecting to 10.10.11.35 at port 139
GENSEC backend 'gssapi_spnego' registered
GENSEC backend 'gssapi_krb5' registered
GENSEC backend 'gssapi_krb5_sasl' registered
GENSEC backend 'spnego' registered
GENSEC backend 'schannel' registered
GENSEC backend 'ncalrpc_as_system' registered
GENSEC backend 'sasl-EXTERNAL' registered
GENSEC backend 'ntlmssp' registered
GENSEC backend 'ntlmssp_resume_ccache' registered
GENSEC backend 'http_basic' registered
GENSEC backend 'http_ntlm' registered
GENSEC backend 'http_negotiate' registered
gensec_gse_client_start: Not using kerberos to cifs/10.10.11.35 as WORKGROUP\tom: NT_STATUS_INVALID_PARAMETER
Got challenge flags:
Got NTLMSSP neg_flags=0x62898215
NTLMSSP: Set final flags:
Got NTLMSSP neg_flags=0x62008215
NTLMSSP Sign/Seal - Initialising with flags:
Got NTLMSSP neg_flags=0x62008215

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DEV             Disk
        HR              Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
```

Version: Client started (version 4.21.1).

```bash
❯ sudo nmap -p445 --script smb-protocols 10.10.11.35
Password:
Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-23 18:56 MST
Nmap scan report for 10.10.11.35
Host is up (0.056s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols:
|   dialects:
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1

Nmap done: 1 IP address (1 host up) scanned in 6.97 seconds
```

http://packetstormsecurity.com/files/157901/Microsoft-Windows-SMBGhost-Remote-Code-Execution.html
http://packetstormsecurity.com/files/158054/SMBleed-SMBGhost-Pre-Authentication-Remote-Code-Execution-Proof-Of-Concept.html

Good Example:
https://github.com/jamf/CVE-2020-0796-RCE-POC/blob/master/SMBleedingGhost.py

That failed looks like it is newer then the CVE.

Trying metasploit recon:
https://exploit.ph/active-directory-recon-1.html

```bash
❯ ldapsearch -x -h 10.10.11.35 -b "dc=cicada,dc=htb"
# extended LDIF
#
# LDAPv3
# base <dc=cicada,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090C78, comment: In order to perform this ope
 ration a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```

```bash
❯ smbcacls //10.10.11.35/HR "Notice from HR.txt" -N
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
REVISION:1
CONTROL:SR|DI|DP
OWNER:BUILTIN\Administrators
GROUP:CICADA\Domain Users
ACL:CICADA\david.orelious:ALLOWED/I/R
ACL:CICADA\sarah.dantelia:ALLOWED/I/R
ACL:Everyone:ALLOWED/I/R
ACL:CICADA\Guest:ALLOWED/I/READ
ACL:NT AUTHORITY\SYSTEM:ALLOWED/I/FULL
ACL:BUILTIN\Administrators:ALLOWED/I/FULL
ACL:BUILTIN\Users:ALLOWED/I/READ
```

```bash
smbclient //10.10.11.35/HR -U "Guest%"
smbclient //10.10.11.35/C$ -N
```

```bash
[+] IP: 10.10.11.35:445 Name: 10.10.11.35               Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS        Remote Admin
        C$                                                      NO ACCESS        Default share
        DEV                                                     NO ACCESS
        HR                                                      READ ONLY
        IPC$                                                    READ ONLY        Remote IPC
        NETLOGON                                                NO ACCESS        Logon server share
        SYSVOL                                                  NO ACCESS        Logon server share
```
