/*
 *  comgt version 0.31 - 3G/GPRS datacard management utility
 *
 *  Copyright (C) 2003  Paul Hardwick <paul@peck.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  See comgt.doc for more configuration and usage information.
 *
 */

 /***************************************************************************
* $Id: comgt.c,v 1.4 2006/10/20 14:30:19 pharscape Exp $
 ****************************************************************************/


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <syslog.h>

#include "debug.h"
#include "gspdu.h"
#include "safe.h"
#include "gs_sms.h"
#include "mcJSON.h"
#include "gstmpconf.h"

#define GTDEVICE "/dev/modem"

char device[1024]; /* Comm device.  May be "-" */
int ignorecase=1;  /* no case sensitivity */
int comfd=0; /* Communication file descriptor.  Defaults to stdin. */
#define BOOL unsigned char
BOOL comecho=0; /* echo what's comin' in */
BOOL high_speed=0;
long senddelay=0; /* 0/100th second character delay for sending */
char cspeed[10];  /* Ascii representation of baudrate */
int speed=B0; /* Set to B110, B150, B300,..., B38400 */
BOOL verbose=0; /* Log actions */
struct termios cons, stbuf, svbuf;  /* termios: svbuf=before, stbuf=while */
int clocal=0;
int parity=0, bits=CS8, stopbits=0;
unsigned long hstart,hset;
BOOL lastcharnl=1; /* Indicate that last char printed from getonebyte
                               was a nl, so no new one is needed */
BOOL tty=1;


//"open com \"/dev/modem\"\nset com 38400n81\nset senddelay 0.05\nsend \"ATi^m\"\nget 2 \" ^m\" $s\nprint \"Response : \",$s,\"\\n\"\nget 2 \" ^m\" $s\nprint \"Response :\",$s,\"\\n\"\nget 2 \" ^m\" $s\nprint \"Response : \",$s,\"\\n\"\n\n";
/* Prototypes. */
unsigned long htime(void);
void dormir(unsigned long microsecs);
void ext(long xtc);
int getonebyte(void);
void setcom(void);

char GTdevice[4][20] = {"/dev/noz2",
                        "/dev/ttyUSB3",
                        "/dev/modem",""}; /* default device names to search for */

/* Returns hundreds of seconds */
unsigned long htime(void) {
  struct timeval timenow;
  gettimeofday(&timenow,NULL);
  return(100L*(timenow.tv_sec-hstart)+(timenow.tv_usec)/10000L-hset);
}

/* I use select() 'cause CX/UX 6.2 doesn't have usleep().
   On Linux, usleep() uses select() anyway.
*/
void dormir(unsigned long microsecs) {
  struct timeval timeout;
  timeout.tv_sec=microsecs/1000000L;
  timeout.tv_usec=microsecs-(timeout.tv_sec*1000000L);
  select(1,0,0,0,&timeout);
}


/* Exit after resetting terminal settings */
void ext(long xtc) {
  ioctl(1, TCSETS, &cons);
  //exit(xtc);
}



/* Write a null-terminated string to communication device */
void writesmscom(char *text) {
  int res;
  unsigned int a;
  char ch;

  int inch;
 debug(LOG_DEBUG,"\r\nwrite AT COMMAND :\r\n[%s]\r\nwrite process:[",text);
  for(a=0;a<strlen(text);a++) {
    ch=text[a];
    if(ch == 0x1a){
    	inch =26;

    	res=write(comfd,&inch,1);
        if(senddelay) dormir(senddelay);
        if(res!=1) {
        	debug(LOG_ERR,"Could not write to COM device [%c]\r\n",ch);
        }
        debug(LOG_DEBUG,"\r\nwrite over\r\n");
    	return ;
    }
    inch = (int)ch;
    //printf("%c",ch);
    res=write(comfd,&inch,1);
    if(senddelay) dormir(senddelay);
    if(res!=1) {
    	debug(LOG_ERR,"\r\nCould not write to COM device [%c]\r\n",ch);
    }
  }

  if(senddelay) dormir(senddelay);
  debug(LOG_DEBUG,"]\r\nwrite over\r\n");

  return ;

}


/* Gets a single byte from comm. device.  Return -1 if none avail. */
int getonebyte(void) {
  fd_set rfds;
  int res;
  char ch;
  comecho = 1;
  struct timeval timeout;
  timeout.tv_sec=0L;
  timeout.tv_usec=10000;
  FD_ZERO(&rfds);
  FD_SET(comfd, &rfds);
  res=select(comfd+1,&rfds,NULL,NULL,&timeout);
  if(res) {
    res=read(comfd,&ch,1);
    if(res==1) {
      if(comecho) {
        if(ch=='\n')
        	lastcharnl=1;
        else {
          if(ch!='\r')
        	  lastcharnl=0;
        }
        /*fputc(ch,stderr);*/
      }
      return(ch);
    }
  }
  else {
    return(-1); /* Nada. */
  }
  return(0);
}


void setcom(void) {
  stbuf.c_cflag &= ~(CBAUD | CSIZE | CSTOPB | CLOCAL | PARENB);
  stbuf.c_cflag |= (speed | bits | CREAD | clocal | parity | stopbits );
  if (tty && ioctl(comfd, TCSETS, &stbuf) < 0) {
     debug(LOG_ERR,"Can't ioctl set device");
    ext(1);
  }
}
void dosmsopen(char *usbport) {
	strcpy(device,usbport);
	if ((comfd = open(device, O_RDWR|O_EXCL|O_NONBLOCK|O_NOCTTY)) <0) { //O_NONBLOCK|O_NOCTTY)) <0) {//
		debug(LOG_ERR,"Can't open device %s.\n",device);
		config_get_config()->is_sms_work = 0;
        return ;
    }
    if (isatty (comfd))
      tty=1;
    else
      tty=0;
    if (tty && ioctl (comfd, TCGETS, &svbuf) < 0) {
    	 debug(LOG_ERR,"Can't ioctl get device %s.\n",device);

    	 config_get_config()->is_sms_work = 0;
     	 return ;
    }
    if (tty)
      ioctl(comfd, TCGETS, &stbuf);
    speed=stbuf.c_cflag & CBAUD;
    strcpy(cspeed,"115200");

    bits=stbuf.c_cflag & CSIZE;
    clocal=stbuf.c_cflag & CLOCAL;
    stopbits=stbuf.c_cflag & CSTOPB;
    parity=stbuf.c_cflag & (PARENB | PARODD);
    stbuf.c_iflag &= ~(IGNCR | ICRNL | IUCLC | INPCK | IXON | IXANY | IGNPAR );
    stbuf.c_oflag &= ~(OPOST | OLCUC | OCRNL | ONLCR | ONLRET);
    stbuf.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHONL);
    stbuf.c_lflag &= ~(ECHO | ECHOE);
    stbuf.c_cc[VMIN] = 1;
    stbuf.c_cc[VTIME] = 0;
    stbuf.c_cc[VEOF] = 1;
    setcom();
    dormir(200000); /* Wait a bit (DTR raise) */
    debug(LOG_DEBUG,"Opened %s as FD %d",device,comfd);

}

//获取AT默认值中的短信中心号码smsc
char *get_atsmsc(char *str)
{
	char *sep;
	if(!str)
		return NULL;
	strsep(&str,"\"");

	if(str)
		sep=strsep(&str,"\"");
	else
		return NULL;

	if(sep)
		return strdup(sep);
	else
		return NULL;
}

char * imei_dump(char *str){

	char *token;
	if(str == NULL)
		return NULL;
	token = malloc(strlen(str));
	memset(token,0,strlen(str));
	int i = 0;
	for(;*str !='\0';str++){
		if(*str >= '0' && *str <= '9'){
			token[i] =*str;
			i++;
		}else if(i>0){
			break;
		}
	}
	token = realloc(token,strlen(token)+1);
	return token;
}


//设置IMEI为本路由器SN
int set_atimei()
{
	char *token;
	char *str;
	s_config *config = config_get_config();

	str = safe_strdup(dosms("AT+GSN"));
	debug(LOG_INFO,"set_atimei==str==%s===",str);
	if(!str)
		return -1;

	token = imei_dump(str);

	debug(LOG_INFO,"set_atimei==token==%s===",token);
	if(token){
		if(strcmp(config->serialnumber,token) !=0 && token !=NULL ){
			debug(LOG_NOTICE,"SerialNumber config chang [%s] to IMEI [%s]",config->serialnumber,token);

			config->serialnumber = token;
		}
		debug(LOG_NOTICE,"IMEI IS  [%s]",token);
		free(str);
		return 0;
	}else
		return -1;

}



//设置IMEI为本路由器SN
int check_cpin()
{

	char *str=NULL;
	str = safe_strdup(dosms("AT+CPIN?"));

	if(str == NULL){
		debug(LOG_ERR,"=======check cpin response NULL");
		return -1;
	}
	debug(LOG_DEBUG,"=======check cpin response [%s]",str);
	if(strstr(str,"ready")){
		config_get_config()->is_sms_work = 1;
		free(str);
		return 0;
	}else{

		config_get_config()->is_sms_work = 0;
		config_get_config()->sms_err_info = str;
		return -1;
	}
}



//AT指令初始化，并获得SMSC
void atcommand_init()
{
	//初始化，
	char *initcmd,*smsc;
	safe_asprintf(&initcmd,"%c%c%c",0x1a,0x0a,0x0d);

	//用结束符把可能的阻塞去掉
	writesmscom(initcmd);

	debug(LOG_DEBUG," sms init ~~~~~~~~~~~~~");

	//没有检测到卡，直接退出
	int i=0 ;
	int flg = 0;
	for(;i<2;i++){
		printf("repeat check cpin if OK?\r\n");
		if(check_cpin() == 0){
			flg = 1;
			break;
		}
		sleep(1);
	}
	if(flg == 0)
		return ;

	//出厂初始化
	dosms("AT&F");

	smsc = get_atsmsc(dosms("AT+CSCA?"));
	dosms("ATE1");
	dosms("AT+CSCS=\"UCS2\"");
	dosms("AT+CMGF=0");
	if(smsc){
		if(strlen(smsc)==12){
			config_get_config()->smsc = smsc;
		}
		else
			debug(LOG_DEBUG,"\r\n sms length[%d] is error!\r\n",strlen(smsc));
	}
	set_atimei();


	return ;
}

/*****
 * XXX 初始化串口，并设置ＩＭＥＩ
 *
 * *****/


int sms_init(char *usbport)
{
	hstart=time(0);
	hset=htime();
	ioctl(1, TCGETS, &cons);

	comecho=1; //Verbose output enabled
	char *devenv;
	//Load up the COMGT device env variable if it exists
	devenv = getenv("COMGTDEVICE");
	if (devenv != NULL && strlen(devenv)){
		strcpy(device,devenv);
	}else
		strcpy(device,"-");
	dosmsopen(usbport);
	if(comfd >0)
		//AT指令初始化，含ＩＭＥＩ设置
		atcommand_init();
	else
		return -1;
	return 0;
}


char * smsreturn_expect(char *expect) {

  char buffer[128];

  char *res;

  res = safe_malloc(1024);

  if(config_get_config()->is_sms_work==0)
	  return "sms not work";

  int i=0;
  unsigned long timeout;
  unsigned int a;
  int c;
  buffer[127]='\0';
  //timeout=htime()+getdvalue();
  timeout=htime()+500;
  a=0;
 debug(LOG_DEBUG,"read back:(EXPECT %s)\r\n[",expect);
  while(htime()<timeout) {
	    c=getonebyte();
	    //printf("%v",c);
	    if(c!= -1) {
	      if(ignorecase) {
	        if(c>='A' && c<='Z') c=c-'A'+'a';
	      }
	      //printf("%c",c);
	      res[i]=c;
	      i++;
	      res[i]='\0';
	      for(a=0;a<127;a++) buffer[a]=buffer[a+1]; //shuffle down
	      buffer[126]=c;
	      c=strlen(expect);
	      if (strstr(&buffer[127-c],expect) > 0){
	    	 debug(LOG_DEBUG,"]\r\nGET EXPECT [%s]\r\n",&buffer[127-c]);
	    	  return res;
	      }
	    }
  }
  res[1023]='\0';
  if(!res)
	  res = "read timeout";
  debug(LOG_DEBUG,"%s]\r\n-----OVER---------\r\n",res);
  return res;

}


char *getsmscmd(char *atcmd)
{
	char *cmd=strdup(atcmd);
	char *tmp = cmd;
	while(*cmd){
		if(*cmd=='^'){
			*cmd=0x1A;
			cmd++;
			*cmd='\0';
			return tmp;
		}
		if(*cmd=='*'){
			*cmd=0x0A;
			cmd++;
			*cmd='\0';
			return tmp;
		}
		if(*cmd=='!'){
			*cmd=0x0D;
			cmd++;
			*cmd='\0';
			return tmp;
		}
		cmd++;
	}
	safe_asprintf(&tmp,"%s\r\n",tmp);
	return tmp;
}

char *getexpect(char *cmd)
{
	if(strstr(cmd,"CMGS") > 0 || strstr(cmd,"cmgs") > 0)
		return ">";
	else
		return "ok";
}

char * dosms(char *atcmd)
{
	char *res,*cmd,*expect;

	cmd = getsmscmd(atcmd);
	expect = getexpect(cmd);
	senddelay = 1000;

	//写入
	writesmscom(cmd);
	//读取
	res = smsreturn_expect(expect);

	if(!res)
		res = "no response";
	return res;

}

char * sms_tool(char *smsc,char *phone,char *message)
{

	debug(LOG_NOTICE,"send message %s %s",phone,message);

	char *res;
	if(strlen(message) >100){
		debug(LOG_ERR,"message too long %d",strlen(message));
		return "message too long";
	}
	char *cmgscmd;
	char * pdustr,*pducmd;
	int pdu_len;

	//获取PDU编码
	pdustr = pdu_encode(smsc, phone, message, 256);
	pdu_len = strlen(pdustr);
	const int pdu_len_except_smsc = (pdu_len - 19)/2+1;

	//AT+CMGS= 长度
	safe_asprintf(&cmgscmd,"AT+CMGS=%d!\r\n", pdu_len_except_smsc);
	res = dosms(cmgscmd);
	if(!strstr(res,">"))
		return res;
	//> [输入内容]
	safe_asprintf(&pducmd,"%s^\r\n",pdustr);
	res = dosms(pducmd);
	if(strstr(res,"+cmgs:") >0)
		res = "OK";
	else if(strstr(res,"+cms") >0)
		res=strstr(res,"+cms");

	return res;

}

void sms_port_close()
{
	close(comfd);
}
