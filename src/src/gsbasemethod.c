/* vim: set sw=4 ts=4 sts=4 et : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file ping_thread.c
    @brief Periodically checks in with the central auth server so the auth
    server knows the gateway is still up.  Note that this is NOT how the gateway
    detects that the central server is still up.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>

//#include "../config.h"
#include "safe.h"
#include "common.h"

#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "simple_http.h"

#include "conf.h"
#include "gsbf.h"
#include "gsclient_handle.h"
#include "gsclient_request.h"
#include "gsbasemethod.h"
#include "md5.h"

#define WIFI_VERSION_FILE "/etc/eotu/ver_wifi.time"
#define MONITOR_VERSION_FILE "/etc/eotu/ver_monitor.time"
#define DLNA_VERSION_FILE "/etc/eotu/ver_dlna.time"
#define OPENWRT_VERSION_FILE "/etc/eotu/ver_openwrt.time"

/*获取软件版本信息，后续添加固件等等*/
char *get_ver(){

	char *wifi,*monitor,*dlna,*openwrt,*ver=NULL;

	if((wifi = read_file_to_string(WIFI_VERSION_FILE)) !=NULL){
		ver = wifi;
	}
	if((monitor = read_file_to_string(MONITOR_VERSION_FILE)) !=NULL){
		safe_asprintf(&ver,"%s%s",ver,monitor);
	}
	if((dlna = read_file_to_string(MONITOR_VERSION_FILE)) !=NULL){
		safe_asprintf(&ver,"%s%s",ver,dlna);
	}
	if((openwrt = read_file_to_string(OPENWRT_VERSION_FILE)) !=NULL){
		safe_asprintf(&ver,"%s%s",ver,openwrt);
	}
	return "";

}


/*任务数据格式 method-id eg: portal=52*/
char *get_method_name(char *method_id)
{
    char *method = safe_strdup(method_id);
    char *res = method;
    for(;*method !='\0';method++){
        if(*method =='-'){
            *method = '\0';
            break;
        }
    }
    return res;

}



/*
* Populate uptime, memfree and load
*/

unsigned long int get_sys_uptime()
{
    FILE *fh;
    unsigned long int sys_uptime = 0;
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");
        fclose(fh);
    }
    return sys_uptime;
}

unsigned int get_sys_memfree()
{
    FILE *fh;
    unsigned int sys_memfree = 0;
    if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
    }
    return sys_memfree;
}

float get_sys_load()
{
    FILE *fh;
    float sys_load = 0;
    if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");
        fclose(fh);
    }
    return sys_load;
}

cJSON *get_status_j()
{
    cJSON *status_j;
    status_j = cJSON_CreateObject();
    
    cJSON_AddNumberToObject(status_j,"sys_uptime",get_sys_uptime());
    cJSON_AddNumberToObject(status_j,"sys_memfree",get_sys_memfree());
    cJSON_AddNumberToObject(status_j,"sys_load",get_sys_load());
    
    long unsigned int eotuwifi_uptime;
    eotuwifi_uptime = (long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time);
    cJSON_AddNumberToObject(status_j,"eotuwifi_uptime",eotuwifi_uptime); 
    return status_j;

}


char *get_firmware_version()
{
    return "none";
}


//add router 项目
void get_ping_router_info(cJSON *p)
{
	s_config *config = config_get_config();
    set_number_member_to_json(p,"id",config->id);
    set_string_member_to_json(p,"gw_id",config->gw_id);
    set_string_member_to_json(p,"gw_address",config->gw_address);
    set_string_member_to_json(p,"created",config->created);
    set_string_member_to_json(p,"updated",config->updated);
}

void get_ping_key_id_info(cJSON *ping_j)
{
    long tt= get_current_time();


    s_config *config = config_get_config();

    //更新sign值
    config->sign = get_new_sign_by_id_gwid_time(tt);



    if(config->sign !=NULL)
    	cJSON_AddStringToObject(ping_j,"sign",config->sign);
    // if(get_configes("interval","uid") !=NULL)
    //		cJSON_AddStringToObject(ping_j,"uid",get_configes("interval","uid"));
    /*
    if(get_configes("interval","mission") !=NULL)
    	cJSON_AddStringToObject(ping_j,"mission",get_configes("interval","mission"));
	*/

    //if(get_configes("interval","token") !=NULL)
    //	cJSON_AddStringToObject(ping_j,"token",get_configes("interval","token"));
    if(config->id >0 )
    	cJSON_AddNumberToObject(ping_j,"id",config->id);

    config->sign_time=tt;

    cJSON_AddNumberToObject(ping_j,"time",tt);

}

cJSON *get_sms_ping_j()
{
    cJSON *ping_j;
    ping_j = cJSON_CreateObject();

    cJSON_AddNumberToObject(ping_j,"id",config_get_config()->id);
    cJSON_AddStringToObject(ping_j,"status","ok");

    return ping_j;
}

/*创建新进程运行cmd*/
char * command_run_thread(char *cmd)
{
    pthread_t tid;
	if(NULL == cmd)
		return "para is NULL, ERROR!";
	int result = pthread_create(&tid, NULL, (void *)excute_cmd, cmd);
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create a new thread (command_run) - exiting");
		return "Failed to create a new thread";
	}
	pthread_detach(tid);
	return "new thread to run";

}






int save_time_to_config_j(cJSON *config_j,char *member,char *string){
	if(NULL != cJSON_GetObjectItem(config_j,member))
		cJSON_GetObjectItem(config_j,member)->valuestring = string;
	else
		cJSON_AddStringToObject(config_j,member,current_time());
	return 0;
}



char *get_dongle_imei()
{
	return get_popen_str("uqmi -d /dev/cdc-wdm0 --get-imei");
}

char *get_nano_second()
{
	struct timeval tv;
	char *res;
	gettimeofday(&tv,NULL);

	safe_asprintf(&res,"%d%d",tv.tv_sec,tv.tv_usec);
	return res;
}

char *get_http_res(int sockfd,char *request )
{

	char *res;

#ifdef USE_CYASSL
    if (config->auth_server->authserv_use_ssl) {
        res = https_get(sockfd, request, config->auth_server->authserv_hostname));
    } else {
        res = http_get(sockfd, request);
    }
#endif
#ifndef USE_CYASSL
    res = http_get(sockfd, request);
#endif
    return res;
}

char *get_new_sign_by_id_gwid_time(long time)
{
    char *tmp_str = malloc(1024);
    s_config *config = config_get_config();

    sprintf(tmp_str,"%s%s%ld",config->gw_id,config->key,time);

    unsigned char decrypt[16];
     MD5_CTX md5;
     MD5Init(&md5);
     MD5Update(&md5,(unsigned char *)tmp_str,strlen(tmp_str));
     MD5Final(&md5,decrypt);
     int i =0;

     // config->sig 在初始化时，已经malloc
//     if(config->sign == NULL)
//    	 config->sign = (char *)malloc(33);

     for(;i<16;i++)
         sprintf(&config->sign[2*i],"%02x",decrypt[i]);
     config->sign[32]='\0';
     //debug(LOG_INFO,"r\n\r\n加密前:%s\n加密后:%s\r\n\r\n",tmp_str,mdres);
     free(tmp_str);
     return config->sign;
}

char *get_string_md5(char *str){

    unsigned char *tmp_str;
    tmp_str = (unsigned char *)str;
    unsigned char decrypt[16];
     MD5_CTX md5;
     MD5Init(&md5);
     MD5Update(&md5,tmp_str,strlen((char *)tmp_str));
     MD5Final(&md5,decrypt);
     char *mdres=malloc(33);
     sprintf(mdres,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
         	decrypt[0],decrypt[1],decrypt[2],decrypt[3],decrypt[4],decrypt[5],decrypt[6],
         	decrypt[7],decrypt[8],decrypt[9],decrypt[10],decrypt[11],decrypt[12],decrypt[13],
         	decrypt[14],decrypt[15]
         	);
     //printf("string:%s encrypt to :%s\r\n",tmp_str,mdres);
     return mdres;
}






//获取文件清单
cJSON *get_document_dir(char * path)
{
	DIR *d;
	struct stat s;
	struct dirent *e;
	char *tmppath;

	cJSON *dir_j = cJSON_CreateObject();

	if (stat(path, &s))
		return NULL;

	if (!(d = opendir(path)))
		return NULL;



	while ((e = readdir(d)) != NULL) {
		safe_asprintf(&tmppath, "%s%s",path, e->d_name);
		if (stat(tmppath, &s) >= 0 && strcmp(e->d_name,".") !=0  && strcmp(e->d_name,"..") !=0){
			cJSON *tmp_j = cJSON_CreateObject();
			cJSON_AddNumberToObject(tmp_j,"size",(double)s.st_size);
			cJSON_AddNumberToObject(tmp_j,"mtime",(double)s.st_mtim.tv_sec);
			cJSON_AddNumberToObject(tmp_j,"type",e->d_type);
			cJSON_AddItemToObject(dir_j,e->d_name,tmp_j);
		}
		//closedir(d);

	}

	debug(LOG_DEBUG,"%s",cJSON_Print(dir_j));

	closedir(d);
	return dir_j;
}

char *uci_commit(char *config)
{
	char *cmd;
	safe_asprintf(&cmd,"uci commit %s",config);
	debug(LOG_NOTICE,"%s",cmd);
	if(excute_cmd(cmd) == 0){
            return "OK";
        }else
            return "FAIL";   
}


/**/
int wifi_ap_member_set(char *member,char *value)
{
	char *cmd;
	safe_asprintf(&cmd,"uci set wireless.apmode.%s=%s",member,value);
	debug(LOG_NOTICE,"%s",cmd);
	if(excute_cmd(cmd) == 0){
		config_get_config()->ap_to_commit =1;
		config_get_config()->bootv =2;
        return 0;
    }else
        return -1;
}

/**/
int wifi_sta_member_set(char *member,char *value)
{
	char *cmd;
	safe_asprintf(&cmd,"uci set wireless.stamode.%s=%s",member,value);
	debug(LOG_NOTICE,"%s",cmd);
        
	if(excute_cmd(cmd) == 0){
		config_get_config()->ap_to_commit =1;
		config_get_config()->bootv =2;
        return 0;
    }else
        return -1;
}



/*更新固件*/
char * upgrade_firmware(cJSON *p)
{
	if(p->valuestring==NULL)
		return "para is NULl,ERROR!";
	char *cmd;
	int rc;


	/*复制到/tmp文件夹下*/
	safe_asprintf(&cmd,"cp %s /tmp/cc.bin",p->valuestring);
	debug(LOG_NOTICE,"%s",cmd);

	rc = excute_cmd(cmd);
	if(rc != 0)
		return "firmware copy to tmp error!";

	if(get_file_size(p->valuestring) !=get_file_size("/tmp/cc.bin")){
		debug(LOG_NOTICE,"compare %s with /tmp/cc.bin error!",p->valuestring);
		return "copy file to /tmp/cc.bin error!";
	}


	//判断固件是否合法
	safe_asprintf(&cmd,"sysupgrade -T /tmp/cc.bin");
	debug(LOG_NOTICE,"%s",cmd);

	rc = excute_cmd(cmd);
	if(rc != 0)
		return "firmware is illeggle";


	/*杀死必要进程
	debug(LOG_NOTICE,"killall dropbear uhttpd");
	rc = excute_cmd("killall dropbear uhttpd");
	if(rc != 0)
		return "killall dropbear uhttpd Fail";

	*/
	//开始升级
	debug(LOG_NOTICE,"Attention ,start to upgrade now!!!!!!!---------------------------------------");

	safe_asprintf(&cmd,"sysupgrade -d 30 -v /tmp/cc.bin");
	//rc = excute_cmd(cmd);
	rc = system(cmd);
	debug(LOG_NOTICE,"cmd[sysupgrade -d 30 -v /tmp/cc.bin] result [%d]",rc);
	if(rc != 0){
		return "please check ver after serial minutes";
	}
	return "OK";

}

