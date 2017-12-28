#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <wait.h>
#include <sys/types.h>
#include <string.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <sys/time.h>

#include "client_list.h"
#include "mcJSON.h"
#include "gsbf.h"
#include "safe.h"
//#include "gstmpconf.h"
#include "gsbasemethod.h"
#include "debug.h"
#include "gs_sms.h"


//重新返回
char *set_mission_code(cJSON *p){
    if(NULL == p->valuestring)
        return "EMPTY PARA";
    
    config_get_config()->mission = p->valuestring;

    return p->valuestring;
}

//获取注册的运营商信息，可能可以获取到本机手机号
char *get_sim_info(cJSON *p){
    char *res ;
    char *provider = dosms("AT+COPS=?");
    char *num = dosms("AT+CNUM");

    safe_asprintf(&res,"provider:%s;num:%s",provider,num);
    return cmd_popen_return_string(res);
}

/*获取路由器基本信息*/
char *get_version(cJSON *p){
    return get_ver();
}


/*获取路由器基本信息*/
char *get_sys_info(cJSON *p){

	//char *info= safe_malloc(2048);
	char *info;

	safe_asprintf(&info,"system:%s\r\ncpu:%s\r\nmem:%s",
			cmd_popen_return_string("uname -a"),
			cmd_popen_return_string("cat /proc/cpuinfo"),
			cmd_popen_return_string("cat /proc/meminfo  |grep Mem"));

    return info;
}

/*获取用户ip清单*/
cJSON *get_client_list(cJSON *p)
{
	cJSON *client_j = cJSON_CreateObject();
    cJSON *tmp_j;

    t_client *ptr;
    ptr = client_get_first_client();

    while (NULL != ptr) {
        cJSON_AddItemToObject(client_j,ptr->ip,tmp_j = cJSON_CreateObject());
        cJSON_AddStringToObject(tmp_j,"mac",ptr->mac);
        cJSON_AddStringToObject(tmp_j,"token",ptr->token);
        cJSON_AddStringToObject(tmp_j,"uid",ptr->uid);
        cJSON_AddNumberToObject(tmp_j,"incoming",ptr->counters.incoming);
        cJSON_AddNumberToObject(tmp_j,"incoming_history",ptr->counters.incoming_history);
        cJSON_AddNumberToObject(tmp_j,"outgoing",ptr->counters.outgoing);
        cJSON_AddNumberToObject(tmp_j,"outgoing_history",ptr->counters.outgoing_history);
        ptr = ptr->next;
    }

    return client_j;

}


// 获取IP信息清单
char *get_users_info_online(cJSON *p)
{
    return cJSON_Print(get_client_list(p));
}

char *get_sim_gps_info(cJSON *p){
	return "ongoing";
}

char * get_asset_info(cJSON *p)
{

	return "ongoing";
}

char * get_eotuwifi_config_json(cJSON *p)
{
	char *cmd,*res;

	save_config_json_to_file(WIFIDOG_JSON_NEW);

	safe_asprintf(&cmd,"cat " WIFIDOG_JSON_NEW);
	res = cmd_popen_return_string(cmd);
	free(cmd);
	return res;

}

char *cmp_time(cJSON *p)
{
	cJSON *tj;
	int i=0;
	char *r;
	char *gettime;
	float tt;
	long ll;
    struct  timeval    tv;

    gettimeofday(&tv,NULL);
    r =NULL;
    tt =  tv.tv_usec/1000000;
    ll = tv.tv_sec;

	while(NULL != (tj = cJSON_GetArrayItem(p,i))){
		if(tj->valuestring !=NULL){
			gettime = safe_strdup(tj->valuestring);
			char tok[10];
			int i=0;
			for (;gettime[i] != 0x20 && (tok[i] = gettime[i]);i++);
			tok[i]='\0';
			safe_asprintf(&r,"get time %s  now time %f %l",gettime,tt,ll);
		}
		i++;
	}

	return r;

}


/*扫描周边wifi热点*/
char * iwinfo_wlan0_scan(cJSON *p)
{
	//except iwinfo wlan0 scan
	char *res;

	res = cmd_popen_return_string("iwinfo wlan0 scan");
	return res;
}

char * get_popen_within_json(cJSON *p){
    
    if(p->valuestring)
        return  cmd_popen_return_string(p->valuestring);
    else
        return "para NULL";
}


char * sys_upgrade(cJSON *p)
{
	//此函数纺织client_set里面

	if(p == NULL)
		return "Para is NULL";

	char *r = upgrade_firmware(p);
	//if(strcmp(r,"OK"))
	//	set_confige("interval","bootv",0,3,NULL);
	return r;

}
