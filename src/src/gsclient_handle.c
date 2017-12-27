#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "httpd.h"
#include <errno.h>
#include <syslog.h>

#include "centralserver.h"
#include "safe.h"
#include "simple_http.h"
#include "wdctl_thread.h"
#include "common.h"

//#include "gstmpconf.h"
#include "debug.h"

#include "mcJSON.h"
#include "gsbasemethod.h"
#include "gsclient_set.h"
#include "gsclient_request.h"
#include "http.h"
#include "httpd.h"
#include "gsclient_handle.h"


typedef struct functions{
    char *method;
    char *(*fct)(cJSON *p);
}functions_t;


/*request */
static functions_t total_methods[]={
	//短信
    {"sms",send_message},
	{"remind_sms_content",set_remind_sms_content},//报警短信
	//程序更新
	{"upgrade_sys",sys_upgrade},
	{"upgrade_ipk",opkg_install_ipk},
	//网络规则
    {"dw_up_speed",dw_up_speed},				//整体速度限制
    {"dw_up_speed_by_ip",dw_up_speed_by_ip},	//ip速度限制
	{"disable_net_except_eotu",disable_net_except_eotu},	//流量有限情况下，只允许路由器访问优途网页
    {"wifi_ap_mode_set",wifi_ap_mode_set},  //ssid:eotu_test;encry:psk;key:123;power:12;
    {"wifi_sta_mode_set",wifi_sta_mode_set},//ssid=eotu_test;encryption=psk2;bssid=14:75:90:E2:77:88;key=guosheng123;
	{"checkinterval",internet_config_int_set},	//心跳周期设置
	{"clienttimeout",internet_config_int_set},	//心跳周期设置
	{"portal",router_config_string_set},	//重定向url设置
	{"scan",iwinfo_wlan0_scan},	//wifi扫描
	{"users_info_online",get_users_info_online},//用户信息
	//启动类功能
    {"boot_sw_restart",wdctl_eotu_restart},
	{"boot_dlna_restart",dlna_restart},
    {"boot_sw_stop",wdctl_eotu_stop},
    {"boot_sys_restart",system_restart},
    {"boot_net_restart",network_restart},
    {"mission",set_mission_code}, //接到任务code后，保存到配置中
	//请求类
    {"eotuwifi_config",get_eotuwifi_config_json},
    {"gps",get_sim_gps_info},
    {"sim",get_sim_info},
    {"sysinfo",get_sys_info},
	{"ver",get_version},
	//黑白名单
    {"global_white",net_whitelist_url_set},
    {"global_black",net_blacklist_url_set},
	{"sync_path",rsync_file},
    {"cmd",get_popen_within_json},
    {"password",set_psswd},
    {"username",set_psswd},
    {"httpdmaxconn",internet_config_int_set},
    {NULL,NULL}

};

char *(*get_total_methods(char *method,functions_t *fct))(cJSON *)
{
    int i=0;
    for(;fct[i].method != NULL;i++){
        if(strcmp(fct[i].method,method) == 0)  return fct[i].fct;
    }
        return NULL;
}

/*request有关的函数处理*/
char  * method_excute(char *method,cJSON *paras_j)
{

    char *(*set_func)(cJSON *);
    set_func = get_total_methods(method,total_methods);
    if(set_func != NULL){
        debug(LOG_DEBUG,"start to run  %s",method);
            return  set_func(paras_j);
    }else{
            return "method NOT FOUND!";
    }
}


/*
*	路由器信息设置和请求数据处理
*/

cJSON * client_set_and_request(cJSON *server_json)
{
	cJSON *res_j,*tmp_j;  
    char *method_id,*method,*res;
        	
	debug(LOG_INFO,"client_set_and_request");
    res_j = cJSON_CreateObject();
    tmp_j = server_json->child;
        
        for(;tmp_j != NULL; tmp_j = tmp_j->next){

            if((method_id = tmp_j->string) == NULL){
            	continue;
            }
            if((method = get_method_name(method_id))== NULL)
            	continue;
            res = method_excute(method,tmp_j);

            if(res)
                cJSON_AddStringToObject(res_j,method_id,res);
            else
                cJSON_AddStringToObject(res_j,method_id,"no response");

        }

	return  res_j;
}




void gsclient_handle_main(cJSON *server_json)
{
	cJSON * set_and_request_main_j =client_set_and_request(server_json);

	char *res = cJSON_Print(set_and_request_main_j);
	debug(LOG_INFO,"测试结果:\n%s\n",res);

}

void eotu_set_handle(httpd * webserver, request *r)
{
    char *data,*dataj_str;
    cJSON *config_j,*config_res_j;

    data = r->readBuf;
    dataj_str= strstr(data,"\r\n\r\n");

    debug(LOG_INFO,"eotu get ==============\r\n%s",r->readBuf);

    if(dataj_str){
    //暂时先简单判断后续携带数据是否超过3个
    if (strlen(dataj_str) >3){
        config_j = cJSON_Parse(dataj_str);
        if (config_j){
            /*路由器设置method set and request*/

            /*设置结果返回给服务器*/
            if((config_res_j = client_set_and_request(config_j)) != NULL){
                char *config_res_str = cJSON_Print(config_res_j);
                send_http_page(r, "/eotu/ response", config_res_str);
                //free(config_res_str);
                }else
                	send_http_page(r, "/eotu/ response", "response NULL");
            }else{
                    send_http_page(r, "/eotu/ response NOTHING", data);
            }
        }
    }
    return ;
}


void boot_handle()
{
	s_config *config = config_get_config();
    if(config->sta_to_commit == 1 || config->ap_to_commit == 1){
        uci_commit("wireless");
    }
    
    switch(config->bootv){
    	case 1:
    		config->bootv =0;
    		wdctl_eotu_restart(NULL);
    		break;
    	case 2:
    		config->bootv =0;
            network_restart(NULL);
            break;
    	case 3:
    		config->bootv =0;
            system_restart(NULL);
            break;
    	default:
    		config->bootv =0;
            break;
    }
    return ;
}



