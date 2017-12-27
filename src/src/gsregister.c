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

#include "gstmpconf.h"
#include "gsbf.h"
#include "gsclient_handle.h"
#include "gsclient_request.h"
#include "mcJSON.h"
#include "gsbasemethod.h"
#include "md5.h"

static int authdown = 0;

/*************************************************
 * 注册后 ，服务器将返回数据， 赋值到对应config中
 * */
static int save_register_to_config(char *str);
static int get_register(int sockfd);
//is_register 为判断依据
static int register_judge();
static char *coin_register();

//注册前重新sock连接
static int  register_handle();


char *coin_register()
{
    cJSON *ping_j;
    char *ping_string;
    char *request;
    
    ping_j = cJSON_CreateObject();

    s_config *config = config_get_config();

    //cJSON_AddStringToObject(ping_j,"sign", sign);
    cJSON_AddStringToObject(ping_j,"ver", get_ver());
    cJSON_AddNumberToObject(ping_j,"id", config->id);
    cJSON_AddStringToObject(ping_j,"serialnumber", config->serialnumber);
    cJSON_AddStringToObject(ping_j,"mac", config->mac);
    cJSON_AddItemToObject(ping_j,"status",get_status_j());
    cJSON_AddItemToObject(ping_j,"user_info",get_client_list(NULL));

    ping_string = safe_strdup(cJSON_Print(ping_j));
    cJSON_Delete(ping_j);

    safe_asprintf(&request,
             "POST %s%s HTTP/1.0\r\n"
             "Host: %s\r\n"
             "User-Agent: EOTU/%s\r\n"
             "Content-Type: application/json\r\n"
             "content-length:%d\r\n\r\n"
             "%s\r\n",
             config->auth_servers->authserv_path,config->auth_servers->eotu_register,
			 config->auth_servers->authserv_hostname,
             VERSION,strlen(ping_string),
             ping_string);
    
    return request;
}

/*************************************************
 * 注册后 ，服务器将返回数据， 赋值到对应config中
 * */
int save_register_to_config(char *str)
{
    cJSON *server_reg;
    server_reg = cJSON_Parse(str);
    s_config *config = config_get_config();
    
    if(NULL == server_reg){
    	debug(LOG_ERR,"register string Parse Json ERROR!");
    	return -1;
    }
    cJSON *router_j,*set_j;
    set_j = cJSON_GetObjectItem(server_reg,"set");
    if(NULL == set_j){
    	debug(LOG_ERR,"get set json error");
    	return -1;
    }
    router_j = cJSON_GetObjectItem(set_j,"router");
    if(NULL == router_j){
    	debug(LOG_ERR,"register string Parse Json router part ERROR!");
    	return -1;
    }


    config->id = get_number_from_json_by_member(router_j,"id");
    config->key = get_string_from_json_by_member(router_j,"key");
    config->updated =current_time();


    //gsconfig->router->updated = get_string_from_json_by_member(router_j,"updated");
    debug(LOG_INFO,"register update time is %d", config->updated);
    config->is_register = 1;
    debug(LOG_NOTICE,"get register : id %d key %s ",config->id,config->key);


    return 0;
}


int get_register(int sockfd)
{
	char *res,*request;
	request = coin_register();
	res = get_http_res(sockfd,request);

	debug(LOG_DEBUG, "get_register server response:===================================\r\n [%s]",res);

    char *status_line;
    if (NULL == res) {
        debug(LOG_ERR, "There was a problem pinging the auth server!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
            //config_get_gsconfig_struct()->auth_down_qty = config_get_gsconfig_struct()->auth_down_qty +1;
            return -1;
        }
    } else{
        status_line = strsep(&res,"\r\n");
        if(strstr(status_line,"200") >0 ){
            debug(LOG_DEBUG, "Auth Server connect, and give set json data");
            char *dataj_str ;
            dataj_str = strstr(res,"\r\n\r\n");
            return save_register_to_config(dataj_str);
       }
    }
    return -1;
}

//注册前重新sock连接
int  register_handle()
{
    int sockfd;
    /***
     * eotu own
     * ping server ,and set auth_server online , the old apfree_wifidog set at thread_ping
     * **/
    sockfd = connect_auth_server();
    if (sockfd == -1) {
    	debug(LOG_ERR, "connect auth server error , break");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
        return -1;
    }
    return get_register(sockfd);

}


//is_register 为判断依据
int register_judge()
{
	if(config_get_config()->is_register == 0)
		return register_handle();
	else
		return 0;
}

//注册后 开始 主程序;
void register_loop()
{

    while(1) {
        if(register_judge() == 0)
        	break;
        debug(LOG_NOTICE,"will register 120 seconds later");
        sleep(120);
    }
}


