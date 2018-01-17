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
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "simple_http.h"
#include "wd_util.h"
#include "version.h"
#include "httpd_priv.h"

#include "mcJSON.h"
#include "gsclient_handle.h"

#include "gsbf.h"
#include "gsclient_handle.h"
#include "gsclient_request.h"
#include "gsbasemethod.h"

static void ping(void);
static void evpings(struct evhttps_request_context *context);
static void ping_handle(char *res);


/******
 * 组合要发送的Ping response 数据
 * ******/
char *coin_ping_response(char *reponse)
{
    char *request;
    s_config *config = config_get_config();

    //auth_server->authserv_ping_script_path_fragment,
    safe_asprintf(&request,
             "POST %s%s HTTP/1.0\r\n"
             "User-Agent: EOTU %s\r\n"
             "Content-Type:application/json\r\n"
             "Host: %s\r\n"
             "content-length:%d\r\n\r\n"
             "%s",
			 config->auth_servers->authserv_path,
			 config->auth_servers->eotu_response,
            VERSION,config->auth_servers->authserv_hostname,
            strlen(reponse),reponse);

    return request;
}


/******
 * 组合要发送的Ping数据
 * ******/

char *coin_ping()
{
    char *id;
    char *sign;
    char *key;
    char *extra_string;
    char *request;
    float sys_load = 0;
    char *status_line;
    cJSON *ping_key_id_j;

    s_config *config = config_get_config();

    ping_key_id_j = cJSON_CreateObject();
    get_ping_key_id_info(ping_key_id_j);

    cJSON_AddItemToObject(ping_key_id_j,"user_info",get_client_list(NULL));
    cJSON_AddItemToObject(ping_key_id_j,"status",get_status_j());

//    //add router 项目
//    cJSON *router_jj = cJSON_CreateObject();
//    get_ping_router_info(router_jj);
//    cJSON_AddItemToObject(ping_key_id_j,"router",router_jj);

    extra_string = cJSON_Print(ping_key_id_j);
    cJSON_Delete(ping_key_id_j);
    request = malloc(1024+strlen(extra_string));

    sprintf(request,
             "POST %s%s HTTP/1.0\r\n"
             "User-Agent: EOTU %s\r\n"
             "Content-Type:application/json\r\n"
             "Host: %s\r\n"
             "content-length:%d\r\n\r\n"
             "%s",
			 config->auth_servers->authserv_path,
			 config->auth_servers->authserv_ping_script_path_fragment,
             VERSION,
			 config->auth_servers->authserv_hostname,strlen(extra_string),
             extra_string);

    free(extra_string);
    return request;
}








/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_ping(void *arg)
{
	return ;

    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
	t_auth_serv *auth_server = get_auth_server();
	struct evhttps_request_context *context = NULL;
	
	//>>> liudf added 20160411
	// move from fw_init to here	
	fw_set_pan_domains_trusted();

	fix_weixin_http_dns_ip();

	parse_inner_trusted_domain_list();
	fw_set_inner_domains_trusted();

	parse_user_trusted_domain_list();
    fw_set_user_domains_trusted();

	fw_set_trusted_maclist();
	fw_set_untrusted_maclist();
	
	if (auth_server->authserv_use_ssl) {
		context = evhttps_context_init();
		if (!context) {
			debug(LOG_ERR, "evhttps_context_init failed, process exit()");
			exit(0);
		}
	}

    while (1) {
        /* Make sure we check the servers at the very begining */
        
		if (auth_server->authserv_use_ssl) {
       		debug(LOG_DEBUG, "Running evpings()");
			evpings(context);
		} else {
			debug(LOG_DEBUG, "Running ping()");
			ping();
		}
		
        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }

    if (auth_server->authserv_use_ssl) {
		evhttps_context_exit(context);
	}
}

static long
check_and_get_wifidog_uptime(long sys_uptime)
{
    long wifidog_uptime = time(NULL) - started_time;
    if (wifidog_uptime > sys_uptime) {
        started_time = time(NULL);
        return 0;
    }
    return wifidog_uptime;
}

char *
get_ping_request(const struct sys_info *info)
{
	t_auth_serv *auth_server = get_auth_server();
	char *request = NULL;
	
	if (!info)
		return NULL;
	
	int nret = safe_asprintf(&request,
			"GET %s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&nf_conntrack_count=%lu&cpu_usage=%3.2lf%%25&wifidog_uptime=%lu&online_clients=%d&offline_clients=%d&ssid=%s&version=%s&type=%s&name=%s&channel_path=%s&wired_passed=%d HTTP/1.1\r\n"
             "User-Agent: ApFree WiFiDog %s\r\n"
			 "Connection: keep-alive\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             config_get_config()->gw_id,
             info->sys_uptime,
             info->sys_memfree,
             info->sys_load,
			 info->nf_conntrack_count,
			 info->cpu_usage,
             check_and_get_wifidog_uptime(info->sys_uptime),
			 g_online_clients,
			 offline_client_ageout(),
			 NULL != g_ssid?g_ssid:"NULL",
			 NULL != g_version?g_version:"null",
			 NULL != g_type?g_type:"null",
			 NULL != g_name?g_name:"null",
			 NULL != g_channel_path?g_channel_path:"null",
             config_get_config()->wired_passed,
             VERSION, auth_server->authserv_hostname);
	
	return nret>0?request:NULL;
}

char *
get_ping_uri(const struct sys_info *info)
{
	t_auth_serv *auth_server = get_auth_server();
	char *uri = NULL;
	
	if (!info)
		return NULL;
	
	int nret = safe_asprintf(&uri, 
			"%s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&nf_conntrack_count=%lu&cpu_usage=%3.2lf%%&wifidog_uptime=%lu&online_clients=%d&offline_clients=%d&ssid=%s&version=%s&type=%s&name=%s&channel_path=%s&wired_passed=%d",
			 auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             config_get_config()->gw_id,
             info->sys_uptime,
             info->sys_memfree,
             info->sys_load,
			 info->nf_conntrack_count,
			 info->cpu_usage,
             (long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time),
			 g_online_clients,
			 offline_client_ageout(),
			 NULL != g_ssid?g_ssid:"NULL",
			 NULL != g_version?g_version:"null",
			 NULL != g_type?g_type:"null",
			 NULL != g_name?g_name:"null",
			 NULL != g_channel_path?g_channel_path:"null",
             config_get_config()->wired_passed);
	
	return nret>0?uri:NULL;
}

void
get_sys_info_o(struct sys_info *info)
{
	FILE 	*fh = NULL;
	char	ssid[32] = {0};
	
	if (info == NULL)
		return;
	
	info->cpu_usage = get_cpu_usage();
	
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &info->sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");

        fclose(fh);
		fh = NULL;
    }
	
	if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &info->sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
		fh = NULL;
    }
	
	if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &info->sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
		fh = NULL;
    }
	
	if ((fh = fopen("/proc/sys/net/netfilter/nf_conntrack_count", "r"))) {
        if (fscanf(fh, "%lu", &info->nf_conntrack_count) != 1)
            debug(LOG_CRIT, "Failed to read nf_conntrack_count");

        fclose(fh);
		fh = NULL;
    }
	
	// get first ssid
	if (uci_get_value("wireless", "ssid", ssid, 31)) {
		trim_newline(ssid);
		if(strlen(ssid) > 0) {
			if(g_ssid) 
				free(g_ssid);
			g_ssid = _httpd_escape(ssid);
		}
	}
	
	if(!g_version) {
		char version[32] = {0};
		if (uci_get_value("firmwareinfo", "firmware_version", version, 31)) {			
			trim_newline(version);
			if(strlen(version) > 0)
				g_version = safe_strdup(version);
		}
	}
	
	if(!g_type) {
		if ((fh = fopen("/var/sysinfo/board_type", "r"))) {
			char name[32] = {0};
			fgets(name, 32, fh);
			fclose(fh);
			fh = NULL;
			trim_newline(name);
			if(strlen(name) > 0)
				g_type = safe_strdup(name);
		}
	}
	
	if(!g_name) {
		if ((fh = fopen("/var/sysinfo/board_name", "r"))) {
			char name[32] = {0};
			fgets(name, 32, fh);
			fclose(fh);
			fh = NULL;
			trim_newline(name);
			if(strlen(name) > 0)
				g_name = safe_strdup(name);
		}
	}
	
	if(!g_channel_path) { 
		free(g_channel_path);
		g_channel_path = NULL;
	}

	char channel_path[128] = {0};
	if (uci_get_value("firmwareinfo", "channel_path", channel_path, 127)) {			
		trim_newline(channel_path);	
		if(strlen(channel_path) > 0)
			g_channel_path = safe_strdup(channel_path);
		debug(LOG_DEBUG, "g_channel_path is %s", g_channel_path);
	}
}

static void
process_ping_response(struct evhttp_request *req, void *ctx)
{
	static int authdown = 0;
	
	if (req == NULL || (req && req->response_code != 200)) {
		mark_auth_offline();
		if (!authdown) {		
            fw_set_authdown();
            authdown = 1;
        }
		return;
	}
	
	char buffer[MAX_BUF] = {0};
	int nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
		    buffer, MAX_BUF-1);
	if (nread > 0)
		debug(LOG_DEBUG, "process_ping_result buffer is %s", buffer);
	
	if (nread <= 0) {
		mark_auth_offline();
        debug(LOG_ERR, "There was a problem getting response from the auth server!");
        if (!authdown) {			
            fw_set_authdown();
            authdown = 1;
        }
    } else if (strstr(buffer, "Pong") == 0) {
		mark_auth_offline();
        debug(LOG_WARNING, "Auth server did NOT say Pong!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
    } else {
    	mark_auth_online();
        debug(LOG_DEBUG, "Auth Server Says: Pong");
        if (authdown) {
            fw_set_authup();
            authdown = 0;
        }
    }
}

static void
evpings(struct evhttps_request_context *context)
{
	struct sys_info info;
	memset(&info, 0, sizeof(info));
		
	get_sys_info_o(&info);
	
	char *uri = get_ping_uri(&info);
	if (uri == NULL)
		return; // impossibe 
	
	debug(LOG_DEBUG, "ping uri is %s", uri);
	
	int timeout = 2; // 2s
	evhttps_request(context, uri, timeout, process_ping_response, NULL);
	free(uri);
}


/***********
 * eotu own　处理服务器设置信息
 * */
static void  ping_reponse(cJSON *back_j)
{
    int sockfd;
    char *resp = NULL;
    char *backto_response = NULL;
    char *tmpstr;

    cJSON *ping_key_id_j = cJSON_CreateObject();
	get_ping_key_id_info(ping_key_id_j);

	if(NULL == back_j)
		return ;

	cJSON *tmp_j=ping_key_id_j->child;
	while(tmp_j){
		if(NULL == tmp_j->next){
			tmp_j->next =back_j->child;
			break;
		}else
		tmp_j = tmp_j->next;
	}

	tmpstr=cJSON_Print(ping_key_id_j);

	/*整合返回的数据*/
    if((backto_response = coin_ping_response(tmpstr)) == NULL){
    	debug(LOG_ERR, "coin_ping_response  function error! get nothing!");
    }


    /*是否服务器继续连接*/
    if((sockfd = connect_auth_server()) <= 0){
    	debug(LOG_ERR, "connect_auth_server get sockfd error! !!!!");
    	free(backto_response);
    	return ;
    }


    if((resp = get_http_res(sockfd,backto_response)) == NULL){
    	debug(LOG_ERR, "ERROR !,ping_reponse NULL !!!!");
    }

    debug(LOG_NOTICE, "ping_reponse reback:%s !!!!",resp);

    free(backto_response);
    close(sockfd);
    boot_handle();

    return ;
}



/**
 * eotu own
 * */
void ping_handle(char *res)
{
    cJSON *ping_reback_j=NULL;
    char *res_bk = res;
    char *dataj_str;
    cJSON *cnfj;
    char *status;

    debug(LOG_NOTICE, "Get Ping Response: \r\n%s\r\n" ,res);

    if (NULL == res) {
        debug(LOG_ERR, "There was a problem pinging the auth server!");
        return ;
    } else{
        if(strstr(res,"200")){
            debug(LOG_DEBUG, "Auth Server connect, and give set json data");
            dataj_str = strstr(res,"\r\n\r\n");
            if(NULL == dataj_str || (dataj_str[5]=='O' && dataj_str[6]=='K') ){
            	free(res_bk);
            	return ;
            }
            cnfj = cJSON_Parse(dataj_str);
            if (cnfj){
            	ping_reback_j = client_set_and_request(cnfj);
            	cJSON_Delete(cnfj);
            }else{
            	ping_reback_j = cJSON_CreateObject();
            	cJSON_AddStringToObject(ping_reback_j,"Error","ReceiveFromServer");
            }

            ping_reponse(ping_reback_j);
            cJSON_Delete(ping_reback_j);
        }
       else{
    	   if((status = strstr(res,"Status")) != NULL){
        	   if(strlen(status) > 12)
        	   debug(LOG_ERR, "unknow status code [%c%c%c%c]!",status[8],status[9],status[10]);
    	   }
       }
    }
    free(res_bk);

    return ;
}

/** @internal
 * This function does the actual request.
 */
static void
ping(void)
{
    char *request = NULL;
    int sockfd;
    static int authdown = 0;
	
	struct sys_info info;
	memset(&info, 0, sizeof(info));
	
	get_sys_info_o(&info);
	
	/*
     * The ping thread does not really try to see if the auth server is actually
     * working. Merely that there is a web server listening at the port. And that
     * is done by connect_auth_server() internally.
     */
    sockfd = connect_auth_server();
    if (sockfd == -1) {
        /*
         * No auth servers for me to talk to
         */
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
        return;
    }
	
    /*
     * Prep & send request
     */
	// request = get_ping_request(&info);

    /***eotu own **/
	if ((request = coin_ping()) == NULL)
		return; // impossible
    
    char *res = http_get(sockfd, request);
	free(request);


    if (res == NULL) {
    	debug(LOG_ERR, "There was a problem pinging the auth server!");
    	fw_set_authdown();
        authdown = 1;
    }
    if (authdown) {
        fw_set_authup();
        authdown = 0;
    }
	/***
	 * eotu own
	 * **/
	ping_handle(res);
	close_auth_server();

    return;
}

