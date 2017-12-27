/* vim: set et sw=4 ts=4 sts=4 : */
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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <zlib.h>
#include <httpd.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gstmpconf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"
#include "gateway.h"
#include "https_server.h"
#include "simple_http.h"
#include "wdctl_thread.h"
#include "version.h"
#include "safe.h"

#define APPLE_REDIRECT_MSG  "<!DOCTYPE html>"	\
				"<html>"						\
				"<title>Success</title>"		\
				"<script type=\"text/javascript\">"	\
					"window.location.replace(\"%s\");"	\
				"</script>"	\
				"<body>"	\
				"Success"	\
				"</body>"	\
				"</html>"


const char *apple_domains[] = {
					"captive.apple.com",
					"www.apple.com",
					NULL
};

const char *apple_wisper = "<!DOCTYPE html>"
				"<html>"
				"<script type=\"text/javascript\">"
					"window.setTimeout(function() {location.href = \"captive.apple.com/hotspot-detect.html\";}, 12000);"
				"</script>"
				"<body>"
				"</body>"
				"</html>";

static int
_is_apple_captive(const char *domain)
{
	int i = 0;
	while(apple_domains[i] != NULL) {
		if(strcmp(domain, apple_domains[i]) == 0)
			return 1;
		i++;
	}

	return 0;
}

static int
_special_process(request *r, const char *mac, const char *redir_url)
{
	t_offline_client *o_client = NULL;

	if(_is_apple_captive(r->request.host)) {
		int interval = 0;
		LOCK_OFFLINE_CLIENT_LIST();
    	o_client = offline_client_list_find_by_mac(mac);
    	if(o_client == NULL) {
    		o_client = offline_client_list_add(r->clientAddr, mac);
    	} else {
			o_client->last_login = time(NULL);
			interval = o_client->last_login - o_client->first_login;
		}

		debug(LOG_DEBUG, "Into captive.apple.com hit_counts %d interval %d http version %d\n", 
				o_client->hit_counts, interval, r->request.version);
    	
		o_client->hit_counts++;

		if(o_client->client_type == 1 ) {
    		UNLOCK_OFFLINE_CLIENT_LIST();
			if(interval > 20 && r->request.version == HTTP_1_0) {
				fw_set_mac_temporary(mac, 0);	
				http_send_apple_redirect(r, redir_url);
			} else if(o_client->hit_counts > 2 && r->request.version == HTTP_1_0)
				http_send_apple_redirect(r, redir_url);
			else {
				http_send_redirect(r, redir_url, "Redirect to login page");
			}
		} else {	
			o_client->client_type = 1;
			UNLOCK_OFFLINE_CLIENT_LIST();
			http_relay_wisper(r);
		}
		return 1;
	} 

	return 0;
}
//<<< liudf added end

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{  	
    if (!is_online()) {
		char *msg = evb_2_string(evb_internet_offline_page, NULL);
        send_http_page_direct(r, msg);
		free(msg);
        debug(LOG_DEBUG, "Sent %s an apology since I am not online - no point sending them to auth server",
              r->clientAddr);
    } else if (!is_auth_online()) {
    	/**
    	 * 离线网页
    	 * */
		char *msg = evb_2_string(evb_authserver_offline_page, NULL);
        send_http_page_direct(r, msg);
		free(msg);
        debug(LOG_DEBUG, "Sent %s an apology since auth server not online - no point sending them to auth server",
              r->clientAddr);
    } else {
		/* Re-direct them to auth server */
		const s_config *config = config_get_config();
		char tmp_url[MAX_BUF] = {0};
        char  mac[18] = {0};
        httpVar *uidv,*tokenv,*eotuv;

        uidv = httpdGetVariableByName(r,"uid");
        tokenv = httpdGetVariableByName(r,"token");
        eotuv = httpdGetVariableByName(r,"eotu");

        int nret = br_arp_get_mac(r->clientAddr, mac);

		if (nret == 0) {
            strncpy(mac, "ff:ff:ff:ff:ff:ff", 17);
        }
        r->uid = uidv? uidv->value:"null";
        r->mac = mac;
        r->token = tokenv ?tokenv->value:"null";
        r->request.is_eotu = eotuv? atoi(eotuv->value ? eotuv->value :0):0;

		snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
		


    	char *url = httpdUrlEncode(tmp_url);	

    	debug(LOG_DEBUG,"client request :[%s] \r\n [%s]",tmp_url,url);

    	char *redir_url = evhttpd_get_full_redir_url_eotu(r,url);
        if (nret) {  // if get mac success              
			t_client *clt = NULL;
            debug(LOG_DEBUG, "Got client MAC address for ip %s: %s", r->clientAddr, mac);	
			
			//>>> liudf 20160106 added
			if(config->bypass_apple_cna != 0)
				if(_special_process(r, mac, redir_url)) {
					goto end_process;
				}
			
			// if device has login; but after long time reconnected router, its ip changed
			LOCK_CLIENT_LIST();
			clt = client_list_find_by_mac(mac);
			if(clt && strcmp(clt->ip, r->clientAddr) != 0) {
				fw_deny(clt);
				free(clt->ip);
				clt->ip = safe_strdup(r->clientAddr);
				fw_allow(clt, FW_MARK_KNOWN);
				UNLOCK_CLIENT_LIST();
                debug(LOG_INFO, "client has login, replace it with new ip");
				http_send_redirect(r, tmp_url, "device has login");
            	goto end_process;
			}
			UNLOCK_CLIENT_LIST();

			//直接放行～～～～～～～～～～
            if (config->wired_passed && br_is_device_wired(mac)) {
                debug(LOG_DEBUG, "wired_passed: add %s to trusted mac", mac);
                if (!is_trusted_mac(mac))
                    add_trusted_maclist(mac);
                http_send_redirect(r, tmp_url, "device was wired");
                goto end_process;
            }
        }
		
        debug(LOG_DEBUG, "Captured %s requesting [%s] and re-directing them to checkuid page \r\n[%s]", r->clientAddr, tmp_url ,redir_url);
		if(config->js_filter)
			http_send_js_redirect(r, redir_url);
		else
			http_send_redirect(r, redir_url, "Redirect to login page");
		
end_process:
		if (redir_url) free(redir_url);
		if (url) free(url);
    }
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFiDog Status", buf);
    free(buf);
    free(status);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
}

/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
	// liudf 20160104; change 302 to 307
    safe_asprintf(&response, "307 %s\r\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);

    safe_asprintf(&message, "<html><body>Please <a href='%s'>click here</a>.</body></html>", url);
    httpdOutputDirect(r, message);
	_httpd_closeSocket(r);
    free(message);
}

void
http_callback_auth(httpd * webserver, request * r)
{
    t_client *client;
    httpVar *token;
    char *mac;
    httpVar *logout = httpdGetVariableByName(r, "logout");

    if ((token = httpdGetVariableByName(r, "token"))) {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();

            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                debug(LOG_DEBUG, "New client for %s", r->clientAddr);
                client_list_add(r->clientAddr, mac, token->value,NULL);
            } else if (logout) {
                logout_client(client);
            } else {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }

            UNLOCK_CLIENT_LIST();
            if (!logout) { /* applies for case 1 and 3 from above if */
                authenticate_client(r);
            }
            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
        send_http_page(r, "WiFiDog error", "Invalid token");
    }
}

void
http_callback_disconnect(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) {
        t_client *client;

        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);

        if (!client || strcmp(client->token, token->value)) {
            UNLOCK_CLIENT_LIST();
            debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac->value, token->value);
            httpdOutput(r, "Invalid token for MAC");
            return;
        }

        /* TODO: get current firewall counters */
        logout_client(client);
        UNLOCK_CLIENT_LIST();

    } else {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        httpdOutput(r, "Both the token and MAC need to be specified");
        return;
    }

    return;
}

// liudf added 20160421
void
http_callback_temporary_pass(httpd * webserver, request * r)
{	
    const s_config *config = config_get_config();
    httpVar *mac = httpdGetVariableByName(r, "mac");
	
	if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

	if(mac) {
        debug(LOG_INFO, "Temporary passed %s", mac->value);
		fw_set_mac_temporary(mac->value, 0);	
        httpdOutput(r, "startWeChatAuth();");
	} else {
        debug(LOG_INFO, "Temporary pass called without  MAC given");
        httpdOutput(r, "MAC need to be specified");
        return;
    }

	return;
}

void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}

//>>> liudf added 20160104
void
http_send_js_redirect(request *r, const char *redir_url)
{
	struct evbuffer *evb = evbuffer_new ();	
	struct evbuffer *evb_redir_url = evbuffer_new();
	
	evbuffer_add(evb, wifidog_redir_html->front, wifidog_redir_html->front_len);
	evbuffer_add_printf(evb_redir_url, WIFIDOG_REDIR_HTML_CONTENT, redir_url);
	evbuffer_add_buffer(evb, evb_redir_url);
	evbuffer_add(evb, wifidog_redir_html->rear, wifidog_redir_html->rear_len);
	
	int html_length = 0;
	char *redirect_html = evb_2_string(evb, &html_length);
	
#ifdef	_DEFLATE_SUPPORT_
	if (r->request.deflate) {
		char *deflate_html = NULL;
		int wlen = 0;
		
		if (deflate_write(redirect_html, html_length, &deflate_html, &wlen, 1) == Z_OK) {
			httpdOutputLengthDirect(r, deflate_html, wlen);				
		} else
			debug(LOG_INFO, "deflate_write failed");
		
		if (deflate_html) free(deflate_html);
	} else
#endif
		httpdOutputLengthDirect(r, redirect_html, html_length);
	
	_httpd_closeSocket(r);
	
	free(redirect_html);
	evbuffer_free(evb);
	evbuffer_free(evb_redir_url);
}

void
http_send_apple_redirect(request *r, const char *redir_url)
{
   	httpdPrintf(r, APPLE_REDIRECT_MSG, redir_url);
	_httpd_closeSocket(r);
}

void
http_relay_wisper(request *r)
{
	httpdOutputDirect(r, apple_wisper);
	_httpd_closeSocket(r);
}

void send_http_page_direct(request *r,  char *msg) 
{
	httpdOutputDirect(r, msg);
	_httpd_closeSocket(r);
}

//<<< liudf added end
















/****
 *
 * eotu app
 *
 * **/



/* ＡＰＰ获取路由器频道文件清单*/
void http_eotu_avlist(httpd * webserver, request * r)
{
	//ls -lt ./ | awk -F ' ' '{print "{\"size\":"$5",\"date\":\""$6,$7,$8,"\",\"file\":\""$9"\"},"}'
	char *buff=NULL,*cnf=NULL;

	s_config config=*(config_get_config());

	/*check sign value == md5?*/
	if(r->request.is_eotu == 0 ){
		debug(LOG_ERR,"not EOTU APP,refuse to give json config!!!!!");
		return ;
	}
	if(config.root_sd_card == NULL ){
		debug(LOG_ERR,"SD CARD NOT FOUND!");
		return ;
	}
	httpVar *tmpvar = httpdGetVariableByName(r,"path");
	cnf =tmpvar ? ( tmpvar->value ? tmpvar->value :"av.json" ):"av.json";
	buff = get_apncjson(cnf);

	if(buff){
		debug(LOG_NOTICE,"ip[%s] request [%s]\r\n",r->clientAddr,cnf);
		eotu_av_response(r,buff);
	}else{
		debug(LOG_ERR,"ERROR! ip[%s] request [%s] get nothing ",r->clientAddr,cnf);
	}
	return ;
}

/** for EOTU PORTAL
 * 优途浏览器／非优途浏览器，统一跳转处理
 * */
void
http_send_redirect_eotu_login_handle(request * r)
{
    char *url= NULL,*portal= NULL,*u = NULL,*t= NULL ;

    httpVar *token= NULL,*uid = NULL;
    s_config *config = config_get_config();

    portal = config->portal_url;
	uid = httpdGetVariableByName(r,"uid");
	token = httpdGetVariableByName(r,"token");
	int is_eotu=r->request.is_eotu;

	if(httpdGetVariableByName(r,"eotu") != NULL){
		is_eotu = atoi(httpdGetVariableByName(r,"eotu")->value);
	}

	if(is_eotu == 1){
		if(uid) u = uid->value;
		if(token) t = token->value;
	    safe_asprintf(&url, "%s?gw_address=%s&gw_port=%d&router_id=%d&ip=%s&mac=%s&eotu=%d&uid=%s&token=%s",
	    		portal,config->gw_address,
				config->gw_port, config->id,
				r->clientAddr, r->mac,is_eotu,u,t);
	    free(r->mac);
	}else{
	    safe_asprintf(&url, "%s?gw_address=%s&gw_port=%d&router_id=%d&ip=%s&mac=%s&eotu=%d",
	    		portal,config->gw_address,
				config->gw_port, config->id,
				r->clientAddr, r->mac,is_eotu);
	    free(r->mac);
	}

    debug(LOG_DEBUG,"redirect to url(%s)",url);
    //http_send_redirect(r, url, NULL);

    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */

    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    httpdOutput(r, "ready to put html content");
    close(r->clientSock);
    free(response);
    free(header);
    free(url);
    return ;
}


/*app login api 入口 2017*/
void http_eotu_checkuid(httpd * webserver, request * r)
{
	http_send_redirect_eotu_login_handle(r);
	return ;
}

/****
 * wifiguid 用户指南接口
 * ***/

static struct evbuffer *
evhttp_read_file_eotu(const char *filename, struct evbuffer *evb)
{
	int fd;
	struct stat stat_info;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		debug(LOG_CRIT, "Failed to open HTML message file %s: %s", strerror(errno),
			filename);
		return NULL;
	}

	if (fstat(fd, &stat_info) == -1) {
		debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
		close(fd);
		return NULL;
	}

	evbuffer_add_file(evb, fd, 0, stat_info.st_size);
	close(fd);
	return evb;
}
void http_eotu_guid(httpd * webserver, request * r)
{

	httpVar *image = httpdGetVariableByName(r, "image");
	char *path;
	char *rootpath = "/www/wifiguid/";

	if(image != NULL){
		safe_asprintf(&path,"%simages/%s",rootpath,image->value);
//		struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);
//		evhttp_add_header(output_headers, "Content-Type", "image/gif");
	}else{
		safe_asprintf(&path,"%s/index.html",rootpath);
	}

	struct evbuffer	* evb_page = evbuffer_new();
	evhttp_read_file_eotu(path, evb_page);

	char *msg = evb_2_string(evb_page, NULL);
    send_http_page_direct(r, msg);
	free(msg);

	return ;
}




/**
 * 放行接口
 * */
void
http_eotu_auth(httpd * webserver, request * r)
{
    t_client *client;
    httpVar *token, *uid;
    char *mac;
    httpVar *logout = httpdGetVariableByName(r, "logout");

    if ((token = httpdGetVariableByName(r, "token")) && (uid = httpdGetVariableByName(r, "uid"))) {
        /* They supplied variable "token" */
    	//&& !(mac=httpdGetVariableByName(r, "mac")->value)
    	debug(LOG_RECORD, "UID[%s] TOKEN[%s] IP[%s] ENTER", uid,token,r->clientAddr);
        if (!(mac = arp_get(r->clientAddr))  ) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "eotuwifi Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();
            //add to  client list
            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                client_list_add(r->clientAddr, mac, token->value ,uid->value);
            } else if (logout) {
                logout_client(client);
            } else {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }
            UNLOCK_CLIENT_LIST();
            //request to auth 1
            if (!logout) { /* applies for case 1 and 3 from above if */
            	authenticate_client(r);//原计划，请求服务器一次再放行
            }
            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
    	debug(LOG_RECORD, "Invalid token %s", r->clientAddr);
        send_http_page(r, "eotuwifi error", "Invalid token");
    }
}








