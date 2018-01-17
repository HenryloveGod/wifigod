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
/** @file conf.h
    @brief Config file parsing
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/



#ifndef _GSTMPCONFIG_H_
#define _GSTMPCONFIG_H_

#include <stdio.h>
#include <stdarg.h>

#include "mcJSON.h"
#include "conf.h"

#define VERSION "2017.12.12"


#define DEFAULT_NOT_FOUNT_INT -99

#define WIFIDOG_JSON_NEW "/etc/eotu/wifidog.json.new"

typedef enum {

	ouse_local_html=0,
	odeltatraffic = 1,
	odaemon,
	oauth_down_max_to_reboot,
	obaudrate,
	ologsize,
	oid,
	odebuglevel,
	ogw_port,
	ogw_https_port,
	ogw_http_port,
	ohttpdmaxconn,
	oclienttimeout,
	ocheckinterval,
	osyslogfacility,
	oauthserv_use_ssl,
	ossl_use_sni,
	oproxy_port,
	ois_sslpeerverification,
	oauthserv_connect_timeout,
	ojs_filter,
	opool_mode,
	othread_number,
	oqueue_size,
	owired_passed,
	oauthserv_http_port,
	oauthserv_https_port,
	owork_mode,
	ogatewayHttpsPort,
	oparse_checked,
	obypass_apple_cna,
	ono_auth,
	omqtt_port,

	oauthserv_fd,
	oauthserv_fd_ref,
	oauthserv_ssl_port,
	oupdate_domain_interval,
	ocodeErrInt
}enum_defualt_i;




static struct {
	enum_defualt_i name;
	int value;
	const char *jkey;
} config_defualt_i[] = {
		{ouse_local_html, 0,"use_local_html"},
		{odeltatraffic, 1,"deltatraffic"},
		{odaemon, 1,"daemon"},

		{obaudrate, 1152000,"baudrate"},
		{ologsize, 200000,"logsize"},
		{oauth_down_max_to_reboot, 1,"auth_down_max_to_reboot"},
		{oid, 0,"id"},

		{odebuglevel, 6,"debuglevel"},
		{ogw_port, 2060,"gw_port"},
		{ogw_http_port,2060,"gw_http_port"},
		{ogw_https_port, 2061,"gw_https_port"},
		{ohttpdmaxconn, 10,"httpdmaxconn"},
		{oclienttimeout, 5,"clienttimeout"},
		{ocheckinterval, 60,"checkinterval"},
		{osyslogfacility, 0,"syslogfacility"},
		{oauthserv_use_ssl, 1,"authserv_use_ssl"},
		{oauthserv_https_port, 443,"authserv_https_port"},
		{oauthserv_ssl_port, 443,"authserv_ssl_port"},
		{oauthserv_http_port, 80,"authserv_http_port"},
		{ossl_use_sni, 0,"sslusesni"},
		{oproxy_port, 0,"proxy_port"},
		{ois_sslpeerverification, 1,"is_sslpeerverification"},
		{oauthserv_connect_timeout, 600,"authserv_connect_timeout"},
		{ojs_filter, 1,"js_filter"},
		{opool_mode, 1,"pool_mode"},
		{othread_number, 10,"thread_number"},
		{oqueue_size, 30,"queue_size"},
		{owired_passed, 0,"wired_passed"},
		{owork_mode, 0,"work_mode"},
		{oparse_checked, 0,"parseChecked"},
		{obypass_apple_cna, 1,"bypass_apple_cna"},
		{ono_auth, 0,"no_auth"},
		{omqtt_port, 8883,"mqtt_port"},

		{oauthserv_fd,0,"authserv_fd"},
		{oauthserv_fd_ref,0,"authserv_fd_ref"},
		{oupdate_domain_interval,600,"update_domain_interval"},
		{ocodeErrInt,DEFAULT_NOT_FOUNT_INT,NULL}
};

typedef enum {
	/** eotu own by denglei*/

	oportal_url,
	oroot_sd_card,
	olast_use_time,
	osms_port_path,
	osmsc,
	oprocesslog,
	oclientslog,
	oapp_conf_path,
	oglobal_white,
	oglobal_black,
	oremind_sms_content,
	ologin_skip_host,
	ossid,
	oserialnumber,
	omac,
	okey,
	ocreated,
	oupdated,
	oversion,

	otrusted_domain_string,

	/** base*/
	odns_timeout,
	opidfile,
	oarp_table_path,
	ointernal_sock,
	oconfigfile,
	oexternal_interface,
	ogw_id,
	ogw_interface,
	ogw_address,
	oauthserv_hostname,
	ohttpdname,
	ohttpdrealm,
	ohttpdusername,
	ohttpdpassword,
	owdctl_sock,
	omqtt_hostname,
	oauthserv_path,
	ologin,
	oportal,
	omsg,
	oping,
	oauth,
	oeotu_register,
	oresponse,
	ofirewallruleset,
	ofirewallrule,
	otrustedmaclist,
	opopularservers,
	ohtmlmessagefile,
	osslcertpath,
	ossl_cipher_list,
	otrustedPanDomains,
	otrustedDomains,
	ountrustedmaclist,
	otrustedIpList,
	otrustedlocalmaclist,
	olast_ip,
	ointernet_offline_file,
	oauthserver_offline_file,
	ohtmlmsgfile,
	ohtmlredirfile,
	oca_crt_file,
	osvr_crt_file,
	osvr_key_file,


	obase_path,


	/**
	 * mqtt_server
	 * */
	omqtt_addr,
	omqtt_cafile,
	omqtt_crtfile,
	omqtt_keyfile,
	ocodeErrStr
}enum_defualt_s;


/** @internal
 The config file keywords for the different configuration options */
static struct {
	enum_defualt_s name;
	char *value;
	const char *jkey;
} config_defualt_s[] = {

		/**
		 * eotu own by denglei
		 * **/

		{otrusted_domain_string,"www.eotu.com,wx-s.net","trusted_domain_string"},
		{odns_timeout,"1.0","dnstimeout"},
		{oapp_conf_path,"/eotufiles/api","app_conf_path"},
		{oportal_url,"http://wifi.eotu.com/app/checkuid","portal_url"},
		{oroot_sd_card,"/mnt/eotusd","root_sd_card"},
		{olast_use_time,"","last_use_time"},
		{osms_port_path,"/dev/ttyUSB3","sms_port_path"},
		{osmsc,"8613010720500","smsc"},
		{oprocesslog,"/mnt/eotusd/log/process.log","processlog"},
		{oclientslog,"/mnt/eotusd/log/clients.log","clientslog"},
		{oglobal_white,"eotu.com;apple.com;","global_white"},
		{oglobal_black,"qq.com;weixin.com;","global_black"},
		{oremind_sms_content,"路由器异常","remind_sms_content"},
		{ologin_skip_host,"aliyuncs.com;weixin.qq.com;dianping.com;cgicol.amap.com;appjiagu.com","login_skip_host"},
		{oserialnumber,"","serialnumber"},
		{omac,"","mac"},
		{okey,"1234","key"},
		{ocreated,"2017-03-14 17:06:36","created"},
		{oupdated,"","updated"},
		{oversion,"openwrt cc 0.0.171212","version"},

		/**
		 * base
		 * **/

		{opidfile,"/tmp/wifidog.pid","pidfile"},
		{oarp_table_path,"/proc/net/arp","arp_table_path"},
		{ointernal_sock,"/tmp/wifidog.sock","internal_sock"},
		{oconfigfile, "/etc/eotu/wifidog.json","configfile"},
		{oexternal_interface, "enp2s0","external_interface"},
		{ogw_id,"gw_id","gw_id"},
		{ogw_interface, "br-lan","gw_interface"},
		{ogw_address, "192.168.10.1","gw_address"},
		{ohtmlmsgfile,"/etc/eotu/wifidog-msg.html","htmlmsgfile"},
		{ointernet_offline_file,"/etc/eotu/internet-offline.html","internet_offline_file"},
		{oauthserver_offline_file,"/etc/eotu/internet-offline.html","authserver_offline_file"},
		{ohtmlredirfile,"/etc/eotu/internet-offline.html","htmlredirfile"},

	/****
	 * local_server
	 * ****/
	{ohttpdname,"WIFIDOG","httpdname"},
	{ohttpdrealm,"WIFIDOG","httpdrealm"},
	{ohttpdusername,"root","httpdusername"},
	{ohttpdpassword,"root","httpdpassword"},
	{owdctl_sock, "/tmp/wdctl.sock","wdctl_sock"},
	{olast_ip,NULL,"last_ip"},

	{obase_path,"/www/","base_path"},

	/****
	 * auth_server
	 * ****/
	{oauthserv_hostname, "www.server.com","authserv_hostname"},
	{oauthserv_path,"/","authserv_path"},
	{ologin,"login?","login"},
	{oportal,"portal?","portal"},
	{oresponse,"response?","eotu_response"},
	{omsg,"msg","msg"},
	{oeotu_register,"reg","eotu_register"},
	{oping,"ping?","ping"},
	{oauth,"0","auth"},

	{osslcertpath,"/etc/ssl/certs/","sslcertpath"},
	{oca_crt_file,"/etc/eotu/apfree.ca","ca_crt_file"},
	{osvr_crt_file,"/etc/eotu/apfree.crt","svr_crt_file"},
	{osvr_key_file,"/etc/eotu/apfree.key","svr_key_file"},

	{ossl_cipher_list,NULL,"sslallowedcipherlist"},


	/****
	 * mqtt_server
	 * ****/
	{omqtt_hostname, "www.eotu.com","mqtt_hostname"},
	{omqtt_addr, "localhost","mqtt_addr"},
	{omqtt_cafile, "/etc/eotu/apfree.ca","mqtt_cafile"},
	{omqtt_crtfile, "/etc/eotu/apfree.crt","mqtt_crtfile"},
	{omqtt_keyfile, "/etc/eotu/apfree.key","mqtt_keyfile"},
	/****
	 * rules
	 * ****/
	{ofirewallruleset, NULL,"firewallruleset"},
	{ofirewallrule, NULL,"firewallrule"},
	{otrustedmaclist,NULL,"trustedmaclist"},
	{opopularservers,NULL,"popularservers"},
	{otrustedPanDomains,NULL,"trustedPanDomains"},
	{otrustedDomains,NULL,"trustedDomains"},
	{ountrustedmaclist,NULL,"untrustedmaclist"},
	{otrustedIpList,NULL,"trustedIpList"},
	{otrustedlocalmaclist, NULL,"trustedlocalmaclist"},

	{ocodeErrStr, NULL,NULL},

};



int set_ocode_str_by_jsonkey(char * key ,char * value);


/**
 *
 * 返回configj
 * **/
cJSON *config_get_config_json(void);
/*
 * 读取配置文件初始化为json数据
 * */
void config_json_init(void);

/*
 * 获取参数，返回为json对象
 * 备注：最后一个参数一定要为NULL
 * */
cJSON * config_get_obj(char *father,...);
/*
 * 通过key来访问
 * */
char *config_gets_bykey(enum_defualt_s code);
int config_geti_bykey(enum_defualt_i code);
void set_config_default_byjson(cJSON *cfg);

t_domain_trusted *set_domain_trusted_by_arrayjson();
t_popular_server *set_popular_server_by_arrayjson();
void set_auth_server_byarrayjson();

/**
 * 获取默认值
 * **/
const char * config_get_default_s(enum_defualt_s code);
int config_get_default_i(enum_defualt_i code);
char *config_get_str(enum_defualt_s return_defvalue,char *father,...);
int config_get_int(enum_defualt_i return_defvalue,char *father,...);


/**
 * 根据code 设置value
 * **/
int config_set_int_bykey(enum_defualt_i code ,int value);
int config_set_str_bykey(enum_defualt_s code ,char * value);

/**
 * 获取视频文件av.json/app.json/novel.json/eotu_config.json
 * */
char *get_apncjson(char *cnf);

/**
 *　把当前配置的信息，存储的json数据中
 * **/

cJSON * config_struct_to_json();


/*保存当前的config_json到文件中*/
int save_config_json_to_file(char *filepath);

/**
 * 根据json key 设置value
 * **/
int set_ocode_int_by_jsonkey(char * key ,int value);

#endif
