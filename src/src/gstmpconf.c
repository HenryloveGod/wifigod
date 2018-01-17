
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
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Gr茅goire, Technologies Coeus inc.
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "gstmpconf.h"
#include "mcJSON.h"
#include "conf.h"
#include "debug.h"
#include "gs_sms.h"

#define WIFIDOG_JSON "/etc/eotu/wifidog.json"

static  char *avlist,*applist,*novellist,*conflist;

static cJSON *configj;
static cJSON *poplularserver_json;
static cJSON *trustedmaclist_json;
static cJSON *fwruleset_json;
static cJSON *domaintrusted_json;
static cJSON *auth_servers_json;


static int return_default_flg;



char * set_applistjson(char *name);

void set_configs_fromenum(enum_defualt_s code,char **dest);
void set_configi_fromenum(enum_defualt_s code,int *dest);
void set_global_arrayjson(cJSON *arrayj);
void set_configsi_fromenum(enum_defualt_s code,short *dest);
void set_config_json_to_old();
void avlist_json_init();

/** Accessor for the current gateway configuration
@return:  A pointer to the current config->  The pointer isn't opaque, but should be treated as READ-ONLY
 */
cJSON *config_get_config_json(void)
{
	return configj;
}


int config_get_default_i(enum_defualt_i code){
	int i=0;
	for(;config_defualt_i[i].name !=ocodeErrInt;i++){
		if(config_defualt_i[i].name == code){
			return config_defualt_i[i].value;
		}
	}
	return_default_flg=1;
	return DEFAULT_NOT_FOUNT_INT;
}
const char * config_get_default_s(enum_defualt_s code){
	int i=0;
	for(;config_defualt_s[i].name !=ocodeErrStr;i++){
		if(config_defualt_s[i].name == code){
			return config_defualt_s[i].value;
		}
	}
	return_default_flg=1;
	return NULL;
}


/**根据enum_defualt_s　返回默认值
 *
 * **/
char *config_get_str(enum_defualt_s return_defvalue,char *father,...){
	va_list p;
	va_start(p,father);
	va_end(p);
	cJSON *j =  _mjson_getobject(father,p);

	return j ? j->valuestring:(char *) config_get_default_s(return_defvalue);
}

int config_get_int(enum_defualt_i return_defvalue,char *father,...){
	va_list p;
	va_start(p,father);
	va_end(p);
	cJSON *j =  _mjson_getobject(father,p);

	return j ? j->valuedouble:config_get_default_i(return_defvalue);
}



/**
 * 根据json key 设置value
 * **/
int set_ocode_int_by_jsonkey(char * key ,int value){
	int i;
	for(i=0;config_defualt_i[i].name !=ocodeErrInt;i++){
		if(strcmp(config_defualt_i[i].jkey,key) == 0){
			config_defualt_i[i].value = value;
			//printf("SET INT NO.%d : %s [%d]\r\n",config_defualt_i[i].name,config_defualt_i[i].jkey,config_defualt_i[i].value);
			break;
		}
	}
	return 0;
}
int set_ocode_str_by_jsonkey(char * key ,char * value){
	int i;
	for(i=0;config_defualt_s[i].name !=ocodeErrStr;i++){
		if(strcmp(config_defualt_s[i].jkey,key) == 0){
			config_defualt_s[i].value = value;
			//printf("SET STR NO.%d : %s [%s]\r\n",config_defualt_s[i].name,config_defualt_s[i].jkey,config_defualt_s[i].value);
			break;
		}
	}
	return 0;
}


/**
 * 根据code 设置value
 * **/

int config_set_int_bykey(enum_defualt_i code ,int value){
	int i;
	for(i=0;config_defualt_i[i].name !=ocodeErrInt;i++){
		if(config_defualt_i[i].name ==code){
			config_defualt_i[i].value = value;
			printf("SET INT NO.%d : %s [%d]\r\n",config_defualt_i[i].name,config_defualt_i[i].jkey,config_defualt_i[i].value);
			break;
		}
	}
	return 0;
}
int config_set_str_bykey(enum_defualt_s code ,char * value){
	int i;
	for(i=0;config_defualt_s[i].name !=ocodeErrStr;i++){
		if(config_defualt_s[i].name ==code){
			config_defualt_s[i].value = value;
			printf("SET STR NO.%d : %s [%s]\r\n",config_defualt_s[i].name,config_defualt_s[i].jkey,config_defualt_s[i].value);
			break;
		}
	}
	return 0;
}


/**
 *
 *
 *
 * **/

t_domain_trusted *set_domain_trusted_by_arrayjson(){


	return NULL;
}
t_popular_server *set_popular_server_by_arrayjson(){
	cJSON *tmpj;
	t_popular_server *pr,*tr;
	tr=pr = (t_popular_server *)malloc(sizeof(t_popular_server *));
	int len = cJSON_GetArraySize(poplularserver_json);
	int i=0;

	for(;i<len;i++){
		if(tr==NULL){
			tr = (t_popular_server *)malloc(sizeof(t_popular_server *));
		}
		tmpj = cJSON_GetArrayItem(poplularserver_json,i);

		mjson_sets_to_poit(tmpj,"hostname",&pr->hostname);
		tr = tr->next;
	}

	return pr;
}

void set_auth_server_byarrayjson(){
	cJSON *tmpj;
	int array_l=0,i=0;

	s_config *config=config_get_config();
	t_auth_serv *pr;

	debug(LOG_DEBUG, "set_auth_server_byarrayjson %s",auth_servers_json->string);

	if(config->auth_servers == NULL){
		 pr = (t_auth_serv  *)malloc(sizeof(t_auth_serv));
		 bzero(pr,sizeof(t_auth_serv ));
		 config->auth_servers =pr;
	}else{
		pr = config->auth_servers;
	}
	array_l = cJSON_GetArraySize(auth_servers_json);
	i=0;

	for(;i<array_l;i++){
		if((tmpj = cJSON_GetArrayItem(auth_servers_json,i)) == NULL)
			break;
		if(pr==NULL){
			pr =  (t_auth_serv *)malloc(sizeof(t_auth_serv));
		}
		mjson_sets_to_poit(tmpj,"authserv_hostname",&pr->authserv_hostname);
		mjson_sets_to_poit(tmpj,"authserv_path",&pr->authserv_path);
		mjson_sets_to_poit(tmpj,"login",&pr->authserv_login_script_path_fragment);
		mjson_sets_to_poit(tmpj,"portal",&pr->authserv_portal_script_path_fragment);
		mjson_sets_to_poit(tmpj,"msg",&pr->authserv_msg_script_path_fragment);
		mjson_sets_to_poit(tmpj,"ping",&pr->authserv_ping_script_path_fragment);
		mjson_sets_to_poit(tmpj,"eotu_response",&pr->eotu_response);
		mjson_sets_to_poit(tmpj,"eotu_register",&pr->eotu_register);

		mjson_seti_to_poit(tmpj,"authserv_http_port",&pr->authserv_http_port);
		mjson_seti_to_poit(tmpj,"authserv_ssl_port",&pr->authserv_ssl_port);
		mjson_seti_to_poit(tmpj,"authserv_use_ssl",&pr->authserv_use_ssl);
		mjson_seti_to_poit(tmpj,"authserv_fd",&pr->authserv_fd);
		mjson_seti_to_poit(tmpj,"authserv_fd_ref",&pr->authserv_fd_ref);
		mjson_seti_to_poit(tmpj,"authserv_connect_timeout",&pr->authserv_connect_timeout);

		pr = pr->next;
	}

	debug(LOG_DEBUG, "set_auth_server_byarrayjson over~~~~~ %s",config->auth_servers->authserv_hostname);

	return ;
}


void set_global_arrayjson(cJSON *arrayj){

	if(strcmp(arrayj->string,"popularservers") ==0){
		poplularserver_json=arrayj;
	}else if(strcmp(arrayj->string,"trustedmaclist") ==0){
		trustedmaclist_json=arrayj;
	}else if(strcmp(arrayj->string,"firewall_ruleset") == 0 ){
		fwruleset_json=arrayj;
	}else if(strcmp(arrayj->string,"domaintrusted") == 0 ){
		domaintrusted_json = arrayj;
	}else if(strcmp(arrayj->string,"auth_servers") == 0 ){
		auth_servers_json = arrayj;
	}
}

/**
 * 读取到的json数据，设置到对应的enmu_config中
 * 对于 array json ，直接整合到　static 公共变量中
 * **/
void set_config_default_byjson(cJSON *cfg){
	cJSON *c = cfg;
	while(c){
		if(c->type == cJSON_String){
			set_ocode_str_by_jsonkey(c->string,c->valuestring);
		}else if(c->type == cJSON_Number){
			set_ocode_int_by_jsonkey(c->string,c->valuedouble);
		}else if(c->type == cJSON_Object){
			set_config_default_byjson(c->child);
		}else if(c->type == cJSON_Array){
			set_global_arrayjson(c);
		}
		c = c->next;
	}
}



char *config_gets_bykey(enum_defualt_s code){
	int i;

	for(i=0;config_defualt_s[i].name != ocodeErrStr;i++){
		if(config_defualt_s[i].name == code){
			return config_defualt_s[i].value;
		}
	}
	return NULL;
}

int config_geti_bykey(enum_defualt_i code){
	int i;
	for(i=0;config_defualt_i[i].name !=ocodeErrInt;i++){
		if(config_defualt_i[i].name == code){
			return config_defualt_i[i].value;
		}
	}
	return DEFAULT_NOT_FOUNT_INT;
}


void set_configs_fromenum(enum_defualt_s code,char **dest){
	char *tmpstr;
	if((tmpstr = config_gets_bykey(code)) != NULL)
		(*dest) = strdup(tmpstr);
}
void set_configi_fromenum(enum_defualt_s code,int *dest){
	int tmpi;
	if((tmpi = config_geti_bykey(code)) >0)
		(*dest) = tmpi;
}
void set_configsi_fromenum(enum_defualt_s code,short *dest){
	int tmpi;
	if((tmpi = config_geti_bykey(code)) >0)
		(*dest) = tmpi;
}
void set_config_json_to_old(){

	t_http_server *http_server;
	t_https_server *https_server;

	s_config *config = config_get_config();

	//	config->pan_domains_trusted		= NULL;
	//	config->domains_trusted			= NULL;
	//	config->inner_domains_trusted	= NULL;
	//	config->roam_maclist				= NULL;
	//	config->trusted_local_maclist	= NULL;
	//	config->mac_blacklist			= NULL;
	//	config->rulesets = NULL;
	//	config->trustedmaclist = NULL;
	//	config->popular_servers = NULL;
	//	config->auth_servers = NULL;
	/******auth_servers******/
	set_auth_server_byarrayjson();

	set_configs_fromenum(otrusted_domain_string,&config->trusted_domain_string);
	parse_inner_trusted_domain_string(strdup(config->trusted_domain_string));


	debug(LOG_DEBUG, "Setting json config parameters");


	debug(LOG_DEBUG, "Setting https_server");
	https_server = (t_https_server *)malloc(sizeof(struct _https_server_t )) ;
	//memset(https_server, 0, sizeof(struct _https_server_t ));
	set_configsi_fromenum(ogw_https_port,&https_server->gw_https_port);
	set_configs_fromenum(oca_crt_file,&https_server->ca_crt_file);
	set_configs_fromenum(osvr_key_file,&https_server->svr_key_file);
	set_configs_fromenum(osvr_crt_file,&https_server->svr_crt_file);


	config->https_server	= https_server;

	debug(LOG_DEBUG, "Setting http_server");
	http_server = (t_http_server *)malloc(sizeof(struct _http_server_t));
	//memset(http_server, 0, sizeof(struct _http_server_t ));
	set_configsi_fromenum(ogw_http_port,&http_server->gw_http_port);
	set_configs_fromenum(obase_path,&http_server->base_path);
	config->http_server  = http_server;





	debug(LOG_DEBUG, "Setting set_configs_fromenum");
	set_configs_fromenum(ohtmlmsgfile,&config->htmlmsgfile);
	set_configs_fromenum(oexternal_interface,&config->external_interface);
	set_configs_fromenum(ogw_id,&config->gw_id);
	set_configs_fromenum(ogw_interface,&config->gw_interface);
	set_configs_fromenum(ogw_address,&config->gw_address);
	set_configs_fromenum(ohttpdname,&config->httpdname);
	set_configs_fromenum(ohttpdrealm,&config->httpdrealm);
	set_configs_fromenum(ohttpdpassword,&config->httpdpassword);
	set_configs_fromenum(ohttpdusername,&config->httpdusername);
	set_configs_fromenum(opidfile,&config->pidfile);
	set_configs_fromenum(owdctl_sock,&config->wdctl_sock);
	set_configs_fromenum(ointernal_sock,&config->internal_sock);



	set_configs_fromenum(osslcertpath,&config->ssl_certs);
	set_configs_fromenum(ossl_cipher_list,&config->ssl_cipher_list);
	set_configs_fromenum(oarp_table_path,&config->arp_table_path);
	set_configs_fromenum(ointernal_sock,&config->internal_sock);
	set_configs_fromenum(ointernet_offline_file,&config->internet_offline_file);
	set_configs_fromenum(oauthserver_offline_file,&config->authserver_offline_file);
	set_configs_fromenum(odns_timeout,&config->dns_timeout);

	debug(LOG_DEBUG, "Setting set_configi_fromenum");
	set_configi_fromenum(ohttpdmaxconn,&config->httpdmaxconn);
	set_configi_fromenum(ogw_port,&config->gw_port);
	set_configi_fromenum(oclienttimeout,&config->clienttimeout);
	set_configi_fromenum(ocheckinterval,&config->checkinterval);
	set_configi_fromenum(odaemon,&config->daemon);

	//set_configi_fromenum(oauthserv_use_ssl,&config->ssl_verify);


	set_configi_fromenum(odeltatraffic,&config->deltatraffic);
	set_configi_fromenum(ossl_use_sni,&config->ssl_use_sni);
	set_configsi_fromenum(ojs_filter,&config->js_filter);
	set_configsi_fromenum(opool_mode,&config->pool_mode);
	set_configsi_fromenum(othread_number,&config->thread_number);
	set_configsi_fromenum(oqueue_size,&config->queue_size);
	set_configsi_fromenum(owired_passed,&config->wired_passed);
	set_configsi_fromenum(oparse_checked,&config->parse_checked);
	set_configsi_fromenum(ono_auth,&config->no_auth);
	set_configsi_fromenum(owork_mode,&config->work_mode);
	set_configi_fromenum(oupdate_domain_interval,&config->update_domain_interval);
	set_configsi_fromenum(obypass_apple_cna,&config->bypass_apple_cna);



	debug(LOG_DEBUG, "Setting t_mqtt_server");

	t_mqtt_server *mqtt_server = (t_mqtt_server *)malloc(sizeof(t_mqtt_server));
	//memset(mqtt_server, 0, sizeof(t_mqtt_server));
	set_configs_fromenum(omqtt_hostname,&mqtt_server->hostname);
	set_configs_fromenum(omqtt_cafile,&mqtt_server->cafile);
	set_configs_fromenum(omqtt_keyfile,&mqtt_server->keyfile);
	set_configs_fromenum(omqtt_crtfile,&mqtt_server->crtfile);
	set_configi_fromenum(omqtt_port,&mqtt_server->port);
	config->mqtt_server  = mqtt_server;
	//<<<

	debug(LOG_DEBUG, "Setting eotu own");


	/** eotu own by denglei **/
	set_configi_fromenum(ouse_local_html,&config->use_local_html);
	set_configs_fromenum(oportal_url,&config->portal_url);
	set_configs_fromenum(oroot_sd_card,&config->root_sd_card);
	set_configs_fromenum(olast_use_time,&config->last_use_time);
	set_configs_fromenum(osms_port_path,&config->sms_port_path);
	set_configs_fromenum(oprocesslog,&config->processlog);
	set_configs_fromenum(oclientslog,&config->clientslog);
	set_configs_fromenum(osmsc,&config->smsc);
	set_configs_fromenum(oglobal_white,&config->global_white);
	set_configs_fromenum(oglobal_black,&config->global_black);
	set_configs_fromenum(oremind_sms_content,&config->remind_sms_content);
	set_configs_fromenum(ologin_skip_host,&config->login_skip_host);
	set_configs_fromenum(oserialnumber,&config->serialnumber);
	set_configs_fromenum(omac,&config->mac);
	set_configs_fromenum(okey,&config->key);
	set_configs_fromenum(ocreated,&config->created);
	set_configs_fromenum(oupdated,&config->updated);
	set_configs_fromenum(oversion,&config->version);
	set_configi_fromenum(oid,&config->id);
	set_configi_fromenum(obaudrate,&config->baudrate);
	set_configi_fromenum(oauth_down_max_to_reboot,&config->auth_down_max_to_reboot);
	set_configi_fromenum(ologsize,&config->logsize);

}


/** Sets the default config parameters and initialises the configuration system */
void config_json_init(void)
{
	char *configstr;

	/**读取文件*/
	if((configstr =read_json_file_delete_comment(WIFIDOG_JSON) ) != NULL){
		configj = cJSON_Parse(configstr);
		free(configstr);
	}else{
		debug(LOG_ERR,"error! "WIFIDOG_JSON " file read!");
		return ;
		//exit(-1);
	}

	if(configj==NULL){
		debug(LOG_ERR,"error! "WIFIDOG_JSON " file parse to JSON!");

		return ;
		//exit(-1);
	}

	/**
	 * 使用mcjson时，需要设置mc_top_config　全局变量
	 * 后续不能更改
	 * **/
	set_mc_top_config(configj);

	//把json数据覆盖　默认值
	set_config_default_byjson(configj);

	//新的配置数据覆盖原由的
	set_config_json_to_old();

	//其他参数设置
	s_config *config = config_get_config();
	config->is_register = 0;
	config->sign = (char *)malloc(33);
	memset(config->sign,0,33);

    char *gwface= get_gw_interface();
    char *ip = get_iface_ip(gwface);
    if(gwface)
    	config->gw_interface=gwface;
    if(ip)
    	config->gw_address = ip;


	//初始化串口，并设置imei
	sms_init(config->sms_port_path);

}


/**
 * 获取视频文件av.json/app.json/novel.json/eotu_config->json
 * */
char * set_applistjson(char *name){

	s_config *config = config_get_config();
	char *res;
	char *sd_root = config->root_sd_card;
	char *app_path = config->app_conf_path;
	char *conf_path;
	char *cnf =name;

	conf_path = malloc(strlen(sd_root)+strlen(app_path)+strlen(cnf) + 6);
	sprintf(conf_path,"%s%s/%s",sd_root,app_path,cnf);
	debug(LOG_INFO,"-------got av.json path %s",conf_path);
	res = read_json_file_delete_comment(conf_path);
	free(conf_path);
	return res;
}
void avlist_json_init(){

	avlist = set_applistjson("av.json");
	applist = set_applistjson("app.json");
	novellist = set_applistjson("novel.json");
	conflist = set_applistjson("eotu_config.json");
}

char *get_apncjson(char *cnf){

	if(avlist == NULL || applist == NULL || novellist == NULL || conflist == NULL)
		return "nothing ,may be sd card not insert";

	if(strcmp(cnf,"av.json") == 0){
		return avlist;
	}else if(strcmp(cnf,"app.json") == 0){
		return applist;
	}else if(strcmp(cnf,"novel.json") == 0){
		return novellist;
	}else if(strcmp(cnf,"eotu_config.json") == 0){
		return conflist;
	}else
		return NULL;
}




/*保存当前的config_json到文件中*/

int save_config_json_to_file(char *filepath)
{
    /*获取最新的json配置数据*/
	cJSON *newj = config_struct_to_json();

    char *filestr = cJSON_Print(newj);
    cJSON_Delete(newj);

    if(NULL == filestr)
    	return -1;
    /*打开文件，把json字符串 全部写入到文件中，保存在dstfile_path文件中*/
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC,0777);
    if (fd == -1) {
        debug(LOG_ERR, "Could not open configuration file '%s', " "exiting...", filepath);
        free(filestr);
        exit(1);
    }

    int rc =  write(fd,filestr,strlen(filestr));
    if(rc == -1 ) {
        debug(LOG_CRIT, "Failed to write[%d] %s; ERROR : %s", rc, filepath, strerror(errno));
        free(filestr);
        close(fd);
        exit(1);
    }

    free(filestr);
    close(fd);
    debug(LOG_NOTICE, "success to save config to file  %s ! ",filepath);
    return 0;
}



/*
 * 获取IMEI，赋值给serialnumber
 * XXX 通过smsport 获取，　不过已经防盗　sms_init()中
 * 通过这个命令吧：	smsport /dev/ttyUSB3 AT+CGSN
 * */

int set_imei()
{
	char *cmd;

	s_config *config= config_get_config();

	if(config->is_sms_work ==0){
		debug(LOG_ERR,"sms_work not work");
		return -1;

	}


	safe_asprintf(&cmd,"smsport %s AT+CGSN",config->sms_port_path);

	char *imeir =get_popen_str(cmd);
	if(!imeir){
		debug(LOG_ERR,"smsport run fail!");
		return -1;
	}

	char *token = strstr(imeir,"smsresult");
	char imei[16];
	int i=0;
	while(token){
		if( *token >= 0+'0' && *token <= 9+'0' ){
			imei[i]=*token;
			i++;
			if(i>14){
				break;
			}
		}
		token++;
	}
	imei[i]='\0';
	char * oldimei = config->serialnumber;
	if(i==15){
		if(NULL == oldimei || strcmp(oldimei,imei) !=0){
			debug(LOG_NOTICE,"serialnumber change to : %s" ,imei);
			config->serialnumber = safe_strdup(imei);
		}
	}
	return 0;

}




void add_enumi_to_json(cJSON *newj){
	int i=0;
	for(;config_defualt_i[i].name != ocodeErrInt;i++){
		if(config_defualt_i[i].jkey)
		cJSON_AddNumberToObject(newj,config_defualt_i[i].jkey,config_defualt_i[i].value);
	}
}

void add_enums_to_json(cJSON *newj){
	int i=0;
	for(;config_defualt_s[i].name != ocodeErrStr;i++){
		if(config_defualt_s[i].jkey && config_defualt_s[i].value != NULL)
			cJSON_AddStringToObject(newj,config_defualt_s[i].jkey,config_defualt_s[i].value);
	}
}



cJSON * config_struct_to_json(){
	cJSON *new_config_j=cJSON_CreateObject();
	/**
	 * XXX
	 * 没有做分类～～～～～ ,正犹豫，configj　与　new_config_j　的处理方式，覆盖原文件，还是新建，后续再想
	 * */
	add_enumi_to_json(new_config_j);
	add_enums_to_json(new_config_j);

	return new_config_j;

}



