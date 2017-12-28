
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
#include <iconv.h>

#include "common.h"
#include "wdctl_thread.h"
#include "safe.h"
#include "gstmpconf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"
#include "mcJSON.h"
#include "gateway.h"
#include "gsclient_handle.h"
#include "wdctl_thread.h"
#include "gs_sms.h"
#include "gsclient_set.h"
#include "gsbasemethod.h"
#include "conf.h"

#include "wdctl_thread.h"


//#define CHAIN_UNTRUSTED "CHAIN_UNTRUSTED"
#define INTERFACE_OUT "wlan0"

static char *config_string_set(cJSON *p,char *cc);
static char *config_int_set(cJSON *p,char *cc);

char *config_string_set(cJSON *p,char *cc){

    char *method = get_method_name(p->string);
    char *str = p->valuestring;

    if(!method)
    	return "fuck no method!";
    if(str){
    	//////// on going 只是修改了默认值，没有赋值到config
        set_ocode_str_by_jsonkey(method,str);

        return "OK";
    }else
        return "para NULL";
}
char *config_int_set(cJSON *p,char *cc){

    char *method = get_method_name(p->string);
    char *value = p->valuestring;
    char *checkv = value;
    int v=9999;
    int is_int = 1;

    if(!method)
    	return "fuck no method!";


    if((v = p->valuedouble) == 0 && value!=NULL){
    	checkv = value;
    	for(;*checkv!='\0';checkv++){
    		if(*checkv >='0' && *checkv <='9')
    			continue;
    		else{
    			is_int = 0;
    			break;
    		}
    	}
    	if(is_int == 1){
    		v = atoi(value);
    		//////// on going 只是修改了默认值，没有赋值到config
    		set_ocode_int_by_jsonkey(method,v);
    		return "OK";
    	}else{
    		return "valuedouble =0,valuestring is string!!not config_int_set!";
    	}
    }else if(v ==0 && value == NULL){
    	debug(LOG_ERR,"if value =0,should set in string position! ");
    	return "if value =0,should set in string position!";
    }else{
    	//////// on going 只是修改了默认值，没有赋值到config
    	set_ocode_int_by_jsonkey(method,v);
    }
    return "OK";

}




char *internet_config_int_set(cJSON *p){
    return  config_int_set(p,"internet");
}


char *internet_config_string_set(cJSON *p){
    return config_string_set(p,"internet");
}


char *router_config_string_set(cJSON *p){
	return config_string_set(p,"router");
}
char *router_config_int_set(cJSON *p){
    return  config_int_set(p,"router");
}



char * set_psswd(cJSON *p)
{

    char *cmd=safe_malloc(100);
    char *method = p->string;
    char *para = p->valuestring;

    char *user = "root";

    if(method == NULL || para == NULL)
        return "PARA NULL";
    debug(LOG_NOTICE,"set_psswd1 %s  %s",method,para);
    if(strstr(method,"username") > 0){
        debug(LOG_NOTICE,"set_psswd12");
        return "username must be root";
    }else if(strstr(method,"password") >0){
        debug(LOG_NOTICE,"set_psswd1");
        safe_asprintf(&cmd,"lua /usr/bin/setpwd.lua %s %s",user,para);
        debug(LOG_NOTICE,"password change command [%s]",cmd);
        if( excute_cmd(cmd) == 0){
            free(cmd);
            return "OK";
        }else{
            free(cmd);
            return "FAIL";
        }
    }else{
    	free(cmd);
    	return "method not found";
    }
 }



char *router_base_set(cJSON *p)
{
//	s_config *conf = config_get_gsconfig();
//	set_psswd(p);
//	e2json_set(p,config_get_gsconfig()->router);

	return "OK";
}

/*
 * 整体下载上传限速
 *	@参数	aaaa:bbbbb	aaaa下载，bbbbb上传
 *	tc class add dev $ODEV parent 1: classid 1:1 htb rate $UPkbit ceil $UPkbit
 *	tc class add dev $IDEV parent 1: classid 1:1 htb rate $DOWNkbit ceil $DOWNkbit
 * */
char * dw_up_speed(cJSON *p)
{

	char *dw,*up,*v;
	char *cmd;
	int max_upload,max_download;

	if(p == NULL)	return "para is empty";
	if(p->valuestring == NULL)	return "para empty";

	char *indev = get_gw_interface();

	dw = v =p->valuestring;
	for(;*v!='\0';v++){
		if(*v==':'){
			*v='\0';up=v+1;
			if(up == NULL) return "fuck u! please format string as dw;up !";
			break;
		}
	}
	max_upload = atoi(up);
	max_download = atoi(dw);
	safe_asprintf(&cmd,"tc class add dev %s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit",indev,max_upload,max_upload);

	if(excute_cmd(cmd)!=0 ){
		debug(LOG_ERR,"max_upload run error![%s]",cmd);
		free(cmd);
		return "upload run fail!";
	}

	safe_asprintf(&cmd,"tc class add dev "INTERFACE_OUT" parent 1: classid 1:1 htb rate %dkbit ceil %dkbit",max_download,max_download);
	if(excute_cmd(cmd)!=0 ){
		debug(LOG_ERR,"max_download run error![%s]",cmd);
		free(cmd);
		return "download run fail!";
	}

	return "OK";
}


/*
 *	@p	参数定义：d，下载，Ｕ，上传
 *
 *	192.168.10.167=100:100;192.168.10.242=d100:u100;
 *
iptables -t mangle -A PREROUTING -s $INET$i -j MARK --set-mark 2$i
iptables -t mangle -A PREROUTING -s $INET$i -j RETURN
iptables -t mangle -A POSTROUTING -d $INET$i -j MARK --set-mark 2$i
iptables -t mangle -A POSTROUTING -d $INET$i -j RETURN
 *
 *
 *DOWNLOAD

tc class add dev $IDEV parent 10:1 classid 10:2$i htb rate $DOWNLOAD ceil $MDOWNLOAD prio 1
tc qdisc add dev $IDEV parent 10:2$i handle 100$i: pfifo
tc filter add dev $IDEV parent 10: protocol ip prio 100 handle 2$i fw classid 10:2$i

 *UPLOAD

tc class add dev $ODEV parent 10:1 classid 10:2$i htb rate $UPLOAD ceil $MUPLOAD prio 1
tc qdisc add dev $ODEV parent 10:2$i handle 100$i: pfifo
tc filter add dev $ODEV parent 10: protocol ip prio 100 handle 2$i fw classid 10:2$i
 *
 *
 * */


int dw_up_ip_speed_set(int ipi ,char * dw,char * up){

	char *cmd;

	char *indev = get_gw_interface();

	if(dw !=NULL){
		safe_asprintf(&cmd,"tc class add dev %s"
				 " parent 1:1 classid 1:2%d htb rate %dkbit ceil %dkbit prio 1",indev,ipi,atoi(dw),atoi(dw));
		if(excute_cmd(cmd) != 0){
			debug(LOG_ERR,"tc class indev dw cmd error! ");
			return -1;
		}
		safe_asprintf(&cmd,"tc qdisc add dev %s"
				 " parent 1:2%d handle 100%d: pfifo",indev,ipi,ipi);
		if(excute_cmd(cmd) != 0){
			debug(LOG_ERR,"tc qdisc indev pfifo error! ");
			return -1;
		}
		safe_asprintf(&cmd,"tc filter add dev %s"
				 " parent 1: protocol ip prio 1 handle 2%d fw classid 1:2%d",indev,ipi,ipi);
		if(excute_cmd(cmd) != 0){
			debug(LOG_ERR,"tc filter DOWNLOAD ipi error! ");
			return -1;
		}
	}

	if(up !=NULL){
		safe_asprintf(&cmd,"tc class add dev " INTERFACE_OUT
				 " parent 1:1 classid 1:2%d htb rate %dkbit ceil %dkbit prio 1",ipi,atoi(up),atoi(up));
		if(excute_cmd(cmd) != 0){
			debug(LOG_ERR,"tc class upload cmd error! ");
			return -1;
		}
		safe_asprintf(&cmd,"tc qdisc add dev " INTERFACE_OUT
				 " parent 1:2%d handle 100%d: pfifo",ipi,ipi);
		if(excute_cmd(cmd) != 0){
			debug(LOG_ERR,"tc qdisc upload ipi error! ");
			return -1;
		}
		safe_asprintf(&cmd,"tc filter add dev " INTERFACE_OUT
				 " parent 1: protocol ip prio 1 handle 2%d fw classid 1:2%d",ipi,ipi);
		if(excute_cmd(cmd) != 0){
			debug(LOG_ERR,"tc filter upload ipi error! ");
			return -1;
		}
	}
	return 0;
}
//用iptables 实现对　tc mark的速度限制

int dw_up_ip_mark_set(char *ip,int ipi){

	if(iptables_do_command("-t mangle -A PREROUTING -s %s -j MARK --set-mark 2%d",ip,ipi)!=0){
		debug(LOG_ERR,"IP PREROUTING MARK error!");
		return -1;
	}
	if(iptables_do_command("-t mangle -A PREROUTING -s %s -j RETURN",ip)!=0){
		debug(LOG_ERR,"IP PREROUTING RETURN error!");
		return -1;
	}
	if(iptables_do_command("-t mangle -A POSTROUTING -s %s -j MARK --set-mark 2%d",ip,ipi)!=0){
		debug(LOG_ERR,"IP POSTROUTING MARK error!");
		return -1;
	}
	if(iptables_do_command("-t mangle -A POSTROUTING -s %s -j RETURN",ip)!=0){
		debug(LOG_ERR,"IP POSTROUTING RETURN error!");
		return -1;
	}
	return 0;
}

//单IP下载限速
char * dw_up_speed_by_ip(cJSON *p)
{
	char *v,*tmp_v;
	char *ip,*dspeed,*uspeed;
	int ipi=0;
	int i=0;
	char *mark;

	if(p == NULL)	return "para is empty";
	if(p->valuestring == NULL)	return "para empty";
	tmp_v = v = p->valuestring;

	while(v!=NULL && *v !='\0'){
		if((tmp_v = strsep(&v,";")) == NULL){
			return "strsep ; error!";
		}
		if((ip = strsep(&tmp_v,"=")) == NULL){
			return "strsep = ip error!";
		}
		if((dspeed = strsep(&tmp_v,":")) == NULL){
			return "strsep : error!";
		}
		uspeed = tmp_v;

		//try to get mark,ipi
		mark = NULL;
		for(i=0;ip[i] !='\0';i++){
			if(ip[i]=='.') mark = &ip[i];
		}
		if(mark == NULL)
			return "get ipi fail, ip format error!";
		if((mark = mark+1) == NULL)
			return "get ipi fail, ip format error!";
		ipi = atoi(mark);


		if(dw_up_ip_speed_set(ipi,dspeed,uspeed) ==-1)
			return "dw_up_ip_speed_set tc set run error!";

		if(dw_up_ip_mark_set(ip,ipi) == -1)
			return "dw_up_ip_mark_set iptables run error!";

	}
	return "OK";
}




/*
 * 用于流量有限的时候
 * 禁止上网，除服务器外*/

char * disable_net_except_eotu(cJSON *p)
{
	char *server_ip = config_get_config()->auth_servers->last_ip;

	iptables_do_command("-F");
	iptables_do_command("-X");
	iptables_do_command("-Z");
	iptables_do_command("-P INPUT DROP");
	iptables_do_command("-P FORWARD DROP");
	iptables_do_command("-P OUTPUT DROP");
	iptables_do_command("-I INPUT -p all -s %s -j ACCEPT" , server_ip);
	iptables_do_command("-I INPUT -p all -d %s -j ACCEPT" , server_ip);
	iptables_do_command("-I OUTPUT -p all -s %s -j ACCEPT" , server_ip);
	iptables_do_command("-I OUTPUT -p all -d %s -j ACCEPT" , server_ip);
	iptables_do_command("-I FORWARD -p all -s %s -j ACCEPT" , server_ip);
	iptables_do_command("-I FORWARD -p all -d %s -j ACCEPT" ,server_ip);
	return "OK";
}

/*
//网站白名单MAC设置
char * net_whitelist_mac_set(para_struct_t * p)
{
	iptables_do_command("-t mangle -A " CHAIN_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d",tmp_p->value, FW_MARK_KNOWN);
	return "NOUSE";
}

//网站黑名单MAC设置
char * net_blacklist_mac_set(cJSON *p)
{
iptables_do_command("-t mangle -A %s -m mac --mac-source %s -j	MARK --set-mark %d",CHAIN_UNTRUSTED ,  url, FW_MARK_KNOWN);
	return "NOUSE";
}
*/
//网站白名单域名URL设置
char * net_whitelist_url_set(cJSON *p)
{
	char *tmps ,*url;

	if(NULL == p)
		return "JSON EMPTY";
	if(NULL == p->valuestring)
		return "PARA EMPTY";

	config_get_config()->global_white = strdup(p->valuestring);

	tmps = p->valuestring;

	while(*tmps !='\0' && tmps !=NULL){
		url = strsep(&tmps,";");
		if(url == NULL) break;
		if(iptables_do_command("-t nat -A " CHAIN_GLOBAL " -d %s -p tcp -j ACCEPT",url) != 0){
			return "nat set error!";
		}
		if(iptables_do_command("-t filter -A " CHAIN_GLOBAL " -d %s -p tcp -j ACCEPT",url)!=0){
			return "filter set error!";
		}
	}

	return "OK";
}

//网站黑名单域名URL设置
char * net_blacklist_url_set(cJSON *p)
{

	char *tmps ,*url;

	if(NULL == p)
		return "JSON EMPTY";
	if(NULL == p->valuestring)
		return "PARA EMPTY";

	config_get_config()->global_black = strdup(p->valuestring);

	tmps = p->valuestring;

	while(*tmps !='\0' && tmps !=NULL){
		url = strsep(&tmps,";");
		if(url == NULL) break;
		if(iptables_do_command("-t filter -A " CHAIN_GLOBAL " -d %s -p tcp -j REJECT",url) != 0){
			return "filter set error!";
		}
	}

	return "OK";
}

char *set_remind_sms_content(cJSON *p)
{
	if(NULL == p)
		return "JSON EMPTY";
	if(NULL == p->valuestring)
		return "PARA EMPTY";
	config_get_config()->remind_sms_content = strdup(p->valuestring);
	return "OK";
}

char * message_thread_handle(char *phone,char *message,char *smsc)
{
	//判断手机号是否合法
	safe_asprintf(&phone,"86%s",phone);
	if(strlen(phone) !=13) return "PARA phone error";
	//发送短信
	return sms_tool(smsc,phone,message);
}


char * send_message(cJSON *p)
{
	if(p ==NULL)
		return "FAIL0";
	else if(NULL == p->string)
		return "NOSMS";

	char *res=NULL,*phone,*message=NULL,*c;




	if(config_get_config()->is_sms_work== 0){
		debug(LOG_ERR,"send sms stop for error [%s]",config_get_config()->sms_err_info);
		safe_asprintf(&res,"ERROR(%s)",config_get_config()->sms_err_info);
		return res;
	}
        
	c = safe_strdup(p->valuestring);
    phone = c;
    for(;*c!='\0';c++){
    	if(*c==':'){
    		*c = '\0';
    		c++;
    		break;
        }
    }
    if((message = c) == NULL)
        return "no message to send";
        
	return message_thread_handle(phone,message,config_get_config()->smsc);
}


char *rsync_file(cJSON *p)
{
//command	rsync -vzrtopg --delete --password-file=/etc/rsync.pwd  113.195.207.216::www ./twofiles/
	char * cmd,*dest,*src;
        
	if(config_get_config()->sync_server == NULL)
		return NULL ;
	if(NULL == p || p->valuestring == NULL)
            return "paras is NULL";
        
        dest=safe_strdup(p->valuestring);
        if(NULL != dest)
                src = strsep(&dest,":");
        else
                return "para : error";
        
        safe_asprintf(&cmd,"rsync -vzrtopg --delete --password-file=/etc/rsync.pwd  %s::%s %s",
        		config_get_config()->sync_server,src,dest);
	command_run_thread(cmd);
        
	return "ongoing";
}

/*安装软件*/
char * opkg_install_ipk(cJSON *p)
{
	char *cmd;

	safe_asprintf(&cmd, "opkg install %s", p->valuestring);
	debug(LOG_NOTICE,"%s",cmd);
	int rc;
	rc = excute_cmd(cmd);

	if(rc == 0){
		config_get_config()->bootv = 1;
		debug(LOG_INFO,"%s run OK",cmd);
		return "OK";
	}
	else
		return "fail";


}
/*更新固件*/
char * sysupgrade_firmware(cJSON *p)
{
	if(!p)
		return "para is NULl,ERROR!";
	return upgrade_firmware(p);

}





/*
 * wifi 无线 AP模式设置
 *
 * ssid:eotu_test;encry:psk;pwd:123;
 * uci set wireless.radio0.power=%d power功能去掉
 * */

char * wifi_ap_mode_set(cJSON *p)
{
	if(p==NULL)
		return "unable!";
	if(p->valuestring == NULL)
		return "para is NULL";

    char *v,*token;
    char *key,*value;

    v = p->valuestring;

    //有一个失败就退出吧～～
    while(*v!='\0'){
    	token = strsep(&v,";");
    	key = strsep(&token,":");
    	value = token;
    	if(wifi_ap_member_set(key,value)==-1)
    		return "FAIL";
    }

    return "OK";


}

/*
 * wifi 无线 ＳＴＡ模式设置
 *
 * ssid=eotu_test;encryption=psk2;bssid=14:75:90:E2:77:88;key=guosheng123;
 * uci set wireless.radio0.power=%d power功能去掉
 * */
char * wifi_sta_mode_set(cJSON *p)
{
	if(p==NULL)
		return "unable!";
	if(p->valuestring == NULL)
		return "para is NULL";

    char *v,*token;
    char *key,*value;

    v = p->valuestring;
    //有一个失败就退出吧～～
    while(*v!='\0'){
    	token = strsep(&v,";");
    	key = strsep(&token,"=");
    	value = token;
    	if(wifi_sta_member_set(key,value)==-1)
    		return "FAIL";
    }
    return "OK";
}

/**************************************
*	system restart  
***************************************/


char *system_restart(cJSON *p)
{
	config_struct_to_json();
    save_config_json_to_file(WIFIDOG_JSON_NEW);
    debug(LOG_NOTICE,"Run command system reboot!");
	excute_cmd("reboot");
	return "system_restart";

}
/**************************************
*	network restart 
***************************************/

char *network_restart(cJSON *p)
{
	config_struct_to_json();
    save_config_json_to_file(WIFIDOG_JSON_NEW);
    debug(LOG_NOTICE,"Run command Network restart");
	excute_cmd("/etc/init.d/network restart");
	return "network_restart";

}

/**************************************
*	eotu restart 
***************************************/

static size_t
send_request(int sock, const char *request)
{
    size_t len;
    ssize_t written;

    len = 0;
    while (len != strlen(request)) {
        written = write(sock, (request + len), strlen(request) - len);
        if (written == -1) {
            fprintf(stderr, "Write to eotuwifi failed: %s\n", strerror(errno));
            exit(1);
        }
        len += (size_t) written;
    }

    return len;
}


static int
connect_to_server(const char *sock_name)
{
    int sock;
    struct sockaddr_un sa_un;

    /* Connect to socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "wdctl: could not get socket (Error: %s)\n", strerror(errno));
        exit(1);
    }
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

    if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
        fprintf(stderr, "wdctl: eotuwifi probably not started (Error: %s)\n", strerror(errno));
        exit(1);
    }

    return sock;
}


char * dlna_restart(cJSON *p){



	return "on going";

}


char * wdctl_eotu_restart(cJSON *p)
{
    int sock;
    char buffer[4096];
    char request[16];
    ssize_t len;
	
    /*save config before restart*/
    config_struct_to_json();
    save_config_json_to_file(WIFIDOG_JSON_NEW);


    sock = connect_to_server(config_get_config()->wdctl_sock);
    strncpy(request, "restart\r\n\r\n", 10);
    debug(LOG_NOTICE,"send signal to restart");
    send_request(sock, request);

    while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        fprintf(stdout, "%s", buffer);
    }

    shutdown(sock, 2);
    close(sock);

	return "wdctl_eotu_restart sock send restart Now";
}


char *wdctl_eotu_stop(cJSON *p)
{

    config_struct_to_json();
    save_config_json_to_file(WIFIDOG_JSON_NEW);
    debug(LOG_NOTICE,"save config , then self kill");
	wdctl_stop(1);
	return "unexcept return after wdctl_eotu_stop";
}

