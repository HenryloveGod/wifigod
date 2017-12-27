
#ifndef GSCLIENT_SET_H
#define GSCLIENT_SET_H

#include "mcJSON.h"
#include "gsbf.h"

/**	下载之后检测md5值
	cmd = p->value;
	md5 = p->next->value;
	filename = p->next->next->value;
*/

//基础设置
char *router_base_set(cJSON *p);
//网站白名单域名URL设置
char * net_whitelist_url_set(cJSON *p);
//网站黑名单域名URL设置
char * net_blacklist_url_set(cJSON *p);

// 发送短信
char * send_message(cJSON *p);

/*上传下载文件 */
char * download_file_thread(cJSON *p);
/* 用rsync同步文件*/
char *rsync_file(cJSON *p);
/*安装软件*/
char * opkg_install_ipk(cJSON *p);
/*更新固件*/
char * sysupgrade_firmware(cJSON *p);
/*wifi 无线 AP模式设置*/
char * wifi_ap_mode_set(cJSON *p);
/*wifi 无线 STA模式设置*/
char * wifi_sta_mode_set(cJSON *p);

/*system restart **/
char *system_restart(cJSON *p);

/*network restart */
char *network_restart(cJSON *p);
/*eotu restart */
char * wdctl_eotu_restart(cJSON *p);
/*eotu stop */
char *wdctl_eotu_stop(cJSON *p);

char *set_remind_sms_content(cJSON *p);

/*
 *	@p	参数定义：d，下载，Ｕ，上传
 *	d:192.168.10.167;100&s:192.101.1.2;12&
 *
 * */
//单IP下载限速
char * dw_up_speed_by_ip(cJSON *p);
/*
 * 整体下载上传限速
 *	@参数	aaaa;bbbbb	aaaa下载，bbbbb上传
 * */
char * dw_up_speed(cJSON *p);


char *internet_config_string_set(cJSON *p);
char *internet_config_int_set(cJSON *p);
char *router_config_int_set(cJSON *p);
char *router_config_string_set(cJSON *p);

char * set_psswd(cJSON *p);

//流量有限情况下，只允许路由器访问优途网页
char * disable_net_except_eotu(cJSON *p);
char * dlna_restart(cJSON *p);


#endif
