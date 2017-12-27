#ifndef GSCLIENT_REQUEST_H
#define GSCLIENT_REQUEST_H

#include "mcJSON.h"

char *get_sim_info(cJSON *);
// 获取IP信息清单
char *get_users_info_online(cJSON *p);
char *get_version(cJSON *p);

//重新返回mission_code值
char *set_mission_code(cJSON *p);
/*扫描周边wifi热点*/
char * iwinfo_wlan0_scan(cJSON *p);
char * get_asset_info(cJSON *p);
char * get_eotuwifi_config_json(cJSON *p);
char * get_popen_within_json(cJSON *p);
char * sys_upgrade(cJSON *p);
char *cmp_time(cJSON *p);
cJSON *get_client_list(cJSON *p);
char *get_sim_gps_info(cJSON *p);

char *get_sys_info(cJSON *p);

#endif
