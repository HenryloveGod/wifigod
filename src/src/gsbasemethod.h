
#ifndef GSBASEMETHOD_H
#define GSBASEMETHOD_H

#include "mcJSON.h"
#include "gstmpconf.h"

char *get_router_id();
char *get_router_sign();
char *get_router_key();
char *get_ver();

unsigned long int get_sys_uptime();
unsigned int get_sys_memfree();
float get_sys_load();
char *get_firmware_version();
int save_time_to_config_j(cJSON *config_j,char *member,char *string);
cJSON *get_status_j();
void get_ping_key_id_info(cJSON *j);
void get_ping_router_info(cJSON *p);

char *get_portal_url();
int set_string_ajson_to_bjson(cJSON *a_j,char *amember,cJSON *b_j,char *bmember);

void check_gsconfig_with_system();
char *get_dongle_imei();
/*获取毫秒级时间*/
char *get_nano_second();
cJSON *get_sms_ping_j();
/*创建新进程运行cmd*/
char * command_run_thread(char *p);

char *get_http_res(int sockfd,char *request );

char *get_new_sign_by_id_gwid_time(long time);

int wifi_ap_member_set(char *member,char *value);
int wifi_sta_member_set(char *member,char *value);

int wifi_ap_commit_apply();
/*更新固件*/
char * upgrade_firmware(cJSON *p);

char *uci_commit(char *config);

char *get_string_md5(char *str);

//获取文件清单
cJSON *get_document_dir(char * path);

/*任务数据格式 method-id eg: portal=52*/
char *get_method_name(char *method_id);


#endif
