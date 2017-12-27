
#ifndef GSCLIENT_HANDLE_H
#define GSCLIENT_HANDLE_H

#include "mcJSON.h"

/*路由器SET相关导入设置*/
cJSON * router_set( cJSON * set_j);


/*获取IPMAC清单*/
cJSON * get_ipmac_list_json();

void thread_router_set_and_request(cJSON *server_json);

cJSON * client_set_and_request(cJSON *server_json);

void eotu_set_handle(httpd * webserver, request * r);

void niuniu_handle(httpd * webserver, request * r);

char * method_of_boot_handle(char *method,cJSON *paras_j);

void boot_handle();

#endif
