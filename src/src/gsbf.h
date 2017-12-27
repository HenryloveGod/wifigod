#ifndef GSBF_H
#define GSBF_H
#include "mcJSON.h"

typedef struct para_struct{
	char *value;
	int	qty;
	struct para_struct *next,*prev;
}para_struct_t;



char * current_time();
/**	字符串内部替换*/
char *str_replace(char *orig, char *rep, char *with) ;

unsigned long get_current_time();

char *str_join(char *a, char *b);

cJSON *split_to_json(char *src , char *deli);

const char *int_to_string(int n);

char *check_str_null_return_none(char *str);

unsigned long get_file_size(const char *path);

char *read_file_to_string(char *filepath);

int write_str_to_file(char * filestr, char *dstfile_path);

/*从json中获取string number*/
int get_string_from_json(cJSON *src_j,char *member,char **str);
int get_number_from_json(cJSON *src_j,char *member,int *number);
char* get_string_from_json_by_member(cJSON *src_j,char *member);
int get_number_from_json_by_member(cJSON *src_j,char *member);

/*把some_j 中的member值赋值给configmember*/
int set_number_member_to_struct(cJSON *some_j , char *member, int *configmember);
int set_string_member_to_struct(cJSON *some_j , char *member,char ** configmember);

int set_string_member_to_json(cJSON *add_j,char *member_name,char * member);
int set_number_member_to_json(cJSON *add_j,char *member_name,int member);

/*
*	从路径中截取文件名
*/
char  *get_file_name_from_path(char *filepath ,char *newpath);

/*执行shell命令*/
int excute_cmd(char *cmd);

/*参数分解到链表中*/
para_struct_t * get_para_from_json_list(cJSON *list_j);
/*参数分解到链表中*/
para_struct_t * get_para_j(cJSON *p);

/*执行命令后返回输出*/
char *cmd_popen_return_string(char *cmd);


/*从popen中输出到字符串*/
//执行一个shell命令，输出结果逐行存储在reserve中，并返回行数
char *get_popen_str(char *cmd);

int set_long_member_to_struct(cJSON *some_j , char *member, long *configmember);


int check_mac_format(char *possiblemac);
char *get_gw_interface();


#endif
