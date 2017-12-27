#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "gsbf.h"
#include "gstmpconf.h"
#include "safe.h"
#include "debug.h"
#include "util.h"


FILE *REGULAR_TMP_LOG_STREAM,*REGULAR_ERR_LOG_STREAM;
FILE *LISTEN_TMP_LOG_STREAM,*LISTEN_ERR_LOG_STREAM;
FILE *REGDB_TMP_LOG_STREAM,*REGDB_ERR_LOG_STREAM;

char *NONE;		//检测到NONE，将不输出LOG
char *STDERR ;		//输出到stderr
char *TMPLOG ;		//输出到TMPLOG
char *TMPLOG_P;		//输出到TMPLOG，并打印到STDERR
char *ERRLOG_P ;	//输出到ERRLOG，并打印到STDERR
char *ERRLOG ;		//输出到ERRLOG
char *DEBUG	;		//若设置为NONE，则不输出,默认设置成TMPLOG_P，方便调试


/******************************************
*
*	save eotuwifi.conf to eotuwifi.conf.last
*
********************************************/




/*
*获取当前时间
*/
char * current_time()
{
	time_t nowtime;
	struct tm *local;
	static char time_mark[80];
	
	nowtime = time(NULL);  
	local=localtime(&nowtime);  

	strftime(time_mark,80,"%Y%m%d_%H%M%S",local);
	return time_mark;
}


unsigned long get_current_time()
{
    struct  timeval    tv;

    gettimeofday(&tv,NULL);

    return tv.tv_sec;

}

/*
*	输出由三个方向
*	stderr
*	TMPLOG
*	ERRLOG
*	根据level_name输出一个或多个方向
×	其中level_name赋值为NONE后，可以停止输出。
*/
int log_i(char *err,char *level_name,const char *file,const char *func,const int line,FILE *TMP_LOG,FILE *ERR_LOG)
{	
	if (0 == strcmp(level_name,"NONE"))
		return 0;
	
	char *time_mark;
	
	time_mark = current_time();
	
	if (0 == strcmp(level_name,"STDERR"))
	{
		fprintf(stderr, "[%s] %s %s(:%d) %s\r\n",time_mark,file,func,line,err);
		return 0;
	}
	if (0 == strcmp(level_name,"TMPLOG"))
	{
		fprintf(TMP_LOG, "[%s] %s %s(:%d) %s\r\n",time_mark,file,func,line,err);
		fflush(TMP_LOG);	
		return 0;
	}	
	if (0 == strcmp(level_name,"TMPLOG_P"))
	{
		fprintf(TMP_LOG, "[%s] %s %s(:%d) %s\r\n",time_mark,file,func,line,err);
		fprintf(stderr,"[%s] %s %s(:%d) %s\r\n",time_mark,file,func,line,err);
		fflush(TMP_LOG);
		return 0;
	}	
	if (0 == strcmp(level_name,"ERRLOG_P"))
	{
		fprintf(stderr,"[%s] %s %s (:%d) %s\r\n",time_mark,file,func,line,err);	
		fprintf(TMP_LOG,"[%s] %s %s (:%d) %s\r\n",time_mark,file,func,line,err);	
		fprintf(ERR_LOG,"[%s] %s %s (:%d) %s\r\n",time_mark,file,func,line,err);	
		fflush(TMP_LOG);
		fflush(ERR_LOG);
		return 0;
	}
	fprintf( stderr, "[%s] %s %s (:%d) %s\r\n",time_mark,file,func,line,err);
	fprintf( TMP_LOG, "[%s] %s %s (:%d) %s\r\n",time_mark,file,func,line,err);	
	fprintf( ERR_LOG, "[%s] %s %s (:%d) %s\r\n",time_mark,file,func,line,err);
	fflush(TMP_LOG);
	fflush(ERR_LOG);
	
	return 0;
}




/******一个进程对应一个LOG文件，分别为
*	log_regdb
*	log_listen
*	log_regular
*	使用时，先进行初始化，用完后，再关闭
*/

int log_para_init()
{
	NONE = "NONE";				//检测到NONE，将不输出LOG
	STDERR ="STDERR";
	TMPLOG ="TMPLOG";
	TMPLOG_P = "TMPLOG_P";
	ERRLOG_P ="ERRLOG_P";
	ERRLOG ="ERRLOG";
	DEBUG="TMPLOG_P";			//调试输出，可以改为NONE不输出
	return 0;
}

int log_regdb_initial()
{
	if (REGDB_TMP_LOG_STREAM == NULL)
		REGDB_TMP_LOG_STREAM = fopen("./log/regdb_tmp.log", "a");
	if (REGDB_ERR_LOG_STREAM == NULL)
		REGDB_ERR_LOG_STREAM = fopen("./log/regdb_err.log", "a");
	
	return 0;
}

int log_listen_initial()
{
	if (LISTEN_TMP_LOG_STREAM == NULL)
		LISTEN_TMP_LOG_STREAM = fopen("./log/listen_tmp.log", "a");
	if (LISTEN_ERR_LOG_STREAM == NULL)
		LISTEN_ERR_LOG_STREAM = fopen("./log/listen_err.log", "a");
	
	return 0;
}

int log_regular_initial()
{
	if (REGULAR_TMP_LOG_STREAM == NULL)
		REGULAR_TMP_LOG_STREAM = fopen("./log/regular_tmp.log", "a");
	if (REGULAR_ERR_LOG_STREAM == NULL)
		REGULAR_ERR_LOG_STREAM = fopen("./log/regular_err.log", "a");
	
	return 0;
}

int log_regdb_close()
{
	if (REGDB_TMP_LOG_STREAM)
		fclose(REGDB_TMP_LOG_STREAM);
	if (REGDB_ERR_LOG_STREAM)
		fclose(REGDB_ERR_LOG_STREAM);	
	return 0;
}

int log_regular_close()
{
	if (REGULAR_TMP_LOG_STREAM)
		fclose(REGULAR_TMP_LOG_STREAM);
	if (REGULAR_ERR_LOG_STREAM)
		fclose(REGULAR_ERR_LOG_STREAM);	
	return 0;
}

int log_listen_close()
{
	if (LISTEN_TMP_LOG_STREAM)
		fclose(LISTEN_TMP_LOG_STREAM);
	if (LISTEN_ERR_LOG_STREAM)
		fclose(LISTEN_ERR_LOG_STREAM);	
	return 0;
}

int _log_regular(char *err,char *level_name,const char *file,const char *func,const int line)
{	

	log_regular_initial();
	log_i(err,level_name,file,func,line,REGULAR_TMP_LOG_STREAM,REGULAR_ERR_LOG_STREAM);
	return 0;
}

int _log_listen(char *err,char *level_name,const char *file,const char *func,const int line)
{	

	log_listen_initial();
	log_i(err,level_name,file,func,line,LISTEN_TMP_LOG_STREAM,LISTEN_ERR_LOG_STREAM);
	return 0;
}

int _log_regdb(char *err,char *level_name,const char *file,const char *func,const int line)
{	
	log_regdb_initial();
	log_i(err,level_name,file,func,line,REGDB_TMP_LOG_STREAM,REGDB_ERR_LOG_STREAM);
	return 0;
}


/*
*	读取整个文件到字符串中
*/
char *read_file_to_string(char *filepath)
{
    FILE * pFile;
    long lSize;  
    char * buffer,tmp[1024];


    if(access(filepath,F_OK) !=0){
    	debug(LOG_ERR, "Could not find the FILE[%s]", filepath);
    	return NULL;
    }

    /* 若要一个byte不漏地读入整个文件，只能采用二进制方式打开 */   
    pFile = fopen (filepath, "r" );
    if (pFile==NULL)  
    {  
    	debug(LOG_ERR, "Could not open the FILE[%s]", filepath);
        return NULL;  
    }  
  
    /* 获取文件大小 */  
    fseek (pFile , 0 , SEEK_END);  
    lSize = ftell (pFile);  
    rewind (pFile);  
  
    /* 分配内存存储整个文件*/
    buffer = (char*) malloc (sizeof(char)*lSize+2);
    memset(buffer,0,lSize);


    if (buffer == NULL){
        debug(LOG_ERR, "Could not open the FILE[%s]: Memory! ", filepath);
        fclose(pFile);
        return NULL;  
    }  

    int index=0,j=0;
    while(fgets(tmp,1024,pFile) != NULL){
    	j=0;
    	while(tmp[j] != '\0'){
    		buffer[index]=tmp[j];
    		index++;
    		if(index>lSize) break;
    		if(j++ > 1024) break;
    	}
    }
    buffer[index]='\0';

    /* 将文件拷贝到buffer中
    result = fread (buffer,1,lSize,pFile);  
    if (result != lSize)  
    {  
        fputs ("Reading error",stderr);  
        fclose(pFile);
       	return NULL;  
    }  
    */

	fclose(pFile);
	return buffer;

}



/*
*	获取文件大小
*/
unsigned long get_file_size(const char *path)  
{  
    unsigned long filesize = -1;      
    struct stat statbuff;  
    if(stat(path, &statbuff) < 0){  
        return filesize;  
    }else{  
        filesize = statbuff.st_size;  
    }  
    return filesize;  
}  

/*
*	字符串内部替换
*/
char *str_replace(char *orig, char *rep, char *with) {
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep
    int len_with; // length of with
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    if (!orig)
        return NULL;
    if (!rep)
        rep = "";
    len_rep = strlen(rep);
    if (!with)
        with = "";
    len_with = strlen(with);

    ins = orig;
    for (count = 0; NULL != (tmp = strstr(ins, rep)) ; ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}

/*
*	整数转换为字符串
*/
const char *int_to_string(int n)
{
    int len = n==0 ? 1 : floor(log10(labs(n)))+1;
    if (n<0) len++; // room for negative sign '-'

    char	* buf ;
	buf = calloc(sizeof(char), len+1); // +1 for null
    snprintf(buf, len+1, "%ld", (long )n);
    return   buf;
}

/*
*	字符串为空返回none
*/
char *check_str_null_return_none(char *str)
{
	char *none;


	if (str ==NULL){
		none = safe_strdup("");
	}
	else{
		none = safe_strdup(str);
	}
	return none;
}

/*
*	整数为空返回none
*/
int check_int_null_return_zero(int i)
{
	
	if ( i == 0)
		return 0;
	return i;
}



/*
*	分割字符串成一个JSON 列表
*/
cJSON *split_to_json(char *src , char *deli)
{

	cJSON * res_j = cJSON_CreateObject();
	
	
	char * s = strsep(&src, deli);
	int i= 0 ;
	while (s)
	{
		cJSON_AddStringToObject(res_j,int_to_string(i),s);
		s = strsep(&src, deli);
	}

	return res_j;
}


/*
*	从路径中截取文件名
*/
char  *get_file_name_from_path(char *filepath ,char *newpath)
{

	char *f;
	char * s = strsep(&filepath, "/");

	while (s)
	{
		f=s;
		s = strsep(&filepath, "/");	
	}
	char *np;
	for(np=newpath;*np !='\0';*np++);
	char sep = *(np-1);
	if (sep =='/'){
		return str_join(newpath,f);
	}
	else{
		char *n = str_join(newpath,"/");
		return str_join(n,f);
	}
}

/*字符串拼接*/  
char *str_join(char *a, char *b) {  
    char *c = (char *) malloc(strlen(a) + strlen(b) + 1); //局部变量，用malloc申请内存  
    if (c == NULL) exit (1);  
    char *tempc = c; //把首地址存下来  
    while (*a != '\0') {  
        *c++ = *a++;  
    }  
    while ((*c++ = *b++) != '\0') {  
        ;  
    }  
    return tempc;//返回值是局部malloc申请的指针变量，需在函数调用结束后free之  
}  

/*截取部分字符串*/
char* substr(char*str,int start, int end)
{
   int qty = end - start;
   static char stbuf[256];
   strncpy(stbuf, str + start, qty);
   stbuf[qty] = '\0';
   return stbuf;
}


//写入字符串 到文件
int write_str_to_file(char * filestr, char *dstfile_path)
{
    int fd = open(dstfile_path, O_WRONLY , O_CREAT);

    if (fd == -1) {
        debug(LOG_INFO, "Could not open the FILE: '%s', " "exiting...", dstfile_path);
        exit(1);
    }

    int rc =  write(fd,filestr,strlen(filestr));
    if(rc == -1)
    {
        debug(LOG_INFO, "Failed to write[%d] %s; ERROR : %s", rc, dstfile_path, strerror(errno));
        close(fd);
        exit(1);
    }
    close(fd);

    debug(LOG_INFO, "write string to FILE:  %s  --OK! ",dstfile_path);
    return 0;
}


/*从json中获取string number*/
int get_string_from_json(cJSON *src_j,char *member,char **str)
{
	cJSON *tmp_j;
	tmp_j = cJSON_GetObjectItem(src_j, member);
	if (tmp_j){
		*str = tmp_j->valuestring;
		return 0;
	}
	return -1;
}
/*从json中获取string number*/
char* get_string_from_json_by_member(cJSON *src_j,char *member)
{
	cJSON *tmp_j;

	tmp_j = cJSON_GetObjectItem(src_j, member);
	if (tmp_j){
		return tmp_j->valuestring;
	}
	else 
		return NULL;
}


int get_number_from_json(cJSON *src_j,char *member,int *number)
{
	cJSON *tmp_j;
	tmp_j = cJSON_GetObjectItem(src_j, member);
	if (tmp_j){
		*number = tmp_j->valuedouble;
		return 0;
	}
	return -1;
}

int get_number_from_json_by_member(cJSON *src_j,char *member)
{
	cJSON *tmp_j;
	tmp_j = cJSON_GetObjectItem(src_j, member);
	if (tmp_j){
		return tmp_j->valuedouble;
	}
	else
		return 0;
}


/*把some_j 中的成员member中的整数值复制到configmember地址中*/
int set_number_member_to_struct(cJSON *some_j , char *member, int *configmember)
{
    cJSON *tmp_j = cJSON_GetObjectItem(some_j,member);

    if (tmp_j == NULL)
        return -1;
    if(tmp_j->valuedouble){
    	if(tmp_j->valuedouble != *configmember){
    		*configmember = tmp_j->valuedouble;
    		debug(LOG_NOTICE,"config[ %s %d] change to %d ", member,*configmember,tmp_j->valuedouble);
    	}
    }
    return 0;
}

/*把some_j 中的成员member中的整数值复制到configmember地址中*/
int set_long_member_to_struct(cJSON *some_j , char *member, long *configmember)
{
    cJSON *tmp_j = cJSON_GetObjectItem(some_j,member);

    if (tmp_j == NULL)
        return -1;
    if(tmp_j->valuedouble){
    	if(tmp_j->valuedouble != tmp_j->valuedouble){
    		debug(LOG_NOTICE,"config[ %s %d] change to %d ", member,*configmember,tmp_j->valuedouble);
    		*configmember = tmp_j->valuedouble;
    	}
    }
    return 0;
}

/*把some_j 中的成员member中的字符串复制到configmember地址中*/
int set_string_member_to_struct(cJSON *some_j , char *member,char ** configmember)
{
    cJSON *tmp_j = cJSON_GetObjectItem(some_j,member);
    if (tmp_j == NULL)
        return -1;
    if(NULL == configmember)
    	return -1;
    if(NULL == *configmember)
    	*configmember = safe_malloc(sizeof(char *));
    if (configmember !=NULL && NULL != tmp_j->valuestring && strcmp(tmp_j->valuestring,"") != 0){
    	if(strcmp(*configmember , tmp_j->valuestring) !=0 ){
    		debug(LOG_NOTICE,"config[ %s %s] change to %d ", member,tmp_j->valuestring,*configmember);
    		*configmember = safe_strdup(tmp_j->valuestring);
    	}
    }
    return 0;
}


/*设置字符串 到json中*/
int set_string_member_to_json(cJSON *add_j,char *member_name,char * member)
{
	if(NULL ==member)
		return -1;

	if(NULL != cJSON_GetObjectItem(add_j,member_name)){
		cJSON_GetObjectItem(add_j,member_name)->valuestring = safe_strdup(member);
	}else {
        cJSON_AddStringToObject(add_j,member_name,safe_strdup(member));
    }
    return 0;
}
/*设置数据 到json中*/
int set_number_member_to_json(cJSON *add_j,char *member_name,int member)
{
	if(NULL != cJSON_GetObjectItem(add_j,member_name)){
		cJSON_GetObjectItem(add_j,member_name)->valuedouble = member;
		return 0;
	}else
		cJSON_AddNumberToObject(add_j,member_name,member);
    return 0;
}



/*执行shell命令*/

int excute_cmd(char *cmd)
{

	int rc = execute(cmd,0);
    if (rc != 0) {
		debug(LOG_INFO, "failed(%d): %s", rc, cmd);
		//exit(-1);
		return rc;
	}
	else {
		debug(LOG_INFO, "command OK (%d): %s", rc, cmd);
		//exit(0);
		return 0;
    }
}


/*参数分解到链表中*/
para_struct_t * get_para_from_json_list(cJSON *list_j)
{
	char *token;
	para_struct_t *para_p,*tmp_p,*next_p;
	
	cJSON *tmp_para_j;
	int i;
	i=0;
	tmp_p=NULL;
	para_p = safe_malloc(sizeof(para_struct_t));
	bzero(para_p,sizeof(para_struct_t));
	tmp_p=para_p;

	if(!para_p){
		perror("function get_para_j  malloc error! ");
		exit(1);
	}

	while((tmp_para_j=cJSON_GetArrayItem(list_j,i)) != NULL){
		tmp_p->value = tmp_para_j->child->valuestring;
		if (tmp_p->next ==NULL){
			tmp_p->next = malloc(sizeof(para_struct_t));
			bzero(tmp_p->next,sizeof(para_struct_t));		
		}
		tmp_p->prev = tmp_p;
		tmp_p = tmp_p->next;
		
		i=i+1;
		para_p->qty = para_p->qty+1;
	}
	if(!(para_p->value))
		return NULL;

	tmp_p=para_p;

	while(tmp_p){
		if( tmp_p->value == NULL){
				free(next_p->next);
				next_p->next=NULL;
				break;
		}
		next_p=tmp_p;
		tmp_p=tmp_p->next;
	}

	return para_p;
}

/*从字符串中格式化IP地址*/
char *sharp_ip(unsigned int ip)
{

	int a,b,c,d;

	a=ip>>24;
	b=(ip>>16)-(a<<8);
	c=(ip>>8)-((ip>>16)<<8);
	d=ip-((ip>>8)<<8);
	
	char *ipstr=malloc(33);
	
	safe_asprintf(&ipstr,"%u.%u.%u.%u",a,b,c,d);
	
	return ipstr;


}

/*从字符串中格式化MAC地址*/
char *sharp_mac(unsigned char mac[6])
{

	char *m=malloc(18);
	bzero(m,18);

	safe_asprintf(&m,"%x:%x:%x:%x:%x:%x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

	return m;

}


/*从popen中输出到字符串*/
//执行一个shell命令，输出结果逐行存储在reserve中，并返回行数
char *get_popen_str(char *cmd)
{
	char *reserve="";
    FILE *pp =NULL;
    static char tmp[1024];

    if ((pp = popen(cmd, "r"))==NULL) {
        return NULL;
    }

    while (fgets(tmp, sizeof(tmp), pp) != NULL) {
		if(tmp){
			safe_asprintf(&reserve,"%s%s",reserve,tmp);
		}    
	}
    pclose(pp); //关闭管道
    if(strcmp(reserve,"") ==0)
    	return NULL;
    return reserve;
}






/* xsystem.c - system(3) with error messages

   Carl D. Worth

   Copyright (C) 2001 University of Southern California

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
*/



/* Like system(3), but with error messages printed if the fork fails
   or if the child process dies due to an uncaught signal. Also, the
   return value is a bit simpler:

   -1 if there was any problem
   Otherwise, the 8-bit return value of the program ala WEXITSTATUS
   as defined in <sys/wait.h>.
*/
int
xsystem(const char *argv[])
{
	int status;
	pid_t pid;

	pid = safe_fork();

	switch (pid) {
	case -1:
		debug(LOG_DEBUG, "%s: fork", argv[0]);
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char*const*)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}

	if (waitpid(pid, &status, 0) == -1) {
		debug(LOG_DEBUG, "%s: waitpid", argv[0]);
		return -1;
	}

	if (WIFSIGNALED(status)) {
		debug(LOG_DEBUG, "%s: Child killed by signal %d.\n",
			argv[0], WTERMSIG(status));
		return -1;
	}

	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		debug(LOG_DEBUG, "%s: Your system is broken: got status %d "
			"from waitpid.\n", argv[0], status);
		return -1;
	}

	return WEXITSTATUS(status);
}

/*执行命令后返回输出*/
char *cmd_popen_return_string(char *cmd)
{
	char buf[1024];
	char *res=NULL;
	FILE *f;
	bzero(buf,1024);

	if(!cmd)
		return "para is NULL,Error!";	
	if( (f = popen(cmd, "r")) == NULL ){
		printf("popen() error!/n");
		return strerror(errno);
	}
	while(fgets(buf, sizeof (buf), f)){
		if(res ==NULL)
			res="";
		safe_asprintf(&res,"%s%s",res,buf);
	}
	pclose(f);
	return res;
}

/**
 * Parse possiblemac to see if it is valid MAC address format */
int check_mac_format(char *possiblemac)
{
    char hex2[3];
    return
        sscanf(possiblemac,"%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
               hex2, hex2, hex2, hex2, hex2, hex2) == 6;
}
char *get_gw_interface()
{
	char *res;
	res = NULL;
	res = get_popen_str("ifconfig |grep br-lan");
	if(NULL != res)
		return "br-lan";
	return "enp2s0";
}

