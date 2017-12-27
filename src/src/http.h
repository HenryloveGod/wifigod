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
/** @file http.h
    @brief HTTP IO functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _HTTP_H_
#define _HTTP_H_

#include "httpd.h"

/**@brief Callback for libhttpd, main entry point for captive portal */
void http_callback_404(httpd *, request *, int);
/**@brief Callback for libhttpd */
void http_callback_wifidog(httpd *, request *);
/**@brief Callback for libhttpd */
void http_callback_about(httpd *, request *);
/**@brief Callback for libhttpd */
void http_callback_status(httpd *, request *);
/**@brief Callback for libhttpd, main entry point post login for auth confirmation */
void http_callback_auth(httpd *, request *);
/**@brief Callback for libhttpd, disconnect user from network */
void http_callback_disconnect(httpd *, request *);

/** @brief Sends a HTML page to web browser */
void send_http_page(request *, const char *, const char* );

void send_http_page_direct(request *, char *);

/** @brief Sends a redirect to the web browser */
void http_send_redirect(request *, const char *, const char *);
/** @brief Convenience function to redirect the web browser to the authe server */
void http_send_redirect_to_auth(request *, const char *, const char *);
//>>> liudf added 20160104
void http_send_js_redirect(request *, const char *); 
void http_send_apple_redirect(request *, const char *);
void http_relay_wisper(request *);

void http_callback_temporary_pass(httpd *, request *);
//<<< liudf added end

//>>>>>>>>>>>>>>>>By Denglei
/* ＡＰＰ获取路由器频道文件清单*/
void http_eotu_avlist(httpd * webserver, request * r);
/** for EOTU PORTAL
 * 优途浏览器／非优途浏览器，统一跳转处理
 * */
void
http_send_redirect_eotu_login_handle(request * r);
/*app login api 入口 2017*/
void http_eotu_checkuid(httpd * webserver, request * r);

/**
 * 放行接口
 * */
void http_eotu_auth(httpd * webserver, request * r);
/****
 * wifiguid 用户指南接口
 * ***/
void http_eotu_guid(httpd * webserver, request * r);


#endif /* _HTTP_H_ */
