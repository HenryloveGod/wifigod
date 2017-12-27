include $(TOPDIR)/rules.mk

PKG_NAME:=eotuapwifi
PKG_VERSION:=0.0.171212
PKG_RELEASE=1

PKG_MAINTAINER:=Henry
PKG_LICENSE_FILES:=COPYING


PKG_INSTALL:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)/

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk




define Package/$(PKG_NAME)
  SUBMENU:=Captive Portals
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+zlib +iptables-mod-extra +iptables-mod-ipopt +kmod-ipt-nat +iptables-mod-nat-extra \
           +libpthread +libopenssl +@OPENSSL_WITH_EC +@OPENSSL_WITH_DEPRECATED +@OPENSSL_WITH_PSK +libjson-c +ipset +libip4tc +libevent2 +libevent2-openssl \
		   +fping +libmosquitto +libuci
  TITLE:=Apfree's wireless captive portal solution

endef

define Package/$(PKG_NAME)/description
	The ApFree Wifidog project is a complete and embeddable captive
	portal solution for wireless community groups or individuals
	who wish to open a free Hotspot while still preventing abuse
	of their Internet connection.
    It's enhanced wifidog
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/*  $(PKG_BUILD_DIR)

endef



define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/eotu
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wifidog $(1)/usr/bin/$(PKG_NAME)
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wdctl $(1)/usr/bin/apwdctl
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libhttpd.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/wdping $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-msg.html $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-redir.html $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-redir.html.front $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-redir.html.rear $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/authserver-offline.html $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/internet-offline.html $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog.conf $(1)/etc/wifidog.conf
	$(INSTALL_DATA) /etc/eotu/wifidog.json $(1)/etc/eotu/wifidog.json
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/wifidog.init $(1)/etc/init.d/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/etc/config
	$(CP) ./files/wifidog.conf $(1)/etc/config/wifidog
	$(CP) ./files/apfree.* $(1)/etc/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
