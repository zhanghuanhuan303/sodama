# OpenWrt 包（预编译产物版）：sodama —— Rust eBPF 透明代理网关
#
# 用法（OpenWrt SDK / buildroot）：
#   1) 用仓库脚本准备当前架构的产物：
#        lab/build-openwrt.sh --sdk-payload <此目录>            # 交互选择架构
#      或：lab/build-openwrt.sh --arch aarch64 --sdk-payload install/openwrt
#      产物会放到 install/openwrt/prebuilt/{sodama,sodama-ebpf}
#   2) 在 SDK 里：
#        cp -r install/openwrt <sdk>/package/sodama && cd <sdk>
#        make package/sodama/compile V=s
#        # 产出 bin/packages/<arch>/base/sodama_<ver>_<arch>.ipk
#   3) 目标机：opkg install sodama_*.ipk
#        uci set sodama.main.enabled=1
#        cp /usr/share/sodama/config.example.dae /etc/sodama/config.dae  # 改成你的节点
#        /etc/init.d/sodama start
#
# 说明：本 Makefile 安装预编译产物（musl 静态、由 lab/build-openwrt.sh 产出），
# 不做源码交叉编译；如需在 buildroot 里从源码构建，见 docs/openwrt.md 的说明。

include $(TOPDIR)/rules.mk

PKG_NAME:=sodama
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=sodama <https://github.com/zhanghuanhuan303/dae-rust>

include $(INCLUDE_DIR)/package.mk

define Package/sodama
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Rust eBPF transparent proxy gateway (dae rewrite)
  URL:=https://github.com/zhanghuanhuan303/dae-rust
  # ip-full：netns/neigh 需要（busybox ip 不支持）；kmod-veth：控制面对 veth
  DEPENDS:=+ip-full +kmod-veth
endef

define Package/sodama/description
  sodama 是 dae 的全 Rust 重写：tc/eBPF 分流 + 透明代理（VLESS/VMess/Trojan/SS/Hysteria2/TUIC…），
  低内存（稳态 ~12MB）、每连接 0 线程（epoll worker 池）。本包为预编译静态 musl 产物。
endef

# 预编译产物目录（由 lab/build-openwrt.sh --sdk-payload 填充）
define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/prebuilt/sodama $(PKG_BUILD_DIR)/
	$(CP) $(CURDIR)/prebuilt/sodama-ebpf $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/sodama/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/lib/sodama $(1)/usr/share/sodama
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sodama $(1)/usr/bin/sodama
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/sodama-ebpf $(1)/usr/lib/sodama/sodama-ebpf
	$(INSTALL_BIN) $(CURDIR)/files/sodama-datapath $(1)/usr/lib/sodama/sodama-datapath
	$(INSTALL_BIN) $(CURDIR)/files/sodama.init $(1)/etc/init.d/sodama
	$(INSTALL_CONF) $(CURDIR)/files/sodama.config $(1)/etc/config/sodama
	$(INSTALL_DATA) $(CURDIR)/files/sodama.example.dae $(1)/usr/share/sodama/config.example.dae
endef

define Package/sodama/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
mkdir -p /etc/sodama
[ -f /etc/sodama/config.dae ] || cp /usr/share/sodama/config.example.dae /etc/sodama/config.dae
exit 0
endef

$(eval $(call BuildPackage,sodama))
