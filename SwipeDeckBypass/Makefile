ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless
INSTALL_TARGET_PROCESSES = SpringBoard Preferences

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SwipeDeckBypass
SwipeDeckBypass_FILES = Tweak.xm
SwipeDeckBypass_FRAMEWORKS = Foundation Security
SwipeDeckBypass_PRIVATE_FRAMEWORKS = Security
SwipeDeckBypass_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
SwipeDeckBypass_LDFLAGS = -undefined dynamic_lookup

include $(THEOS_MAKE_PATH)/tweak.mk
after-install::
	install.exec "sbreload"
