FILESEXTRAPATHS_prepend := "${THISDIR}/files:"

# enable bootlimit
SRC_URI_append_raspberrypi4 = " file://0001-Enable-Bootlimit.patch"

#DEPENDS_append_rpi = " u-boot-default-script"
