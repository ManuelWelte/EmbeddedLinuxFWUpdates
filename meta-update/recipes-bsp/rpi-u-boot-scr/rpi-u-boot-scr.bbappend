FILESEXTRAPATHS_prepend := "${THISDIR}/files:" 
SRC_URI += "file://boot.cmd.in.new"
do_compile() {
    sed -e 's/@@KERNEL_IMAGETYPE@@/${KERNEL_IMAGETYPE}/' \
        -e 's/@@KERNEL_BOOTCMD@@/${KERNEL_BOOTCMD}/' \
        "${WORKDIR}/boot.cmd.in.new" > "${WORKDIR}/boot.cmd"
    mkimage -A arm -T script -C none -n "Boot script" -d "${WORKDIR}/boot.cmd" boot.scr
}