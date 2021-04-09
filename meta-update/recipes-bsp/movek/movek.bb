#TODO: Umbennen (tut mehr als Kernel-Image zu relokalisieren)
DESCRIPTION = "move kernel to /boot dir of rootfs"
LICENSE = "MIT"

S = "${WORKDIR}"

do_install() {
    install -d ${D}/boot/kernelimg
    install -m 755 ${TMPDIR}/deploy/images/raspberrypi4/uImage ${D}/boot/kernelimg
    install -d ${D}/data
}
FILES_${PN} = "/boot/kernelimg /data"


