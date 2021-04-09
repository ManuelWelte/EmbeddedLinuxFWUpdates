
do_deploy_append() {
	export CONFIG_FILE=${DEPLOYDIR}/${BOOTFILES_DIR_NAME}/config.txt 
	echo "# Enable UART (fixes bug)" >>${CONFIG_FILE}
	echo "enable_uart=1" >>${CONFIG_FILE}
	echo "# Start RPI without monitor" >>${CONFIG_FILE}
	echo "hdmi_force_hotplug=1" >>${CONFIG_FILE}
}
do_install_append() {
	install -d ${D}/data
}

