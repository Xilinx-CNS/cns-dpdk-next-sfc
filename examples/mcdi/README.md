# Applications using MCDI library for MCDI transport, mcdi commands encode and decode

## About
This example contains
1. Initialization application - dpdk-mcdi_init
	- An init time applicaton which creates, destroys the rpmsg end points.
	- This application accepts one arguement as input.Pass "0" for destroying end points and "1" for creating end points.
2. Sample application - dpdk-mcdi_test
	- This application uses MCDI library and performs send, receive of MCDI messages.

## Compiling
Applications will cross compile for AARCH64. Ubuntu gcc-aarch64-linux-gnu toolchain needs to be installed.
Following commands will compile dpdk-mcdi_test and dpdk-mcdi_init, applications will be found at arm64-build/examples/.
~~~
$ cd $DPDK_PATH
$ meson arm64-build --cross-file config/arm/arm64_cdx_linux_gcc -Dexamples=mcdi/mcdi_test,mcdi/mcdi_init
$ ninja -C arm64-build
~~~

## Binding CDX devices to VFIO

Before running application make sure to bind the devices to vfio-cdx:

The devices can be found in /sys/bus/cdx/devices, bind the desired devices to vfio-cdx using following commands

~~~
# Example for binding cdx-00:00 and cdx-00:01
$ echo "vfio-cdx" >  /sys/bus/cdx/devices/cdx-00\:00/driver_override
$ echo "cdx-00:00" > /sys/bus/cdx/drivers_probe
$ echo "vfio-cdx" >  /sys/bus/cdx/devices/cdx-00\:01/driver_override
$ echo "cdx-00:01" > /sys/bus/cdx/drivers_probe
~~~

## Running application
scp the dpdk-mcdi_init, dpdk-mcdi_test applications to board.

~~~
scp dpdk-mcdi_init dpdk-mcdi_test <user>@<ip address>:~
~~~

Run the initialization application dpdk-mcdi_init to create end point devices for all
the available cdx devices using following command.

~~~
# ./dpdk-mcdi_init 1
~~~

Following are the expected logs in case of successful execution of initialization application.

~~~
# ./dpdk-mcdi_init 1
Created endpoint for dst address 1025, cdx device 00:00
Created endpoint for dst address 1026, cdx device 00:01
Created endpoint for dst address 1027, cdx device 00:02
Created endpoint for dst address 1028, cdx device 00:03
~~~

The end point character device creation can be confirmed by new /dev/rpmsg* files.

~~~
# ls /dev/rpmsg*
/dev/rpmsg0  /dev/rpmsg1  /dev/rpmsg2  /dev/rpmsg3  /dev/rpmsg_ctrl0
~~~

The group permissions of /dev/rpmsg* can be changed to uniquely grant the
access of rpmsg endpoints for users.

Run the dpdk-mcdi_test to send and receive the mcdi message using following command.
This example sends the mcdi command get_version over an cdx device with
bus id as 0 and device id as 2.

~~~
# ./dpdk-mcdi_test 0 2 get_version
~~~

Usage of sample application dpdk-mcdi_test is given below.

~~~
# ./dpdk-mcdi_test <bus id> <device id> <command>
~~~

Following are the expected logs in case of successful execution of sample application.

~~~
# ./dpdk-mcdi_test/ 0 2 get_version
Opened an fd on rpmsg device /dev/rpmsg2
Response length : 432
 FF008003 0800A801 03C93F64 02000000 76010011 1977801F 080E200E 00000000 02000500 00000000 38313839 3136392B 00000004 00000000
mc_cmd_get_version_out_firmware = 1681901827 (Wed Apr 19 10:57:07 2023)
pcol = 2
supported_funcs[0] = 11000176 1f807719 0e200e08 00000000
version = 50002
extra = 8189169+
flags = 19
mcfw_build_id = 0000000000000000000000000000000000000000
mcfw_security_level = 0
mcfw_build_name = ksb_dpu_psx_eftest_debug
sucfw_version[0] = 0.0.0.0
sucfw_build_date = 0 (Thu Jan  1 00:00:00 1970)
sucfw_chip_id = 0
cmcfw_version[0] = 0.0.0.0
cmcfw_build_date = 0 (Thu Jan  1 00:00:00 1970)
fpga_version[0] = 0.1.2
fpga_extra =
board_name = ksb_dpu_psx
board_revision = 0
board_serial =
datapath_hw_version[0] = 0.0.0
datapath_fw_version[0] = 0.0.0
soc_boot_version[0] = 0.0.0.0
soc_uboot_version[0] = 0.0.0.0
soc_main_rootfs_version[0] = 0.0.0.0
soc_recovery_buildroot_version[0] = 0.0.0.0
board_version[0] = 0.0.0.0
bundle_version[0] = 0.0.0.0
~~~

Run the dpdk-mcdi_init application to destroy all the end points for cdx devices
using following command

~~~
# ./dpdk-mcdi_init 0
~~~

Confirm that all the end points are destroyed from /dev/rpmsg*.

~~~
# ls /dev/rpmsg*
/dev/rpmsg_ctrl0
~~~

> **_NOTE:_**  Limited testing is performed and only version command is tested.
