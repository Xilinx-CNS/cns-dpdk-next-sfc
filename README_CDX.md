# AMD DPDK README for CDX devices

## About

DPDK provides a set of data plane libraries and driver for for fast
packet processing supporing multiple busses and devices. This README
provides information about building and executing DPDK based
applications on the platforms supporting CDX bus and devices.

## Compiling DPDK for CDX devices

Applications will cross compile for AARCH64. Ubuntu gcc-aarch64-linux-gnu
toolchain needs to be installed.

Please refer to following DPDK documentation for meson and ninja version dependencies:
https://doc.dpdk.org/guides/prog_guide/build-sdk-meson.html#getting-the-tools

~~~
cd <dpdk>/
meson arm64-build --cross-file config/arm/arm64_cdx_linux_gcc -Dexamples=cdma_demo,cdx_test,mcdi/mcdi_init
ninja -C arm64-build
~~~

After compilation, dpdk-cdma_demo dpdk-cdx_test dpdk-mcdi_init applications would respectively
be available at:
arm64-build/examples/dpdk-cdma_demo, arm64-build/examples/dpdk-cdx_test and
arm64-build/examples/dpdk-mcdi_init

> **NOTE:** User can compile applications other than above applications as well.
Please refer to DPDK documentation (http://doc.dpdk.org/guides/linux_gsg/)

## CDMA demo

CDMA demo is a sample application which works on a sample CDMA device
(a simple DMA device present on the CDX bus). The devices on the CDX
bus are bound to vfio-cdx linux driver.

- The CDMA demo test triggers a DMA Copy test to verify MMIO and IOMMU
  functionality provided by the CDX bus.
- It also validates MSI initiating a DMA transaction to GITS TRANSLATOR
  address, thus faking the MSI generation.

Test runs on each CDX device detected on the DPDK CDX bus.

> **NOTE:** CDMA demo application uses CDMA devices which are simulated in
QEMU enviromentment only. Hence this application will provide expected
results only in QEMU enviroment.

## CDX test

CDX test is a basic application which first unplugs and then plugs the CDX
devices, reads the memory addresses for all the memory regions
on all the available CDX devices and tests Msg store , Msg load functionality.

> **NOTE:** CDX test application uses example CDM exeriser for Msg store and Msg load test,
hence this application will not provide expected results on QEMU platform.

## MCDI test app

MCDI test app is a example application which demonstrates using MCDI commands from user space application.
This application uses APIs provided by MCDI library.

Refer to MCDI test application documentation [MCDI test app](./examples/mcdi/README.md) for more details
about MCDI test app.
Please refer to MCDI library documentation [MCDI Library](./lib/mcdi/README.md) for more details about MCDI library.

## Executing DPDK applications

> **NOTE:** Steps in following sections should be run as root user.
~~~
sudo su
~~~

## Mounting hugepages

DPDK uses hugepages for memory allocations and providing DMA'able memory
~~~
# Mount hugepages
mkdir -p /dev/hugetlbfs
mount -t hugetlbfs hugetlbfs /dev/hugetlbfs/
~~~

## Binding CDX devices to VFIO

Before running application make sure to bind the devices to vfio-cdx.
The devices can be found in /sys/bus/cdx/devices.

In case the devices are already bound to the kernel driver, these
needs to be unbind from the kernel driver before binding to vfio-cdx.
For CDMA devices, they need to be unbind from cdx-cdma-1.0 kernel
driver:
~~~
echo "cdx-00:00" > /sys/bus/cdx/drivers/cdx-cdma-1.0/unbind
echo "cdx-00:01" > /sys/bus/cdx/drivers/cdx-cdma-1.0/unbind
~~~

Bind the desired devices to vfio-cdx using following commands:
~~~
# Example for binding cdx-00:00 and cdx-00:01
echo "vfio-cdx" >  /sys/bus/cdx/devices/cdx-00\:00/driver_override
echo "cdx-00:00" > /sys/bus/cdx/drivers_probe
echo "vfio-cdx" >  /sys/bus/cdx/devices/cdx-00\:01/driver_override
echo "cdx-00:01" > /sys/bus/cdx/drivers_probe
~~~

## Running CDMA Demo application on QEMU
scp the *dpdk-cdma_demo* to qemu. Use the port specified in "hostfwd"
options while launching QEMU.

~~~
scp -P <port> <dpdk>/arm64-build/examples/dpdk-cdma_demo petalinux@localhost:~
~~~

Launch the *dpdk-cdma_demo* using following command

~~~
./dpdk-cdma_demo -c 1 -n 1
~~~

The application tests DMA copy and multiple MSIs for all CDX devices
detected in DPDK and exits after test completion.

To run DPDK with continuous DMA on first CDMA device provide -C option:

~~~
./dpdk-cdma_demo -c 1 -n 1 -- -C
~~~

This will keep performing DMA on the first CDMA device until ctrl+C.
On exit it will execute the pending MSI test for first device and
DMA, MSI test for all other CDMA devices.

Check DPDK documentation (https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)
for other EAL arguments

Following are the expected logs in case of successful execution of
the application.

~~~
root@xilinx-versal-net-20222:~# ./dpdk-cdma_demo -c 1 -n 1
EAL: Detected CPU lcores: 8
EAL: Detected NUMA nodes: 1
EAL: Detected static linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: VFIO support initialized
EAL: Using IOMMU type 1 (Type 1)
cdma: Probing CDMA cdx device cdx-00:01
cdma: Probing CDMA cdx device cdx-00:00
TELEMETRY: No legacy callbacks, legacy socket not created
CDMA_DEMO: =================================================
CDMA_DEMO: CDMA DMA TEST PASSED for devid: 0
CDMA_DEMO: CDMA MSI TEST PASSED for devid 0 with 1 MSI
CDMA_DEMO: CDMA DMA TEST PASSED for devid: 1
CDMA_DEMO: CDMA MSI TEST PASSED for devid 1 with 1 MSI
CDMA_DEMO: ----CDMA TEST PASSED----
CDMA_DEMO: =================================================
~~~

## Running dpdk-cdx_test

scp the dpdk-cdx_test application to the board.

~~~
scp <dpdk>/arm64-build/examples/dpdk-cdx_test <user>@<board IP>:~
~~~

Launch the *dpdk-cdx_test* using following command
~~~
./dpdk-cdx_test -c 1 -n 1
~~~

The application first test unplug and plug of CDX devices. It reads and dumps
the MMIO registers of all the regions of the detected CDX devices. It also tests
Msg store, Msg load using CDM exerciser.

Following are the expected logs in case of successful execution of
the application.

~~~
./dpdk-cdx_test -c 1 -n 1
EAL: Detected CPU lcores: 16
EAL: Detected NUMA nodes: 1
EAL: Detected static linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: VFIO support initialized
EAL: Using IOMMU type 1 (Type 1)
cdx_exerciser_probe(): Probing cdx-00:00 device
cdx_exerciser_probe(): Probing cdx-00:01 device
TELEMETRY: No legacy callbacks, legacy socket not created
Removing device: cdx-00:00
cdx_exerciser_remove(): Closing CDX test device cdx-00:00
Probing device with identifier: cdx:cdx-00:00
cdx_exerciser_probe(): Probing cdx-00:00 device
Resource 0 (total len: 2097152)
 0:     00000000 00000000 00000000 00000000
 10:    00000000 00000000 00000000 00000000
 20:    00000000 00000000 00000000 00000000
 30:    00000000 00000000 00000000 00000000
Resource 1 (total len: 67108864)
 0:     01234567 89abcdef 89abcdef 00000000
 10:    1111face facebabe 00000000 00000000
 20:    00000000 00000000 00000000 00000000
 30:    00000000 00000000 00000000 00000000
Self test passed for device cdx-00:00
Msg store test passed for device cdx-00:00
Msg load test passed for device cdx-00:00

Removing device: cdx-00:01
cdx_exerciser_remove(): Closing CDX test device cdx-00:01
Probing device with identifier: cdx:cdx-00:01
cdx_exerciser_probe(): Probing cdx-00:01 device
Resource 0 (total len: 2097152)
 0:     00000000 00000000 00000000 00000000
 10:    00000000 00000000 00000000 00000000
 20:    00000000 00000000 00000000 00000000
 30:    00000000 00000000 00000000 00000000
Resource 1 (total len: 67108864)
 0:     01234567 89abcdef 89abcdef 00000000
 10:    1111face facebabe 00000000 00000000
 20:    00000000 00000000 00000000 00000000
 30:    00000000 00000000 00000000 00000000
Self test passed for device cdx-00:01
Msg store test passed for device cdx-00:01
Msg load test passed for device cdx-00:01
~~~

## Running dpdk-cdx_test with MSI test

scp the dpdk-cdx_test, dpdk-mcdi_init applications to the board.

~~~
scp <dpdk>/arm64-build/examples/dpdk-cdx_test <user>@<board IP>:~
scp <dpdk>/arm64-build/examples/dpdk-mcdi_init <user>@<board IP>:~
~~~

Before running dpdk-cdx_test application, run the initialization application dpdk-mcdi_init
to create end point devices for all the available cdx devices using following command.

~~~
./dpdk-mcdi_init 1
~~~

Following are the expected logs in case of successful execution of initialization application.

~~~
./dpdk-mcdi_init 1
Created endpoint for dst address 1025, cdx device 00:00
Created endpoint for dst address 1026, cdx device 00:01
Created endpoint for dst address 1027, cdx device 00:02
Created endpoint for dst address 1028, cdx device 00:03
~~~

The end point character device creation can be confirmed by new /dev/rpmsg* files.

Launch the *dpdk-cdx_test* application with -m option to perform MSI testing as well.
~~~
./dpdk-cdx_test -c 1 -n 1 -- -m
~~~

## Unbinding CDX devices from VFIO

CDX devices can be unbound from *vfio-cdx* driver, using following commands

~~~
echo "cdx-00:00" > /sys/bus/cdx/drivers/vfio-cdx/unbind
echo > /sys/bus/cdx/devices/cdx-00\:00/driver_override
echo "cdx-00:01" > /sys/bus/cdx/drivers/vfio-cdx/unbind
echo > /sys/bus/cdx/devices/cdx-00\:01/driver_override
~~~

## Building yocto rootfs with DPDK
Please refer to [Building yocto](https://xilinx-wiki.atlassian.net/wiki/spaces/A/pages/18841862/Install+and+Build+with+Xilinx+Yocto) to build rootfs from yocto.
Modify DPDK repository in meta-xilinx/meta-dpdk/recipes-extended/dpdk/dpdk_22.11.0.bb file to update the DPDK
source repo from which the packages,applications needs to be installed into rootfs.

Additionally below steps shall be performed to include DPDK packages, applications into rootfs.

1. Update “COMMON_INSTALL” variable in sources/meta-petalinux/recipes-core/images/petalinux-image-common.inc file
to include dpdk, dpdk-examples, dpdk-tools packages.

~~~
COMMON_INSTALL = " \
    .
    .
    .
    dpdk \
    dpdk-examples \
    dpdk-tools \
    "

~~~

2. Use machine name as *versal-net-generic* to build rootfs for versal net.

~~~
MACHINE=versal-net-generic bitbake petalinux-image-minimal
~~~

> **_NOTE:_**  DPDK EAL argument --log-level=cdx,8 would enable further
logging for DPDK CDX bus and --log-level=cdma,8 would enable logging
for DPDK CDMA driver.
