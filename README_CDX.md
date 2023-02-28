# AMD DPDK README for CDX devices

## About

DPDK provides a set of data plane libraries and driver for for fast
packet processing supporing multiple busses and devices. This README
provides information about building and executing DPDK based
applications on the platforms supporting CDX bus and devices.

## Compiling DPDK for CDX devices

Application will cross compile for AARCH64. Ubuntu gcc-aarch64-linux-gnu
toolchain needs to be installed.

Please refer to meson version and ninja dependency from the DPDK documentation:
https://doc.dpdk.org/guides/prog_guide/build-sdk-meson.html#getting-the-tools

~~~
cd <dpdk>/
meson arm64-build --cross-file config/arm/arm64_cdx_linux_gcc -Dexamples=cdma_demo,cdx_test
ninja -C arm64-build
~~~

After compilation, dpdk-cdma_demo dpdk-cdx_test applications would respectively
be available at:
arm64-build/examples/dpdk-cdma_demo &
arm64-build/examples/dpdk-cdx_test

> **NOTE:** User can compile applications other than CDMA demo/CDX test as well.
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
devices, and then reads the memory addresses for all the memory regions
on all the available CDX devices.

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
[99603.944426] Reset of the CDX device (cdx-00:01) successful
cdma: Probing CDMA cdx device cdx-00:01
[99603.977480] Reset of the CDX device (cdx-00:00) successful
cdma: Probing CDMA cdx device cdx-00:00
TELEMETRY: No legacy callbacks, legacy socket not created
CDMA_DEMO: =================================================
CDMA_DEMO: Dumping CDX devices
CDMA_DEMO: -------------------
cdx device cdx-00:01
   Resource[0]: 0x1100800000 0000000000001000
   Resource[1]: 0x1100801000 0000000000200000
cdx device cdx-00:00
   Resource[0]: 0x1100a01000 0000000000001000
   Resource[1]: 0x1100a02000 0000000000200000
CDMA_DEMO: =================================================
CDMA_DEMO: =================================================
CDMA_DEMO: CDMA DMA TEST PASSED for devid: 0
CDMA_DEMO: CDMA MSI TEST PASSED for devid 0 with 4 MSI
CDMA_DEMO: CDMA DMA TEST PASSED for devid: 1
CDMA_DEMO: CDMA MSI TEST PASSED for devid 1 with 4 MSI
CDMA_DEMO: ----CDMA TEST PASSED----
CDMA_DEMO: =================================================
[99604.223462] Reset of the CDX device (cdx-00:00) successful
[99604.242506] Reset of the CDX device (cdx-00:01) successful
~~~

## Running dpdk-cdx_test

scp the *dpdk-cdx_test* and *csi_exerciser_init.sh*.
Use the port specified in "hostfwd" options while launching QEMU.

~~~
scp -P <port> <dpdk>/arm64-build/examples/dpdk-cdx_test petalinux@localhost:~
scp -P <port> <dpdk>/arm64-build/examples/csi_exerciser_init.sh petalinux@localhost:~
~~~

> **NOTE:** To run dpdk-cdx_test on VNX board with CSI excersizer, CSI 
excersizer needs to be initialized first using following command

~~~
./csi_exerciser_init.sh
~~~
Launch the *dpdk-cdx_test* using following command

~~~
./dpdk-cdx_test
~~~

The application first dumps the existing CDX devices and then test unplug and
plug of CDX devices. It also reads and dumps the MMIO registers of all the
regions of the detected CDX devices.

Following are the expected logs in case of successful execution of
the application.

~~~
root@xilinx-versal-net-virt-20222:~# ./dpdk-cdx_test
EAL: Detected CPU lcores: 8
EAL: Detected NUMA nodes: 1
EAL: Detected static linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: VFIO support initialized
EAL: Using IOMMU type 1 (Type 1)
TELEMETRY: No legacy callbacks, legacy socket not created
PMD: rte_cdx_get_sysfs_path: /sys/bus/cdx/devices

CDX devices:
================================
cdx device cdx-00:01
   Resource[0]: 0x1100800000 0000000000001000
cdx device cdx-00:00
   Resource[0]: 0x1100801000 0000000000001000
   Resource[1]: 0x1100802000 0000000000200000
Removing device: cdx-00:01
EAL: Releasing CDX mapped resource for cdx-00:01
Probing device with identifier: cdx:cdx-00:01
Removing device: cdx-00:00
EAL: Releasing CDX mapped resource for cdx-00:00
Probing device with identifier: cdx:cdx-00:00

CDX device: cdx-00:01
================================
Resource 0 (total len: 4096)
--------------------------------
 0:	00000000 00001002 00000000 00000000
 10:	00000000 00000000 003f63c4 00000001
 20:	9e6dd044 0000ffff 00000000 00000000
 30:	fc1f1e00 00005652 00000011 00000000
 40:	0000001e 00000000 00000000 00000000
 50:	806652b8 00007f09 fbe78e70 00005652
 60:	00089ca8 00000000 00000000 ffffffff
 70:	00000000 00000000 00000000 00000000
 80:	00000000 00000000 00000000 00000000
 90:	00000000 00000000 00000000 00000000
Resource 1 (total len: 2097152)
--------------------------------
 0:	00000000 00000000 00000000 00000000
 10:	00000000 00000000 00000000 00000000
 20:	00000000 00000000 00000000 00000000
 30:	00000000 00000000 00000000 00000000
 40:	00000000 00000000 00000000 00000000
 50:	00000000 00000000 00000000 00000000
 60:	00000000 00000000 00000000 00000000
 70:	00000000 00000000 00000000 00000000
 80:	00000000 00000000 00000000 00000000
 90:	00000000 00000000 00000000 00000000

CDX device: cdx-00:00
================================
Resource 0 (total len: 4096)
--------------------------------
 0:	00000000 00001002 00000000 00000000
 10:	00000000 00000000 003f63c4 00000001
 20:	9e6dd044 0000ffff 00000000 00000000
 30:	fc1f0710 00005652 00000011 00000000
 40:	0000001e 00000000 00000000 00000000
 50:	806643e8 00007f09 fbe78e70 00005652
 60:	00089d29 00000000 00000000 ffffffff
 70:	00000000 00000000 00000000 00000000
 80:	00000000 00000000 00000000 00000000
 90:	00000000 00000000 00000000 00000000
Resource 1 (total len: 2097152)
--------------------------------
 0:	00000000 00000000 00000000 00000000
 10:	00000000 00000000 00000000 00000000
 20:	00000000 00000000 00000000 00000000
 30:	00000000 00000000 00000000 00000000
 40:	00000000 00000000 00000000 00000000
 50:	00000000 00000000 00000000 00000000
 60:	00000000 00000000 00000000 00000000
 70:	00000000 00000000 00000000 00000000
 80:	00000000 00000000 00000000 00000000
 90:	00000000 00000000 00000000 00000000
~~~

## Running dpdk-test with dmadev_autotest

dpdk-test is a DPDK provided test application which can be used
to test the DMA using the CDX CDMA devices

scp the *dpdk-test* to qemu. Use the port specified in "hostfwd"
options while launching QEMU.

~~~
scp -P <port> <dpdk>/arm64-build/app/test/dpdk-test petalinux@localhost:~
~~~

Launch the *dpdk-test* using following command

~~~
./dpdk-test
~~~

The application tests DMA copy for all CDX devices detected in DPDK.

~~~
./dpdk-test
RTE>>dmadev_autotest
RTE>>quit
~~~

Following are the expected logs in case of successful execution of
the application.

~~~
root@xilinx-versal-net-20222:~# ./dpdk-test
EAL: Detected CPU lcores: 8
EAL: Detected NUMA nodes: 1
EAL: Detected static linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: VFIO support initialized
EAL: Using IOMMU type 1 (Type 1)
[101177.305387] Reset of the CDX device (cdx-00:01) successful
cdma: Probing CDMA cdx device cdx-00:01
[101177.364605] Reset of the CDX device (cdx-00:00) successful
cdma: Probing CDMA cdx device cdx-00:00
TELEMETRY: No legacy callbacks, legacy socket not created
APP: HPET is not enabled, using TSC as default timer
RTE>>dmadev_autotest
skeldma_probe(): Create dma_skeleton dmadev with lcore-id -1

### Test dmadev infrastructure using skeleton driver
test_dma_get_dev_id_by_name Passed
test_dma_is_valid_dev Passed
test_dma_count Passed
test_dma_info_get Passed
test_dma_configure Passed
test_dma_vchan_setup Passed
test_dma_start_stop Passed
test_dma_stats Passed
test_dma_dump Passed
test_dma_completed Passed
test_dma_completed_status Passed
Total tests   : 11
Passed        : 11
Failed        : 0

### Test dmadev instance 0 [cdx-00:01]
DMA Dev 0: Running copy Tests
Ops submitted: 640	Ops completed: 640	Errors: 0
DMA Dev 0: insufficient burst capacity (64 required), skipping tests
DMA Dev 0: device does not report errors, skipping error handling tests
DMA Dev 0: No device fill support, skipping fill tests

### Test dmadev instance 1 [cdx-00:00]
DMA Dev 1: Running copy Tests
Ops submitted: 640	Ops completed: 640	Errors: 0
DMA Dev 1: insufficient burst capacity (64 required), skipping tests
DMA Dev 1: device does not report errors, skipping error handling tests
DMA Dev 1: No device fill support, skipping fill tests

### Test dmadev instance 2 [dma_skeleton]
DMA Dev 2: Running copy Tests
Ops submitted: 85120	Ops completed: 85120	Errors: 0
DMA Dev 2: Running burst capacity Tests
Ops submitted: 65536	Ops completed: 65536	Errors: 0
DMA Dev 2: device does not report errors, skipping error handling tests
DMA Dev 2: No device fill support, skipping fill tests
Test OK
RTE>>quit
[101623.376522] Reset of the CDX device (cdx-00:00) successful
[101623.399842] Reset of the CDX device (cdx-00:01) successful
~~~

## Unbinding CDX devices from VFIO

CDX devices can be unbound from *vfio-cdx* driver, using following commands

~~~
echo "cdx-00:00" > /sys/bus/cdx/drivers/vfio-cdx/unbind
echo > /sys/bus/cdx/devices/cdx-00\:00/driver_override
echo "cdx-00:01" > /sys/bus/cdx/drivers/vfio-cdx/unbind
echo > /sys/bus/cdx/devices/cdx-00\:01/driver_override
~~~

> **_NOTE:_**  DPDK EAL argument --log-level=cdx,8 would enable further
logging for DPDK CDX bus and --log-level=cdma,8 would enable logging
for DPDK CDMA driver.
