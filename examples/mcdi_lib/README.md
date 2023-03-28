# MCDI library, applications for MCDI transport

## About
This example contains
1. MCDI library
	- Provides APIs to open and close the rpmsg devices
2. Initialization application - mcdi_init
	- An init time applicaton which creates, destroys the rpmsg end points.
	- This application accepts one arguement as input.Pass "0" for destroying end points and "1" for creating end points.
3. Sample application - mcdi_app
	- This application uses MCDI library and performs send, receive of MCDI messages.

## Compiling
Applications will cross compile for AARCH64. Ubuntu gcc-aarch64-linux-gnu toolchain needs to be installed.
Following command will compile mcdi_init and mcdi_app applications.

~~~
$ cd examples/mcdi_lib
$ make
~~~

## Running application
scp the mcdi_init, mcdi_app applications to board.

~~~
scp mcdi_init mcdi_app <user>@<ip address>:~
~~~

Run the initialization application mcdi_init to create end point devices for all
the available cdx devices using following command.

~~~
# ./mcdi_init 1
~~~

Following are the expected logs in case of successful execution of initialization application.

~~~
# ./mcdi_init 1
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

Run the mcdi_app to send and receive the mcdi message using following command.
This example sends the mcdi command 0x8(get version) over an cdx device with
bus id as 0 and device id as 2.

~~~
# ./mcdi_app 0 2 8 0
~~~

Usage of sample application mcdi_app is given below.

~~~
# ./mcdi_app <bus id> <device id> <opcode> <payload>
~~~

Following are the expected logs in case of successful execution of sample application.

~~~
# ./mcdi_app 0 2 8 0
Opened an fd on rpmsg device /dev/rpmsg2
Response lenth : 128
 5C8000FF  21A80008  641D673F  00000002  11000176  3F807719  0E200E08  00000000  00040002  00000000  65623964  00653732  04000000  00000000  00000019
~~~

Run the mcdi_init application to destroy all the end points for cdx devices
using following command

~~~
# ./mcdi_init 0
~~~

Confirm that all the end points are destroyed from /dev/rpmsg*.

~~~
# ls /dev/rpmsg*
/dev/rpmsg_ctrl0
~~~

> **_NOTE:_**  Limited testing is performed and only version command is tested.
