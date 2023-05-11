# MCDI library: send,receive MCDI request/response over Rpmsg transport

## About
This library enables applications to send and receive MCDI data over rpmsg transport.

This library exposes two types of APIs to applications, these are listed below
1. APIs to open and close the file descriptor on the rpmsg end point.
2. APIs to encode an MCDI command and decode the MCDI response.

## prerequisite
Rpmsg end points shall be created before running the applications using this library.
An example application which creates Rpmsg endpoints for all the available CDX devices is provided
at [MCDI INIT APP](../../examples/mcdi/mcdi_init/).

## Description

### Open/Close file descriptors of rpmsg end point
Following APIs are exposed to applications for opening and closing of file descriptors on rpmsg end points.
1. int mcdi_create_device_ep(u16 bus_id, u16 dev_id)
	- Finds an rpmsg end point using bus, device ID.
	- Opens an file descriptor on the found rpmsg end point in above step and
	  returns the created file descriptor to application.
2. void mcdi_destroy_device_ep(int fd)
	- closes the given file descriptor.
	- Applications should destroy/close the file descriptor opened using mcdi_create_device_ep().

### Encode/Decode of MCDI commands
This library also provides two functions for each command, one to encode the MCDI command and
another to decode the MCDI response.

There are two options for encode and decode APIs, these are
1. APIs with structures as arguments
	- Which takes input/output parameters as structures.
2. APIs with individual variables as arguments.
	- Which takes input/output parameters as individual variables.

Both types of APIs are exposed just as an example in this release and based on MSFT feedback one of these can be removed in future releases.

Refer to doxygen documentation of [mcdi_lib.h](./mcdi_lib.h) from MCDI library for extensive details of
all the APIs supported by this library.

As an example, encode and decode APIs for version command are given below.

Following are the APIs taking structure as arguments.
~~~
    int mc_cmd_get_version_ext_enc(void *buf, size_t bufsize, mc_cmd_get_version_ext_enc_t *msg);
    int mc_cmd_get_version_v5_dec(void *buf, size_t bufsize, mc_cmd_get_version_v5_dec_t *msg);
~~~

Following are the APIs taking variables as arguments.
~~~
    int mc_cmd_get_version_ext_enc2(void *buf, size_t bufsize, uint32_t ext_flags);
    int mc_cmd_get_version_v5_dec2( void *buf,  size_t bufsize, ....);
~~~

## Usage
Applications using this library shall follow below steps.
1. Open an file descriptor using mcdi_create_device_ep().
2. Encode the command using the encode API of the particular command to be tested.
3. Send the encoded buffer using the file descriptor opened in above step.
4. Receive the MCDI response buffer by reading the file descriptor opened in above step.
5. Pass the received buffer on to the decode function of the particular MCDI command
   to convert the data into application usable format.
6. Close the file descriptor using mcdi_destroy_device_ep().

## Sample/example application
An example application which demonstrates the usage of MCDI library is provided
at [MCDI TEST APP](../../examples/mcdi/mcdi_test/).

Please refer to [MCDI TEST README](../../examples/mcdi/README.md) for the instructions to run the example application.

> **_NOTE:_**  Limited testing is performed.
>              This library is for demonstration purpose only and will not be upstreamed.
