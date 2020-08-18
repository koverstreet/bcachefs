.. Permission is granted to copy, distribute and/or modify this
.. document under the terms of the GNU Free Documentation License,
.. Version 1.1 or any later version published by the Free Software
.. Foundation, with no Invariant Sections, no Front-Cover Texts
.. and no Back-Cover Texts. A copy of the license is included at
.. Documentation/userspace-api/media/fdl-appendix.rst.
..
.. TODO: replace it to GFDL-1.1-or-later WITH no-invariant-sections

.. _VIDIOC_ENUM_FMT:

*********************
ioctl VIDIOC_ENUM_FMT
*********************

Name
====

VIDIOC_ENUM_FMT - Enumerate image formats


Synopsis
========

.. c:function:: int ioctl( int fd, VIDIOC_ENUM_FMT, struct v4l2_fmtdesc *argp )
    :name: VIDIOC_ENUM_FMT


Arguments
=========

``fd``
    File descriptor returned by :ref:`open() <func-open>`.

``argp``
    Pointer to struct :c:type:`v4l2_fmtdesc`.


Description
===========

To enumerate image formats applications initialize the ``type``, ``mbus_code``
and ``index`` fields of struct :c:type:`v4l2_fmtdesc` and call
the :ref:`VIDIOC_ENUM_FMT` ioctl with a pointer to this structure. Drivers
fill the rest of the structure or return an ``EINVAL`` error code. All
formats are enumerable by beginning at index zero and incrementing by
one until ``EINVAL`` is returned. If applicable, drivers shall return
formats in preference order, where preferred formats are returned before
(that is, with lower ``index`` value) less-preferred formats.

Depending on the ``V4L2_CAP_IO_MC`` :ref:`capability <device-capabilities>`,
the ``mbus_code`` field is handled differently:

1) ``V4L2_CAP_IO_MC`` is not set (also known as a 'video-node-centric' driver)

   Applications shall initialize the ``mbus_code`` field to zero and drivers
   shall ignore the value of the field.

   Drivers shall enumerate all image formats.

   .. note::

      After switching the input or output the list of enumerated image
      formats may be different.

2) ``V4L2_CAP_IO_MC`` is set (also known as an 'MC-centric' driver)

   If the ``mbus_code`` field is zero, then all image formats
   shall be enumerated.

   If the ``mbus_code`` field is initialized to a valid (non-zero)
   :ref:`media bus format code <v4l2-mbus-pixelcode>`, then drivers
   shall restrict enumeration to only the image formats that can produce
   (for video output devices) or be produced from (for video capture
   devices) that media bus code. If the ``mbus_code`` is unsupported by
   the driver, then ``EINVAL`` shall be returned.

   Regardless of the value of the ``mbus_code`` field, the enumerated image
   formats shall not depend on the active configuration of the video device
   or device pipeline.


.. tabularcolumns:: |p{4.4cm}|p{4.4cm}|p{8.7cm}|

.. c:type:: v4l2_fmtdesc

.. flat-table:: struct v4l2_fmtdesc
    :header-rows:  0
    :stub-columns: 0
    :widths:       1 1 2

    * - __u32
      - ``index``
      - Number of the format in the enumeration, set by the application.
	This is in no way related to the ``pixelformat`` field.
    * - __u32
      - ``type``
      - Type of the data stream, set by the application. Only these types
	are valid here: ``V4L2_BUF_TYPE_VIDEO_CAPTURE``,
	``V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE``,
	``V4L2_BUF_TYPE_VIDEO_OUTPUT``,
	``V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE``,
	``V4L2_BUF_TYPE_VIDEO_OVERLAY``,
	``V4L2_BUF_TYPE_SDR_CAPTURE``,
	``V4L2_BUF_TYPE_SDR_OUTPUT``,
	``V4L2_BUF_TYPE_META_CAPTURE`` and
	``V4L2_BUF_TYPE_META_OUTPUT``.
	See :c:type:`v4l2_buf_type`.
    * - __u32
      - ``flags``
      - See :ref:`fmtdesc-flags`
    * - __u8
      - ``description``\ [32]
      - Description of the format, a NUL-terminated ASCII string. This
	information is intended for the user, for example: "YUV 4:2:2".
    * - __u32
      - ``pixelformat``
      - The image format identifier. This is a four character code as
	computed by the v4l2_fourcc() macro:
    * - :cspan:`2`

	.. _v4l2-fourcc:

	``#define v4l2_fourcc(a,b,c,d)``

	``(((__u32)(a)<<0)|((__u32)(b)<<8)|((__u32)(c)<<16)|((__u32)(d)<<24))``

	Several image formats are already defined by this specification in
	:ref:`pixfmt`.

	.. attention::

	   These codes are not the same as those used
	   in the Windows world.
    * - __u32
      - ``mbus_code``
      - Media bus code restricting the enumerated formats, set by the
        application. Only applicable to drivers that advertise the
        ``V4L2_CAP_IO_MC`` :ref:`capability <device-capabilities>`, shall be 0
        otherwise.
    * - __u32
      - ``reserved``\ [3]
      - Reserved for future extensions. Drivers must set the array to
	zero.



.. tabularcolumns:: |p{6.6cm}|p{2.2cm}|p{8.7cm}|

.. _fmtdesc-flags:

.. flat-table:: Image Format Description Flags
    :header-rows:  0
    :stub-columns: 0
    :widths:       3 1 4

    * - ``V4L2_FMT_FLAG_COMPRESSED``
      - 0x0001
      - This is a compressed format.
    * - ``V4L2_FMT_FLAG_EMULATED``
      - 0x0002
      - This format is not native to the device but emulated through
	software (usually libv4l2), where possible try to use a native
	format instead for better performance.
    * - ``V4L2_FMT_FLAG_CONTINUOUS_BYTESTREAM``
      - 0x0004
      - The hardware decoder for this compressed bytestream format (aka coded
	format) is capable of parsing a continuous bytestream. Applications do
	not need to parse the bytestream themselves to find the boundaries
	between frames/fields. This flag can only be used in combination with
	the ``V4L2_FMT_FLAG_COMPRESSED`` flag, since this applies to compressed
	formats only. This flag is valid for stateful decoders only.
    * - ``V4L2_FMT_FLAG_DYN_RESOLUTION``
      - 0x0008
      - Dynamic resolution switching is supported by the device for this
	compressed bytestream format (aka coded format). It will notify the user
	via the event ``V4L2_EVENT_SOURCE_CHANGE`` when changes in the video
	parameters are detected. This flag can only be used in combination
	with the ``V4L2_FMT_FLAG_COMPRESSED`` flag, since this applies to
	compressed formats only. It is also only applies to stateful codecs.


Return Value
============

On success 0 is returned, on error -1 and the ``errno`` variable is set
appropriately. The generic error codes are described at the
:ref:`Generic Error Codes <gen-errors>` chapter.

EINVAL
    The struct :c:type:`v4l2_fmtdesc` ``type`` is not
    supported or the ``index`` is out of bounds.

    If ``V4L2_CAP_IO_MC`` is set and the specified ``mbus_code``
    is unsupported, then also return this error code.
