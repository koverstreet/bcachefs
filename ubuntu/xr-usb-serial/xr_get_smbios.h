/* Copyright (C) 2001-2001 Fujitsu Siemens Computers
   Joachim Braeuer
   This file is part of smbios

   smbios is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License,
   or (at your option) any later version.

   smbios is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
   for more details.

   You should have received a copy of the GNU General Public License
   along with smbios; see the file COPYING. If not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
*/

/* $Id: bios.h,v 1.2 2002/09/03 10:33:12 bretthauert Exp $
 *
 * $Log: bios.h,v $
 * Revision 1.2  2002/09/03 10:33:12  bretthauert
 * fixed a bug with 2.4 kernels (changed kmalloc parameter from
 * GFP_BUFFER to GFP_KERNEL
 *
 * Revision 1.1  2001/09/15 14:52:43  bretthauert
 * initial release
 *
 */

/** \file bios.h
 *  declarations and prototypes of DMI-BIOS and SM-BIOS stuff
 *
 *  \author Markus Lyra
 *  \author Thomas Bretthauer
 *  \author Joachim Braeuer
 *  \version 0.11
 *  \date January 2001
 */
     
#ifndef __SM_BIOS_H__
#define __SM_BIOS_H__

#include <linux/types.h>
//#define _EN_DEBUG_ 1
#ifdef _EN_DEBUG_
#  define SM_BIOS_DEBUG(fmt, args...) printk( KERN_DEBUG "smbios: " fmt, ## args)
#else
#  define SM_BIOS_DEBUG(fmt, args...) /* not debugging: nothing */
#endif
/*
 *   Magic numbers
 */

/** start address of BIOS segment to scanned for SM-BIOS and DMI-BIOS */
#define BIOS_START_ADDRESS      0xF0000
/** length of the scanned BIOS area for SM-BIOS and DMI-BIOS */
#define BIOS_MAP_LENGTH         0x10000
/** magic 4 bytes to identify SM-BIOS entry point, paragraph boundary */
#define SMBIOS_MAGIC_DWORD      0x5F4D535F /* anchor string "_SM_" */
/** magic 4 bytes to identify DMI-BIOS entry point, byte boundary */
#define DMIBIOS_MAGIC_DWORD     0x494d445f /* anchor string "_DMI" */
/** identifier for SM-BIOS structures within SM-BIOS entry point */
#define DMI_STRING              "_DMI_"
/** list of types which are known to have subtyes; expandable! */
#define TYPES_WITH_SUBTYPES     185, 187, 208, 209, 210, 211, 212, 254
/** maximum block size for proc read function */
#define PROC_BLOCK_SIZE         (3*1024)


/** mode raw/cooked */
#define FILE_MODE_RAW       0
#define FILE_MODE_COOKED    1

/*
 *   Structures
 */

/** SM-BIOS entry point structure 
 * the SMBIOS Entry Point structure described below can be located by
 * application software by searching for the anchor string on paragraph
 * (16 byte) boundaries within the physical memory address range 000F0000h to
 * 000FFFFFh. This entry point encapsulates an intermediate anchor string
 * that is used by some existing DMI browsers.
 *
 * @note While the SMBIOS Major and Minor Versions (offsets 06h and 07h)
 * currently duplicate the information present in the SMBIOS BCD Revision
 * (offset 1Dh), they provide a path for future growth in this specification.
 * The BCD Revision, for example, provides only a single digit for each of
 * the major and minor version numbers.
 */
struct smbios_entry_point_struct
{
	/** "_SM_", specified as four ASCII characters (5F 53 4D 5F) */
  __u32 anchor_string;
	/** checksum of the Entry Point Structure (EPS). This value, when added to 
	 * all other bytes in the EPS, will result in the value 00h (using 8 bit
	 * addition calculations). Values in the EPS are summed starting at offset
	 * 00h, for Entry Point Length bytes.*/
  __u8  entry_point_checksum;
	/** Length of the Entry Point Structure, starting with the Anchor String 
	 * field, in bytes, currently 1Fh. */
  __u8  entry_point_length;
	/** identifies the major version of this specification implemented in
	 * the table structures, e.g. the value will be 0Ah for revision 10.22
	 * and 02h for revision 2.1 */
  __u8  major_version;
	/** identifies the minor version of this specification implemented in
	 * the table structures, e.g. the value will be 16h for revision 10.22
	 * and 01h for revision 2.1 */
  __u8  minor_version;
	/** size of the largest SMBIOS structure, in bytes, and encompasses the
	 * structure's formatted area and text strings. This is the value returned
	 * as StructureSize from the Plug-n-Play 'Get SMBIOS Information' function */
	__u16 max_struct_size;
	/** identifies the EPS revision implemented in this structure and identifies
	 * the formatting of offsets 0Bh to 0Fh, one of:
	 * 00h     Entry Point based on SMBIOS 2.1 definition; formatted area is
	 *         reserved and set to all 00h.
	 * 01h-FFh reserved for assignment via this specification */
  __u8  revision;
	/** the value present in the Entry Point Revision field defines the
	 * interpretation to be placed upon these5 bytes. */
  __u8  formated_area[5];
	/** "_DMI_", specified as five ASCII characters (5F 44 4D 49 5F) */
  __u8  intermediate_string[5];
	/** checksum of the Intermediate Entry Point Structure (IEPS). This value,
	 * when added to all other bytes in the IEPS, will result in the value 00h
	 * (using 8 bit addition calculations). Values in the IEPS are summed
	 * starting at offset 10h, for 0Fh bytes */
  __u8  intermediate_checksum;
	/** the 32 bit physical starting address of the read-only SMBIOS Structure
	 * Table, that can start at any 32 bit address. This area contains all of the
	 * SMBIOS structures fully packed together. These structures can then be
	 * parsed to produce exactly the same format as that returned from a 'Get
	 * SMBIOS Structure' function call. */
  __u16 struct_table_length;
  __u32 struct_table_address;
  __u16 no_of_structures;
  __u8  bcd_revision;
}__attribute__ ((packed));

/** SM-BIOS and DMI-BIOS structure header */
struct smbios_struct
{
  __u8  type ;
  __u8  length ;
  __u16 handle ;
  __u8  subtype;
        /* ... other fields are structure dependend ... */
} __attribute__ ((packed));

/** DMI-BIOS structure header */
struct dmibios_table_entry_struct
{
  __u16 size;
  __u16 handle;
  __u32 procedure;
}__attribute__ ((packed));

/** DMI-BIOS entry point structure */
struct dmibios_entry_point_struct
{
  __u8  signature[10];
  __u8  revision;
  struct dmibios_table_entry_struct entry[1];
}__attribute__ ((packed));

/** readable names for smbios structures, they serve as filenames in the /proc file system */
#define RD_BIOS								"bios"
#define RD_SYSTEM							"system"
#define RD_BASEBOARD						"baseboard"
#define RD_ENCLOSURE						"enclosure"
#define RD_PROCESSOR						"processor"
#define RD_MEMCTRL							"memory_controller"
#define RD_MEMMOD							"memory_module"
#define RD_CACHE							"cache"
#define RD_PORT								"port_connector"
#define RD_SLOT								"system_slot"
#define RD_ONBOARD							"onboard_device"
#define RD_OEMSTRINGS						"oem_strings"
#define RD_SYSTEMCONFIG					    "system_configuration"
#define RD_BIOSLANG							"bios_language"
#define RD_GROUPASSOC						"group_association"
#define RD_EVENTLOG							"system_event_log"
#define RD_MEMARRAY							"physical_memory_array"
#define RD_MEMDEV							"physical_memory_device"
#define RD_32MEMERR							"32bit_memory_error_information"
#define RD_MEMMAPPEDADR					    "memory_array_mapped_address"
#define RD_MEMMAPPEDDEV					    "memory_device_mapped_address"
#define RD_POINTINGDEV					    "pointing_device"
#define RD_BATTERY							"portable_battery"
#define RD_RESET							"system_reset"
#define RD_SECURITY							"hardware_security"
#define RD_PWRCTRL							"system_power_controls"
#define RD_VOLTAGE							"voltage_probe"
#define RD_COOLINGDEV						"cooling_device"
#define RD_TEMP								"temperature_probe"
#define RD_CURRENT							"current_probe"
#define RD_RMTACCESS						"out_of_band_remote_access"
#define RD_BIS								"boot_integrity_services"
#define RD_BOOT_INFO						"system_boot_information"
#define RD_64MEMERR							"64bit_memory_error_information"
#define RD_MANAGDEV							"management_device"
#define RD_MANAGDEVCOMP					    "management_device_component"
#define RD_MANAGDEVTHRESH				    "management_device_thresholds"
#define RD_MEMCHANNEL						"memory_channel"
#define RD_IPMI								"ipmi_information"
#define RD_PWRSUP							"system_power_supply"
#define RD_INACTIVE							"inactive"
#define RD_EOT								"end_of_table"


//extern smbios_entry_point_struct * smbios_entry_point;      /* start of SMBIOS within the F-Segment */
//extern dmibios_entry_point_struct * dmibios_entry_point;    /* start of DMIBIOS within the F-Segment */
extern void * smbios_structures_base;                       /* base of SMBIOS raw structures */
extern unsigned char smbios_types_with_subtypes[];
extern char smbios_version_string[32];                      /* e.g. V2.31 */
/*
 *   Functions
 */

/* for the description see the implementation file */
struct smbios_entry_point_struct * smbios_find_entry_point(void * base);
struct dmibios_entry_point_struct * dmibios_find_entry_point(void * base);
unsigned char smbios_check_entry_point(void * addr);
int smbios_type_has_subtype(unsigned char type);
int smbios_get_struct_length(struct smbios_struct * struct_ptr);
int dmibios_get_struct_length(struct smbios_struct * struct_ptr);
unsigned int smbios_get_readable_name_ext(char *readable_name, struct smbios_struct *struct_ptr);
unsigned int smbios_get_readable_name(char *readable_name, struct smbios_struct *struct_ptr);
int smbios_check_if_have_exar_config(unsigned char *config0,unsigned char *config1);


#endif /* __BIOS_H__ */
