/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

static void *smbios_base = 0;
/** SM-BIOS entry point structure */
struct smbios_entry_point_struct *smbios_entry_point = 0;
/** DMI-BIOS entry point structure */
struct dmibios_entry_point_struct *dmibios_entry_point = 0;
/** SM-BIOS, resp. DMI-BIOS structures base address; starting point */
void *smbios_structures_base = 0;
/** enumeration of SM-BIOS, resp. DMI-BIOS types that do have subtypes */
__u8 smbios_types_with_subtypes[] = { TYPES_WITH_SUBTYPES };
/** contains the SMBIOS Version, e.g. V2.31 */
char smbios_version_string[32];
/** \fn unsigned char smbios_check_entry_point (void * addr)
 *  \brief checks the entry point structure for correct checksum
 *  \param addr pointer to the entry point structure
 *  \return the checksum of the entry point structure, should be '0'
 *
 *  This function checks the entry point structure for correct checksum.
 *  The checksum is calculated with adding every byte of the structure
 *  to the checksum byte. The entry point structure is considered correct
 *  if the checksum byte is 0.
 *
 *  \author Markus Lyra
 *  \author Thomas Bretthauer
 *  \date October 2000
 */

unsigned char smbios_check_entry_point (void *addr)
{
    unsigned char *i;
    unsigned char checksum = 0;
    unsigned char length =((struct smbios_entry_point_struct *) addr)->entry_point_length;
    /* calculate checksum for entry point structure (should be 0) */
    for (i = (unsigned char *) addr; i < (unsigned char *) addr + length; i++)
        checksum += *i;
    return checksum;
}

struct smbios_entry_point_struct * smbios_find_entry_point (void *base)
{
    struct smbios_entry_point_struct *entry_point = 0;	/** SM-BIOS entry point */
    unsigned int *temp;				        /** temp. pointer       */


    /* search for the magic dword - '_SM_� as DWORD formatted -  on paragraph boundaries */
    for (temp = base;
		 !entry_point && temp < (unsigned int *) base + BIOS_MAP_LENGTH;
	     temp += 4)
	{
        /* found the identifier ? */
        if (*temp == SMBIOS_MAGIC_DWORD)
        {
            /* check if entry point valid (build checksum) */
	        if (!(smbios_check_entry_point (temp)))
	        {
	            entry_point = (struct smbios_entry_point_struct *) temp;
				
				/* fix display of Bios version string */
			    /* SMBios version is known as 2.1, 2.2, 2.3 and 2.3.1, never as 2.01 (JB) */
	            SM_BIOS_DEBUG("SM-BIOS V%d.%d entry point found at 0x%x\n",
		        entry_point->major_version, entry_point->minor_version, (unsigned int) temp);

                SM_BIOS_DEBUG("V%d.%d\n", entry_point->major_version, entry_point->minor_version);
	        }
        }
    }
    return entry_point;
}
struct dmibios_entry_point_struct *dmibios_find_entry_point (void *base)
{
    struct dmibios_entry_point_struct *entry_point = 0;	    /** DMI-BIOS entry point */
    unsigned char *temp = 0;			                /** temp. pointer        */
    unsigned char biossignature[] =		                /** '_DMI20_NT_'         */
                { 0x5f, 0x44, 0x4d, 0x49, 0x32, 0x30, 0x5f, 0x4e, 0x54, 0x5f };

    /* search for the DMI-BIOS signature on character boundary (hm?) */
    for (temp = base;
	       !entry_point && 
				 temp < (__u8 *) base + BIOS_MAP_LENGTH - sizeof (biossignature) - 32;
	       temp++)
	{
        unsigned long *tempdword = (unsigned long *) temp;

        /* found the identifier '_DMI' ?     (beginning of signature) */
        if (*tempdword == DMIBIOS_MAGIC_DWORD)
        {
	        entry_point = (struct dmibios_entry_point_struct *) temp;
	
	        SM_BIOS_DEBUG ("DMI-BIOS revision %d entry point at 0x%x\n",
		    entry_point->revision, (unsigned int) temp);

            sprintf(smbios_version_string, "V%d\n", entry_point->revision);

	        if (memcmp (temp, biossignature, sizeof (biossignature)) == 0)
	            SM_BIOS_DEBUG ("DMI BIOS successfully identified\n");
        }
    }
    return entry_point;
}
void dump_smbios_hex(unsigned char *p,int len)
{
   int i;
   SM_BIOS_DEBUG("dump_smbios_hex length:%d\n",len);
   for(i=0;i<len;i++)
   {
      if((p[i] == 0xc0)&&(p[i+1]==0x06))  
	  	SM_BIOS_DEBUG("Found 0xc0 at offset:%d 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x \n\t",i,p[i],p[i+1],p[i+2],p[i+3],p[i+4],p[i+5]);
   }
}
int smbios_type_has_subtype (unsigned char type)
{
    int i;


    for (i = 0; i < sizeof (smbios_types_with_subtypes); i++)
        if (type == smbios_types_with_subtypes[i])
	        return 1;

    return 0;
}

int smbios_get_struct_length (struct smbios_struct * struct_ptr)
{
    /* jump to string list */
    unsigned char *ptr = (unsigned char *) struct_ptr + struct_ptr->length;

    /* search for the end of string list */
    while (ptr[0] != 0x00 || ptr[1] != 0x00)
        ptr++;
    ptr += 2;			/* terminating 0x0000 should be included */

    return (int) ptr - (int) struct_ptr;
}

unsigned int smbios_get_readable_name(char *name, struct smbios_struct *struct_ptr)
{
    switch(struct_ptr->type)
    {
        case 0: return sprintf (name, "%s", RD_BIOS);
        case 1: return sprintf (name, "%s", RD_SYSTEM);
		case 2: return sprintf (name, "%s", RD_BASEBOARD);
		case 3: return sprintf (name, "%s", RD_ENCLOSURE);
		case 4: return sprintf (name, "%s", RD_PROCESSOR);
		case 5: return sprintf (name, "%s", RD_MEMCTRL);
		case 6: return sprintf (name, "%s", RD_MEMMOD);
		case 7: return sprintf (name, "%s", RD_CACHE);
		case 8: return sprintf (name, "%s", RD_PORT);
		case 9: return sprintf (name, "%s", RD_SLOT);
		case 10: return sprintf (name, "%s", RD_ONBOARD);
		case 11: return sprintf (name, "%s", RD_OEMSTRINGS);
		case 12: return sprintf (name, "%s", RD_SYSTEMCONFIG);
		case 13: return sprintf (name, "%s", RD_BIOSLANG);
		case 14: return sprintf (name, "%s", RD_GROUPASSOC);
		case 15: return sprintf (name, "%s", RD_EVENTLOG);
		case 16: return sprintf (name, "%s", RD_MEMARRAY);
		case 17: return sprintf (name, "%s", RD_MEMDEV);
		case 18: return sprintf (name, "%s", RD_32MEMERR);
		case 19: return sprintf (name, "%s", RD_MEMMAPPEDADR);
		case 20: return sprintf (name, "%s", RD_MEMMAPPEDDEV);
		case 21: return sprintf (name, "%s", RD_POINTINGDEV);
		case 22: return sprintf (name, "%s", RD_BATTERY);
		case 23: return sprintf (name, "%s", RD_RESET);
		case 24: return sprintf (name, "%s", RD_SECURITY);
		case 25: return sprintf (name, "%s", RD_PWRCTRL);
		case 26: return sprintf (name, "%s", RD_VOLTAGE);
		case 27: return sprintf (name, "%s", RD_COOLINGDEV);
		case 28: return sprintf (name, "%s", RD_TEMP);
		case 29: return sprintf (name, "%s", RD_CURRENT);
		case 30: return sprintf (name, "%s", RD_RMTACCESS);
		case 31: return sprintf (name, "%s", RD_BIS);
		case 32: return sprintf (name, "%s", RD_BOOT_INFO);
		case 33: return sprintf (name, "%s", RD_64MEMERR);
		case 34: return sprintf (name, "%s", RD_MANAGDEV);
		case 35: return sprintf (name, "%s", RD_MANAGDEVCOMP);
		case 36: return sprintf (name, "%s", RD_MANAGDEVTHRESH);
		case 37: return sprintf (name, "%s", RD_MEMCHANNEL);
		case 38: return sprintf (name, "%s", RD_IPMI);
		case 39: return sprintf (name, "%s", RD_PWRSUP);
		case 126: return sprintf (name, "%s", RD_INACTIVE);
		case 127: return sprintf (name, "%s", RD_EOT);
		default: return sprintf (name, "%d", struct_ptr->type);
    }
}
unsigned int smbios_get_readable_name_ext(char *name, struct smbios_struct *struct_ptr)
{
    return sprintf (name, "%d-%d", struct_ptr->type, struct_ptr->subtype);
}

int smbios_make_dir_entries (void)
{
    int i;
    unsigned int raw_name_length = 0;	
    char raw_name[12];                      /* e.g. 0.0 for structure type 0 , first instance */
    unsigned int readable_name_length = 0;	
    char readable_name[64];                 /* e.g. Bios.0 for structure type 0 , first instance */
    struct smbios_struct *struct_ptr = smbios_structures_base;
    /*
     *  for every SMBIOS structure do ...
     */
    for (i = 0; i < smbios_entry_point->no_of_structures; i++)
    {
        memset(raw_name,0,12);
		memset(readable_name,0,64);
        /*
         *  generate an unique name for the file:  "type[-subtype].count"
         */
        if (smbios_type_has_subtype (((struct smbios_struct *) struct_ptr)->type))
        {
      /* name will contain the raw file name, it equals the structure type (e.g. 1 for Type 1).
             * readable_name contains the interpreted file name (e.g. System for Type 1)
             */
	        raw_name_length = sprintf (raw_name, "%d-%d", struct_ptr->type, struct_ptr->subtype);
            readable_name_length = smbios_get_readable_name_ext(readable_name, struct_ptr);
			//printk(KERN_INFO "[%s] smbios_type_has_subtype[%d] length:%d\n",raw_name,struct_ptr->type,struct_ptr->length);
        }
        else
        {
	        raw_name_length = sprintf (raw_name, "%d", struct_ptr->type);
            readable_name_length = smbios_get_readable_name(readable_name, struct_ptr);
			//printk(KERN_INFO "[%s] smbios_type_has type:%d length:%d\n",readable_name,struct_ptr->type,struct_ptr->length);
        }

    /*
         *  go to the next structure
         */
        struct_ptr =(struct smbios_struct *) ((unsigned char *) struct_ptr + smbios_get_struct_length(struct_ptr));
    }

    return 0;
}

int smbios_check_if_have_exar_config(unsigned char *config0,unsigned char *config1)
{
	int i;
	int result = -1;
	unsigned char *p;
	smbios_base = ioremap (BIOS_START_ADDRESS, BIOS_MAP_LENGTH);
	if(!smbios_base)
	{
        SM_BIOS_DEBUG ("ioremap() for entry point failed\n");
        result = -ENXIO;
        return result;
    }
	//printk(KERN_INFO "ioremap bios base at 0x%p\n", smbios_base);	
	if (!(smbios_entry_point = smbios_find_entry_point (smbios_base)))
	{
		SM_BIOS_DEBUG ("SM-BIOS entry point not found\n");
		iounmap (smbios_base);
		result = -ENXIO;
        return result;
		
	}
	 /*
	 *	for SM-BIOS:
	 *	check if Pointer to DMI structures exist.
	 *	intermediate_string (_DMI_) is not '\0' terminated,
	 *	so strncmp() with sizeof(DMI_STRING) - 1 is needed.
	 */
	if (smbios_entry_point)
	{
		if (strncmp((char *) &(smbios_entry_point->intermediate_string),
						DMI_STRING, sizeof (DMI_STRING) - 1))
		{
			SM_BIOS_DEBUG ("Pointer to DMI structures not found!\n");
		   
		}
	}
	
	/*
	 *	map the SM-BIOS structures physical address range.
	 *	the 'real' smbios_structures_base contains the starting
	 *	address, where the instances of dmi structures are located.
	 */
	if (smbios_entry_point)
	{
		if (!(smbios_structures_base =
			  ioremap (smbios_entry_point->struct_table_address,
				(unsigned long) smbios_entry_point->struct_table_length)))
		{
			SM_BIOS_DEBUG("ioremap() for structures table failed\n");
			iounmap (smbios_base);
		    result = -ENXIO;
            return result;
	  	}
	}
	SM_BIOS_DEBUG(KERN_INFO "smbios_structures_base to 0x%p length %d no_of_structures:%d\n", 
		 		  smbios_structures_base,
		   		  smbios_entry_point->struct_table_length,
		          smbios_entry_point->no_of_structures);	
	
   //dump_smbios_hex((unsigned char *)smbios_structures_base,smbios_entry_point->struct_table_length);
   p = (unsigned char *)smbios_structures_base;
   for(i=0;i<smbios_entry_point->struct_table_length;i++)
   {
      if((p[i] == 0xc0)&&(p[i+1]==0x06)) 
      {
	  	SM_BIOS_DEBUG("Found 0xc0 at offset:%d 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x \n\t",i,p[i],p[i+1],p[i+2],p[i+3],p[i+4],p[i+5]);
		*config0 = p[i+4];
		*config1 = p[i+5];
		result = 0;
		break;
      }
   }
    //smbios_make_dir_entries();
    iounmap (smbios_structures_base);
	iounmap (smbios_base);
    return result;

}
/*
void dmi_dump_backup(void)
{
	const char *board_vendor, *board_name,*board_serial;
	const struct dmi_device *dmi;
	struct dmi_dev_onboard *donboard;
	board_vendor = dmi_get_system_info(DMI_BOARD_VENDOR);
	board_name = dmi_get_system_info(DMI_BOARD_NAME);
	board_serial =  dmi_get_system_info(DMI_BOARD_SERIAL);
	printk(KERN_INFO "DMI_BOARD_VENDOR:%s\n",board_vendor);
	printk(KERN_INFO "DMI_BOARD_NAME:%s\n",board_name);
	printk(KERN_INFO "DMI_BOARD_SERIAL:%s\n",board_serial);
	for(i=0;i<256;i++)
	{
		dmi = NULL;
		//printk(KERN_INFO "dmi_find_device<%d>\n",i);
		while ((dmi = dmi_find_device(i,NULL, dmi)) != NULL) 
		{
		  //donboard = dmi->device_data;
		  printk(KERN_INFO "<%d>Found name:%s   type:%d \n",i,dmi->name,dmi->type);
		}
	}			

}
*/

