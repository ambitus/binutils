/* IBM z/OS Program Object support
   Copyright (C) 2019 Free Software Foundation, Inc.
   Contributed by Michael Colavita <mcolavita@rocketsoftware.com>.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef _PO_COMMON_H
#define _PO_COMMON_H

/* The required alignment of a reloc group header.  */
#define RELOC_GROUP_HEADER_ALIGN 4

/* Size of a PRAT entry.  */
#define PRAT_ENTRY_SIZE 4

#define PLMH_VERSION                   0x04

#define PLMH_REC_TYPE_PO_NAME_HEADER   0x0001
#define PLMH_REC_TYPE_PO_NAME          0x0002
#define PLMH_REC_TYPE_PMAR             0x0003
#define PLMH_REC_TYPE_PRAT             0x0004
#define PLMH_REC_TYPE_PRDT             0x0005
#define PLMH_REC_TYPE_LIDX             0x0006
#define PLMH_REC_TYPE_ENTRY            0x0007
#define PLMH_REC_TYPE_BXLF             0x0008

#define PMAR_PO_LEVEL_PM1              0x01
#define PMAR_PO_LEVEL_PM2              0x02
#define PMAR_PO_LEVEL_PM3              0x03
#define PMAR_PO_LEVEL_PM4              0x04
#define PMAR_PO_LEVEL_PM5              0x05

#define PMAR_BINDER_LEVEL_E            0x01
#define PMAR_BINDER_LEVEL_F            0x02
#define PMAR_BINDER_LEVEL_AOS          0x03
#define PMAR_BINDER_LEVEL_XA           0x04
#define PMAR_BINDER_LEVEL_B1           0x05
#define PMAR_BINDER_LEVEL_B2           0x06
#define PMAR_BINDER_LEVEL_B3           0x07
#define PMAR_BINDER_LEVEL_B4           0x08
#define PMAR_BINDER_LEVEL_B5           0x09

#define PMAR_AMODE24                   0x00
#define PMAR_AMODE31                   0x10
#define PMAR_AMODEANY                  0x11
#define PMAR_AMODE64                   0x01

#define PMAR_ATTR1_REENTRANT           0x80
#define PMAR_ATTR1_REUSABLE            0x40
#define PMAR_ATTR1_OVERLAY             0x20
#define PMAR_ATTR1_TEST                0x10
#define PMAR_ATTR1_LOADONLY            0x08
#define PMAR_ATTR1_SCATTER             0x04
#define PMAR_ATTR1_EXECUTABLE          0x02
#define PMAR_ATTR1_ONE_BLOCK_NO_RLD    0x01

#define PMAR_ATTR2_BINDER_F_LEVEL_REQ  0x80
#define PMAR_ATTR2_ORG0                0x40
#define PMAR_ATTR2_NO_RLD              0x10
#define PMAR_ATTR2_NO_REPROCESS        0x08
#define PMAR_ATTR2_TEST_RAN            0x04
#define PMAR_ATTR2_REFRESHABLE         0x01

#define PMAR_ATTR3_BIG                 0x40
#define PMAR_ATTR3_PAGE_ALIGNMENT_REQ  0x20
#define PMAR_ATTR3_SSI_INFO            0x10
#define PMAR_ATTR3_APF_INFO            0x08
#define PMAR_ATTR3_PMARL_PRESENT       0x04
#define PMAR_ATTR3_SIGNED              0x02

#define PMAR_ATTR4_ALT_PRIMARY_NAME    0x80
#define PMAR_ATTR4_RMODE31             0x10
#define PMAR_ATTR4_ALIAS_ENTRY_AMODE   0x0C
#define PMAR_ATTR4_MAIN_ENTRY_AMODE    0x03

#define PMAR_ATTR5_RMODE64             0x80

#define PMARL_ATTR1_NO_PDS_CONVERT     0x80
#define PMARL_ATTR1_FETCHOPT_PRIME     0x40
#define PMARL_ATTR1_FETCHOPT_PACK      0x20
#define PMARL_ATTR1_XPLINK_REQ         0x10

#define PMARL_ATTR2_COMPRESSED         0x80
#define PMARL_ATTR2_SEG1_RMODE31       0x40
#define PMARL_ATTR2_SEG2_RMODE31       0x20
#define PMARL_ATTR2_SEG1_PAGE_ALIGN    0x08
#define PMARL_ATTR2_SEG2_PAGE_ALIGN    0x04
#define PMARL_ATTR2_FILL               0x02

#define PMARL_ATTR3_SEG1_RMODE64       0x80
#define PMARL_ATTR3_SEG2_RMODE64       0x40

#define PMARL_PO_SUBLVL_ZOSV1R3_PO4    0x01
#define PMARL_PO_SUBLVL_ZOSV1R5_PO4    0x02
#define PMARL_PO_SUBLVL_ZOSV1R7_PO4    0x03
#define PMARL_PO_SUBLVL_ZOSV1R8_PO5    0x01
#define PMARL_PO_SUBLVL_ZOSV1R10_PO5   0x02
#define PMARL_PO_SUBLVL_ZOSV1R13_PO5   0x03
#define PMARL_PO_SUBLVL_ZOSV2R1_PO5    0x04

#define PMARL_PM3_NAME_HIDDEN_ALIAS    0x80
#define PMARL_PM3_DLL_ENABLED          0x40
#define PMARL_PM3_MUST_DELETE_STORAGE  0x20
#define PMARL_PM3_BLITO_VALID          0x10
#define PMARL_PM3_MANGLED_NAME         0x08

#define PMARL_CMS_SYSTEM               0x80
#define PMARL_CMS_NO_CLEANUP           0x40
#define PMARL_CMS_STRINIT              0x20
#define PMARL_CMS_GEN_WITH_DOS         0x10
#define PMARL_CMS_GEN_WITH_ALL         0x08
#define PMARL_CMS_GEN_XA_INVALID       0x04
#define PMARL_CMS_GEN_XC_INVALID       0x02

#define PRAT_VERSION                   0x01
#define PRDT_VERSION                   0x01

#define LIDX_VERSION                   0x01

#define LIDX_ENTRY_TYPE_PSEGM          0x02
#define LIDX_ENTRY_TYPE_PGSTB          0x03
#define LIDX_ENTRY_TYPE_PDSIT          0x04

#define PSEGM_VERSION                  0x03

#define PSEGM_NO_LOAD                  0x80
#define PSEGM_DEFERRED                 0x40
#define PSEGM_EXECUTABLE               0x20
#define PSEGM_UNKNOWN                  0x08

/* The one-byte character either in the reloc header or the reloc entry
   itself that identifies the the type of the current entry or
   successive reloc entries.  */

enum po_reloc_type {
  PO_32		= 0x01,
  PO_32_EXT	= 0x03,
  PO_64		= 0x81,
  PO_64_EXT	= 0x83
};

/* The magic value that the reloc's flags must be set to when
   creating an unaligned reloc.  */
#define PO_32_RELOC_UNALIGNED	0x0C
#define PO_64_RELOC_UNALIGNED	0x0E

/* When a 64-bit reloc will cross a page boundary, its flags must be set
   to the following.  */
#define PO_64_RELOC_XPAGE	0x2E

#endif
