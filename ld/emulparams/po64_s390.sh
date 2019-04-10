SCRIPT_NAME=po64_s390
ELFSIZE=64
OUTPUT_FORMAT="po64-s390"
NO_REL_RELOCS=yes
TEXT_START_ADDR=0x0
MAXPAGESIZE="CONSTANT (MAXPAGESIZE)"
COMMONPAGESIZE="CONSTANT (COMMONPAGESIZE)"
ARCH="s390:64-bit"
MACHINE=
NOP=0x07070707
# TEMPLATE_NAME=po64_s390
# GENERATE_SHLIB_SCRIPT=yes
# GENERATE_PIE_SCRIPT=yes
NO_SMALL_DATA=yes
# EXTRA_EM_FILE=s390
IREL_IN_PLT=

# Provide a very minimal elf header
OTHER_READONLY_SECTIONS="
  .thdr ALIGN(16) :
  {
    PROVIDE_HIDDEN (__ehdr_start = .);
    /* e_ident[EI_MAG*]: magic number */
    BYTE (0x7F)
    BYTE (0x45)
    BYTE (0x4C)
    BYTE (0x46)
    /* e_ident[EI_CLASS]: 64-bit */
    BYTE (0x02)
    /* e_ident[EI_DATA]: big-endian */
    BYTE (0x02)
    /* eident[EI_VERSION]: v1 */
    BYTE (0x01)
    /* e_ident[EI_OSABI] */
    BYTE (0x00)
    /* e_ident[EI_ABIVERSION] */
    BYTE (0x00)
    /* e_ident[EI_PAD] */
    . += 7;
    /* e_type: ET_EXEC */
    SHORT (0x02)
    /* e_machine: S390 */
    SHORT (0x16)
    /* e_version: v1 */
    LONG (0x01)
    /* e_entry: nul */
    QUAD (0)
    /* e_phoff */
    QUAD (__phdr_start - __ehdr_start)
    /* e_shoff */
    QUAD (0)
    /* e_flags */
    LONG (0)
    /* e_ehsize */
    SHORT (__ehdr_end - __ehdr_start)
    /* e_phentsize */
    SHORT (__phdr_end - __phdr_start)
    /* e_phnum */
    SHORT ((__preinit_array_start - __tdata_start > 0) ? 1 : 0)
    /* e_shentsize */
    SHORT (0)
    /* e_shnum */
    SHORT (0)
    /* e_shstrndx */
    SHORT (0)
    __ehdr_end = .;
    __phdr_start = .;
    /* p_type: PT_TLS */
    LONG (0x07)
    /* p_flags */
    LONG (0)
    /* p_offset */
    QUAD (0)
    /* p_vaddr */
    *(__tls_ptr)
    /* p_paddr */
    QUAD (0)
    /* p_filesz */
    QUAD (__preinit_array_start - __tdata_start)
    /* p_memsz */
    QUAD (__preinit_array_start - __tdata_start)
    /* p_align: 16 */
    QUAD (16)
    __phdr_end = .;
  }
"

# Treat a host that matches the target with the possible exception of "x"
# in the name as if it were native.
if test `echo "$host" | sed -e s/390x/390/` \
   = `echo "$target" | sed -e s/390x/390/`; then
  case " $EMULATION_LIBPATH " in
    *" ${EMULATION_NAME} "*)
      NATIVE=yes
  esac
fi

# Look for 64 bit target libraries in /lib64, /usr/lib64 etc., first
# on z/OS.
case "$target" in
  s390*-zos*)
    case "$EMULATION_NAME" in
      *64*)
	LIBPATH_SUFFIX=64 ;;
    esac
    ;;
esac

RELOCATEABLE_OUTPUT_FORMAT="elf64-s390"
