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
TEMPLATE_NAME=elf32
GENERATE_SHLIB_SCRIPT=yes
GENERATE_PIE_SCRIPT=yes
NO_SMALL_DATA=yes
EXTRA_EM_FILE=s390
IREL_IN_PLT=

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
