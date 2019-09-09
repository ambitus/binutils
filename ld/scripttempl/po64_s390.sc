# Copyright (C) 2019 Free Software Foundation, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.

cat <<EOF
${RELOCATING-OUTPUT_FORMAT(${RELOCATEABLE_OUTPUT_FORMAT})}
EOF

# Use the generic elf linker script when we're doing a final link.
test "x${RELOCATING+yes}" = xyes && . $srcdir/scripttempl/elf.sc
