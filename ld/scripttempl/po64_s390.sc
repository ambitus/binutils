cat <<EOF
${RELOCATING-OUTPUT_FORMAT(${RELOCATEABLE_OUTPUT_FORMAT})}
EOF

# Use the generic elf linker script when we're doing a final link.
test "x${RELOCATING+yes}" = xyes && . $srcdir/scripttempl/elf.sc
