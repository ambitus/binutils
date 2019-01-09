cat <<EOF
${RELOCATING+OUTPUT_FORMAT(${OUTPUT_FORMAT})}
${RELOCATING-OUTPUT_FORMAT(${RELOCATEABLE_OUTPUT_FORMAT})}
ENTRY(_start)
SECTIONS {
  .tdatabss ALIGN(16) :
  {
    __tls_start = .;
    *(.tdata)
    *(.tbss)
    __tls_end = .;
  }

  .thdr ALIGN(16) :
  {
    __ehdr_start = .;
    /* e_ident[EI_MAG*]: magic number */
    BYTE(0x7F)
    BYTE(0x45)
    BYTE(0x4C)
    BYTE(0x46)
    /* e_ident[EI_CLASS]: 64-bit */
    BYTE(0x02)
    /* e_ident[EI_DATA]: big-endian */
    BYTE(0x02)
    /* eident[EI_VERSION]: v1 */
    BYTE(0x01)
    /* e_ident[EI_OSABI] */
    BYTE(0x00)
    /* e_ident[EI_ABIVERSION] */
    BYTE(0x00)
    /* e_ident[EI_PAD] */
    . += 7;
    /* e_type: ET_EXEC */
    SHORT(0x02)
    /* e_machine: S390 */
    SHORT(0x16)
    /* e_version: v1 */
    LONG(0x01)
    /* e_entry: nul */
    QUAD(0)
    /* e_phoff */
    QUAD(__phdr_start - __ehdr_start)
    /* e_shoff */
    QUAD(0)
    /* e_flags */
    LONG(0)
    /* e_ehsize */
    SHORT(__ehdr_end - __ehdr_start)
    /* e_phentsize */
    SHORT(__phdr_end - __phdr_start)
    /* e_phnum */
    SHORT((__tls_end - __tls_start > 0) ? 1 : 0)
    /* e_shentsize */
    SHORT(0)
    /* e_shnum */
    SHORT(0)
    /* e_shstrndx */
    SHORT(0)
    __ehdr_end = .;
    __phdr_start = .;
    /* p_type: PT_TLS */
    LONG(0x07)
    /* p_flags */
    LONG(0)
    /* p_offset */
    QUAD(0)
    /* p_vaddr */
    *(__tls_ptr)
    /* p_paddr */
    QUAD(0)
    /* p_filesz */
    QUAD(__tls_end - __tls_start)
    /* p_memsz */
    QUAD(__tls_end - __tls_start)
    /* p_align: 16 */
    QUAD(16)
    __phdr_end = .;
  }
}
EOF

