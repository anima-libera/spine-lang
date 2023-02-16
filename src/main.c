
#include <stdio.h>
#include <stdint.h>


int main(void)
{
	FILE* file = fopen("local/jaaj", "wb");

	#define FBYTES(...) \
		fwrite(&(uint8_t[]){__VA_ARGS__}, 1, sizeof((uint8_t[]){__VA_ARGS__}), file)
	#define GET_BYTE(v_, byte_index_) \
		((((uint64_t)(v_)) >> (byte_index_ * 8)) & 0xff)
	#define FLE16(v_) \
		FBYTES(GET_BYTE(v_, 0), GET_BYTE(v_, 1))
	#define FLE32(v_) \
		FBYTES(GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3))
	#define FLE64(v_) \
		FBYTES(GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3), \
			GET_BYTE(v_, 4), GET_BYTE(v_, 5), GET_BYTE(v_, 6), GET_BYTE(v_, 7))

	// See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
	// Also see https://github.com/vishen/go-x64-executable/blob/master/main.go

	// ELF 64-bits header
	FBYTES(0x7f, 'E', 'L', 'F'); // ELF magic number
	FBYTES(2); // 1 -> 32-bits, 2 -> 64-bits
	FBYTES(1); // 1 -> little endian, 2 -> big endian
	FBYTES(1); // ELF format version (still 1 in 2023)
	FBYTES(3); // Target Linux
	FBYTES(0); // Required dynamic linker version (we don't care)
	FBYTES(0, 0, 0, 0, 0, 0, 0); // Padding
	FLE16(2); // This is an executable
	FLE16(0x3e); // Target x86-64
	FLE32(1); // ELF format version (again??)
	uint64_t segment_address = 0x400000;
	FLE64(segment_address+0x40+0x38); // Entry point address
	FLE64(0x40); // Program header table offset in binary
	FLE64(0); // Section header table offset in binary (we don't have one)
	FLE32(0); // Target architecture dependent flags
	FLE16(64); // Size of this header
	FLE16(0x38); // Size of a program header table entry (must be this value in 64bits?)
	FLE16(1); // Number of entries in program header table
	FLE16(0); // Size of a section header table entry (we don't have one)
	FLE16(0); // Number of entries in section header table
	FLE16(0); // Index of the section header table entry that has the section names

	// Program header table
	FLE32(1); // Loadable segment
	FLE32((1<<0/*Readable*/) | (1<<1/*Writable*/) | (1<<2/*Executable*/)); // Flags
	FLE64(0); // Offset of segment in binary
	FLE64(segment_address); // Address of segment in virtual memory
	FLE64(segment_address); // Address of segment in physical memory (wtf)
	#define SEG_SIZE 512
	FLE64(SEG_SIZE); // Segment size in binary
	FLE64(SEG_SIZE); // Segment size in memory
	FLE64(0); // Alignment

	// Program code
	FBYTES(0x48, 0xc7, 0xc0); FLE32(60); // movq $60, %rax (exit syscall)
	FBYTES(0x48, 0xc7, 0xc7); FLE32(0); // movq $0, %rdi
	FBYTES(0x0f, 0x05); // syscall

	fclose(file);
	return 0;
}
