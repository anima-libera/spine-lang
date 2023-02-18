
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

struct buf_t
{
	uint64_t len, cap;
	uint8_t* arr;
};
typedef struct buf_t buf_t;

uint64_t buf_append_zeros(buf_t* buf, uint64_t size)
{
	uint64_t new_len = buf->len + size;
	#define RESIZE_DA(da_cap_, da_arr_, new_len_) \
		if (da_cap_ < (new_len_)) \
		{ \
			if (da_cap_ == 0) \
			{ \
				da_cap_ = 256; \
			} \
			while (da_cap_ < (new_len_)) \
			{ \
				da_cap_ *= 2; \
			} \
			da_arr_ = realloc(da_arr_, da_cap_); \
		}
	RESIZE_DA(buf->cap, buf->arr, new_len);
	memset(&buf->arr[buf->len], 0, size);
	uint64_t old_len = buf->len;
	buf->len += size;
	return old_len;
}

uint64_t buf_append(buf_t* buf, uint8_t const* new_stuff, uint64_t size)
{
	uint64_t old_len = buf_append_zeros(buf, size);
	memcpy(&buf->arr[old_len], new_stuff, size);
	return old_len;
}

void buf_overwrite(buf_t* buf, uint64_t offset, uint8_t const* new_stuff, uint64_t size)
{
	assert(offset + size <= buf->len);
	memcpy(&buf->arr[offset], new_stuff, size);
}

struct addr_ofs_t
{
	uint64_t offset;
	uint64_t size;
	uint64_t value; // base value for data addr, func index for func addr
};
typedef struct addr_ofs_t addr_ofs_t;

struct da_addr_ofs_t
{
	uint64_t len, cap;
	addr_ofs_t* arr;
};
typedef struct da_addr_ofs_t da_addr_ofs_t;

void da_addr_ofs_append(da_addr_ofs_t* da, addr_ofs_t data_addr_ofs)
{
	RESIZE_DA(da->cap, da->arr, da->len + 1);
	da->arr[da->len] = data_addr_ofs;
	da->len++;
}

struct instr_t
{
	enum instr_type_t
	{
		INSTR_INIT_PROG,
		INSTR_HALT_PROG,
		INSTR_PUSH_FUNC,
		INSTR_CALL_POP,
		INSTR_INIT_FUNC,
		INSTR_RETURN_FUNC,
		INSTR_PUSH_IMM,
		INSTR_PRINT_CHAR,
		INSTR_DUP,
		INSTR_DISCARD,
		INSTR_ADD,
		INSTR_SUB,
		INSTR_IF_THEN_ELSE,
		INSTR_WHILE,
	}
	type;
	uint64_t value;
};
typedef struct instr_t instr_t;

struct da_instr_t
{
	uint64_t len, cap;
	instr_t* arr;
};
typedef struct da_instr_t da_instr_t;

void da_instr_append(da_instr_t* da, instr_t instr)
{
	RESIZE_DA(da->cap, da->arr, da->len + 1);
	da->arr[da->len] = instr;
	da->len++;
}

struct func_t
{
	da_instr_t code;
};
typedef struct func_t func_t;

struct da_func_t
{
	uint64_t len, cap;
	func_t* arr;
};
typedef struct da_func_t da_func_t;

void da_func_append(da_func_t* da, func_t func)
{
	RESIZE_DA(da->cap, da->arr, da->len + 1);
	da->arr[da->len] = func;
	da->len++;
}

uint64_t parse_func(da_func_t* da, uint64_t self_index, char const* src, bool is_entry_point)
{
	assert(da->len == self_index);
	da_func_append(da, (func_t){0});
	func_t* func = &da->arr[self_index];
	if (is_entry_point)
	{
		da_instr_append(&func->code,
			(instr_t){.type = INSTR_INIT_PROG});
	}
	else
	{
		da_instr_append(&func->code,
			(instr_t){.type = INSTR_INIT_FUNC});
	}
	uint64_t i = 0;
	while ((src[i] != '\0' && is_entry_point) || (src[i] != ']' && !is_entry_point))
	{
		if (src[i] == ' ')
		{
			i++;
		}
		else if (src[i] == '[')
		{
			// `[...]` pushes the address of a function that does `...`
			// one can use `c` to call it
			i++;
			uint64_t sub_func_index = da->len;
			i += parse_func(da, sub_func_index, &src[i], false);
			assert(src[i] == ']');
			i++;
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_PUSH_FUNC, .value = sub_func_index});
		}
		else if (src[i] == 'c')
		{
			i++;
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_CALL_POP});
		}
		else if ('0' <= src[i] && src[i] <= '9')
		{
			uint64_t value = 0;
			while ('0' <= src[i] && src[i] <= '9')
			{
				value = value * 10 + src[i] - '0';
				i++;
			}
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_PUSH_IMM, .value = value});
		}
		#define SIMPLE_INSTR(char_, instr_type_) \
			(src[i]==(char_)){i++;da_instr_append(&func->code, \
				(instr_t){.type=(instr_type_)});}
		else if SIMPLE_INSTR('p', INSTR_PRINT_CHAR)
		else if SIMPLE_INSTR('h', INSTR_HALT_PROG)
		else if SIMPLE_INSTR('r', INSTR_RETURN_FUNC)
		else if SIMPLE_INSTR('d', INSTR_DUP)
		else if SIMPLE_INSTR('g', INSTR_DISCARD)
		else if SIMPLE_INSTR('+', INSTR_ADD)
		else if SIMPLE_INSTR('-', INSTR_SUB)
		else if SIMPLE_INSTR('i', INSTR_IF_THEN_ELSE) // `<cond> <then> <else> i`
		else if SIMPLE_INSTR('w', INSTR_WHILE) // `[<cond>] [...] w` is `while(cond){...}`
		#undef SIMPLE_INSTR
		else
		{
			assert(false);
		}
	}
	if (is_entry_point)
	{
		da_instr_append(&func->code,
			(instr_t){.type = INSTR_HALT_PROG});
	}
	else
	{
		da_instr_append(&func->code,
			(instr_t){.type = INSTR_RETURN_FUNC});
	}
	return i;
}

int main(int argc, char const* const* argv)
{
	assert(argc == 2);
	char const* src = argv[1];

	// Parsing
	da_func_t func_da = {0};
	parse_func(&func_da, 0, src, true);

	// Buffer
	buf_t bin = {0};
	#define APPBYTES(...) \
		buf_append(&bin, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))
	#define OVWBYTES(offset_, ...) \
		buf_overwrite(&bin, offset_, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))

	// Data buffer
	buf_t data = {0};
	#define DATABYTES(...) \
		buf_append(&data, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))

	#define GET_BYTE(v_, byte_index_) \
		((((uint64_t)(v_)) >> (byte_index_ * 8)) & 0xff)
	#define APPLE16(v_) \
		APPBYTES(GET_BYTE(v_, 0), GET_BYTE(v_, 1))
	#define APPLE32(v_) \
		APPBYTES(GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3))
	#define APPLE64(v_) \
		APPBYTES(GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3), \
			GET_BYTE(v_, 4), GET_BYTE(v_, 5), GET_BYTE(v_, 6), GET_BYTE(v_, 7))
	#define OVWLE16(offset_, v_) \
		OVWBYTES(offset_, GET_BYTE(v_, 0), GET_BYTE(v_, 1))
	#define OVWLE32(offset_, v_) \
		OVWBYTES(offset_, GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3))
	#define OVWLE64(offset_, v_) \
		OVWBYTES(offset_, GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3), \
			GET_BYTE(v_, 4), GET_BYTE(v_, 5), GET_BYTE(v_, 6), GET_BYTE(v_, 7))

	// See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
	// Also see https://github.com/vishen/go-x64-executable/blob/master/main.go

	// ELF 64-bits header
	APPBYTES(0x7f, 'E', 'L', 'F'); // ELF magic number
	APPBYTES(2); // 1 -> 32-bits, 2 -> 64-bits
	APPBYTES(1); // 1 -> little endian, 2 -> big endian
	APPBYTES(1); // ELF format version (still 1 in 2023)
	APPBYTES(3); // Target Linux
	APPBYTES(0); // Required dynamic linker version (we don't care)
	APPBYTES(0, 0, 0, 0, 0, 0, 0); // Padding
	APPLE16(2); // This is an executable
	APPLE16(0x3e); // Target x86-64
	APPLE32(1); // ELF format version (again??)
	uint64_t entry_point_address_ofs = APPLE64(0); // Entry point address
	uint64_t program_header_table_ofs_ofs = APPLE64(0x40); // Program header table offset in binary
	APPLE64(0); // Section header table offset in binary (we don't have one)
	APPLE32(0); // Target architecture dependent flags
	uint64_t elf_header_size_ofs = APPLE16(0); // Size of this header
	APPLE16(0x38); // Size of a program header table entry (must be this value in 64bits?)
	uint64_t program_header_table_length_ofs = APPLE16(0); // Number of entries in program header table
	APPLE16(0); // Size of a section header table entry (we don't have one)
	APPLE16(0); // Number of entries in section header table
	APPLE16(0); // Index of the section header table entry that has the section names
	uint64_t elf_header_size = bin.len;
	OVWLE16(elf_header_size_ofs, elf_header_size);

	// Program header table
	uint64_t program_header_table_ofs = bin.len;
	OVWLE64(program_header_table_ofs_ofs, program_header_table_ofs);
	uint64_t program_header_table_length = 0;

	// Code segment or something
	APPLE32(1); // Loadable segment
	APPLE32((1<<0/*Readable*/) | (1<<1/*Writable*/) | (1<<2/*Executable*/)); // Flags
	uint64_t code_segment_ofs_ofs = APPLE64(0); // Offset of segment in binary
	uint64_t code_segment_address = 0x400000;
	uint64_t code_segment_address_ofs_1 = APPLE64(0); // Address of segment in virtual memory
	uint64_t code_segment_address_ofs_2 = APPLE64(0); // Address of segment in physical memory (wtf)
	uint64_t code_segment_size_ofs_1 = APPLE64(0); // Segment size in binary
	uint64_t code_segment_size_ofs_2 = APPLE64(0); // Segment size in memory
	APPLE64(0); // Alignment
	program_header_table_length++;
	#define COMPLETE_CODE_SEGMENT_INFO(offset_, size_) \
		OVWLE64(code_segment_ofs_ofs, (offset_)); \
		OVWLE64(code_segment_address_ofs_1, (offset_) + code_segment_address); \
		OVWLE64(code_segment_address_ofs_2, (offset_) + code_segment_address); \
		OVWLE64(code_segment_size_ofs_1, (size_)); \
		OVWLE64(code_segment_size_ofs_2, (size_))

	// Data segment
	APPLE32(1); // Loadable segment
	APPLE32((1<<0/*Readable*/) | (1<<1/*Writable*/)); // Flags
	uint64_t data_segment_ofs_ofs = APPLE64(0); // Offset of segment in binary
	uint64_t data_segment_address = 0x600000;
	uint64_t data_segment_address_ofs_1 = APPLE64(0); // Address of segment in virtual memory
	uint64_t data_segment_address_ofs_2 = APPLE64(0); // Address of segment in physical memory (wtf)
	uint64_t data_segment_size_ofs_1 = APPLE64(0); // Segment size in binary
	uint64_t data_segment_size_ofs_2 = APPLE64(0); // Segment size in memory
	APPLE64(0); // Alignment
	program_header_table_length++;
	#define COMPLETE_DATA_SEGMENT_INFO(offset_, size_) \
		OVWLE64(data_segment_ofs_ofs, (offset_)); \
		OVWLE64(data_segment_address_ofs_1, (offset_) + data_segment_address); \
		OVWLE64(data_segment_address_ofs_2, (offset_) + data_segment_address); \
		OVWLE64(data_segment_size_ofs_1, (size_)); \
		OVWLE64(data_segment_size_ofs_2, (size_))

	// Spine call stack
	APPLE32(1); // Loadable segment
	APPLE32((1<<0/*Readable*/) | (1<<1/*Writable*/)); // Flags
	APPLE64(0); // Offset of segment in binary
	uint64_t call_stack_segment_address = 0x800000;
	APPLE64(call_stack_segment_address); // Address of segment in virtual memory
	APPLE64(call_stack_segment_address); // Address of segment in physical memory (wtf)
	APPLE64(0); // Segment size in binary
	uint64_t call_stack_segment_size = 0x8000;
	APPLE64(call_stack_segment_size); // Segment size in memory
	APPLE64(0); // Alignment
	program_header_table_length++;
	
	OVWLE16(program_header_table_length_ofs, program_header_table_length);

	#define BITS(b7_, b6_, b5_, b4_, b3_, b2_, b1_, b0_) \
		(((b7_)<<7) | ((b6_)<<6) | ((b5_)<<5) | ((b4_)<<4) | \
			((b3_)<<3) | ((b2_)<<2) | ((b1_)<<1) | ((b0_)<<0))
	#define REX(w_, r_, x_, b_) \
		BITS(0, 1, 0, 0, (w_), (r_), (x_), (b_))
	enum reg_t { RAX = 0, RBX = 3, RCX = 1, RDX = 2, RSP = 4, RBP = 5, RSI = 6, RDI = 7 };
	#define GET_BIT(v_, bit_index_)	\
		((((uint64_t)(v_)) >> (bit_index_)) & 1)
	// For `mod_` see https://wiki.osdev.org/X86-64_Instruction_Encoding#32.2F64-bit_addressing
	#define MODRM(mod_, reg_, rm_) \
		BITS(GET_BIT(mod_, 1), GET_BIT(mod_, 0), \
			GET_BIT(reg_, 2), GET_BIT(reg_, 1), GET_BIT(reg_, 0), \
			GET_BIT(rm_, 2), GET_BIT(rm_, 1), GET_BIT(rm_, 0))
	#define MOD11 \
		((1<<1)|(1<<0))
	#define MOD01 \
		((0<<1)|(1<<0))
	#define MOD00 \
		((0<<1)|(0<<0))

	#define SYSCALL() \
		APPBYTES(0x0f, 0x05)

	struct da_addr_ofs_t data_address_offsets = {0};
	#define APPDATAADDR32(v_) \
		da_addr_ofs_append(&data_address_offsets, \
			(addr_ofs_t){.offset = APPLE32(v_), .size = 32, .value = (v_)})

	struct da_addr_ofs_t func_address_offsets = {0};
	#define APPFUNCADDR32(func_index_) \
		da_addr_ofs_append(&func_address_offsets, \
			(addr_ofs_t){.offset = APPLE32(func_index_), .size = 32, .value = (func_index_)})
	
	#define MOV_IMM32_TO_R64(imm32_, reg64_) \
		APPBYTES(REX(1,0,0,0), 0xc7, MODRM(MOD11, 0, (reg64_))); APPLE32(imm32_)
	#define MOV_DATAADDR32_TO_R64(imm32_, reg64_) \
		APPBYTES(REX(1,0,0,0), 0xc7, MODRM(MOD11, 0, (reg64_))); APPDATAADDR32(imm32_)
	#define MOV_FUNCADDR32_TO_R64(func_index_, reg64_) \
		APPBYTES(REX(1,0,0,0), 0xc7, MODRM(MOD11, 0, (reg64_))); APPFUNCADDR32(func_index_)

	#define MOV_R64_TO_R64(reg64_src_, reg64_dst_) \
		APPBYTES(REX(1,0,0,0), 0x89, MODRM(MOD11, (reg64_src_), (reg64_dst_)))

	#define MOV_R64_TO_MEMPOINTEDBY_R64(reg64_src_, reg64_pointingto_dst_) \
		APPBYTES(REX(1,0,0,0), 0x89, MODRM(MOD01, (reg64_src_), (reg64_pointingto_dst_)), 0)
	#define MOV_MEMPOINTEDBY_R64_TO_R64(reg64_pointingto_src_, reg64_dst_) \
		APPBYTES(REX(1,0,0,0), 0x8b, MODRM(MOD01, (reg64_dst_), (reg64_pointingto_src_)), 0)

	#define PUSH_IMM32(imm32_) \
		APPBYTES(0x68); APPLE32(imm32_)
	#define POP64_TO_R64(reg64_) \
		APPBYTES(0x58 + (reg64_))
	#define PUSH_R64(reg64_) \
		APPBYTES(0x50 + reg64_)
		
	#define CALL_R64(reg64_) \
		APPBYTES(0xff, MODRM(MOD11, 2, (reg64_)))
	#define RET() \
		APPBYTES(0xc3)

	#define ADD_IMM32_TO_R64(imm32_, reg64_) \
		APPBYTES(REX(1,0,0,0), 0x81, MODRM(MOD11, 0, reg64_)); APPLE32(imm32_)
	#define SUB_IMM32_TO_R64(imm32_, reg64_) \
		APPBYTES(REX(1,0,0,0), 0x81, MODRM(MOD11, 5, reg64_)); APPLE32(imm32_)

	#define CMOVE_R64_TO_R64(reg64_src_, reg64_dst_) \
		APPBYTES(REX(1,0,0,0), 0x0f, 0x44, MODRM(MOD11, reg64_dst_, reg64_src_))
	#define JE_REL8(rel8_) \
		(APPBYTES(0x74, rel8_) + 1 /* evaluates to rel8's offset */)
	#define JMP_REL8(rel8_) \
		(APPBYTES(0xeb, rel8_) + 1 /* evaluates to rel8's offset */)
	#define SIGNED_BYTE(v_) \
		((union{uint8_t u; int8_t s;}){.s = (v_)}.u)
	
	#define ADD_R64_TO_R64(reg64_src_, reg64_dst_) \
		APPBYTES(REX(1,0,0,0), 0x01, MODRM(MOD11, reg64_src_, reg64_dst_))
	#define SUB_R64_TO_R64(reg64_src_, reg64_dst_) \
		APPBYTES(REX(1,0,0,0), 0x29, MODRM(MOD11, reg64_src_, reg64_dst_))

	#define PUSH_R64_TO_RBPCALLSTACK(reg64_) \
		MOV_R64_TO_MEMPOINTEDBY_R64(reg64_, RBP); \
		SUB_IMM32_TO_R64(8, RBP)
	#define POP_RBPCALLSTACK_TO_R64(reg64_) \
		ADD_IMM32_TO_R64(8, RBP); \
		MOV_MEMPOINTEDBY_R64_TO_R64(RBP, reg64_)

	#define IMUL_R64_TO_R64(reg64_src_, reg64_dst_) \
		APPBYTES(REX(1,0,0,0), 0x0f, 0xaf, MODRM(MOD11, reg64_dst_, reg64_src_))
	#define IMUL_R64_WITH_IMM32_TO_R64(reg64_src_a_, imm32_src_b_, reg64_dst_) \
		APPBYTES(REX(1,0,0,0), 0x69, MODRM(MOD11, reg64_dst_, reg64_src_a_)); APPLE32(imm32_src_b_)

	// turns stuff like 3 into %rbp+3*8
	// note that the spine call stack grows doenward, and that index 1 here is top
	#define TURN_RBPCALLSTACK_R64_1INDEX_INTO_ADDR(reg64_) \
		IMUL_R64_WITH_IMM32_TO_R64(reg64_, 8, reg64_); \
		ADD_R64_TO_R64(RBP, reg64_)

	// Program code
	uint64_t code_offset = bin.len;
	OVWLE64(entry_point_address_ofs, code_segment_address + code_offset);

	#if 0
	// Print a string stored in data segment via pointer
	MOV_IMM32_TO_R64(1, RAX); // `write` syscall number
	MOV_IMM32_TO_R64(1, RDI); // `stdout` file descriptor
	uint64_t message_address = data_segment_address + DATABYTES('u', 'w', 'u', '\n');
	MOV_DATAADDR32_TO_R64(message_address, RSI);
	MOV_IMM32_TO_R64(4, RDX); // message length
	SYSCALL();
	#endif

	uint64_t func_offset[func_da.len];

	for (uint64_t func_i = 0; func_i < func_da.len; func_i++)
	{
		func_offset[func_i] = bin.len;
		for (uint64_t instr_i = 0; instr_i < func_da.arr[func_i].code.len; instr_i++)
		{
			instr_t instr = func_da.arr[func_i].code.arr[instr_i];
			switch (instr.type)
			{
				case INSTR_INIT_PROG:
					// %rbp is used as the spine call stack pointer
					// it grows downward
					MOV_IMM32_TO_R64(call_stack_segment_address+call_stack_segment_size-8, RBP);
				break;
				case INSTR_HALT_PROG:
					MOV_IMM32_TO_R64(60, RAX); // `exit` syscall number
					MOV_IMM32_TO_R64(0, RDI); // exit code value
					SYSCALL();
				break;
				case INSTR_PUSH_FUNC:
					MOV_FUNCADDR32_TO_R64(instr.value, RAX);
					PUSH_R64(RAX);
				break;
				case INSTR_CALL_POP:
					POP64_TO_R64(RAX);
					CALL_R64(RAX);
				break;
				case INSTR_INIT_FUNC:
					// The `call` to here pushed the return address on the data stack
					// so we move it to the spine call stack
					POP64_TO_R64(RAX);
					PUSH_R64_TO_RBPCALLSTACK(RAX);
				break;
				case INSTR_RETURN_FUNC:
					// The return address was put on the spine call stack
					// so we move it back to the data stack for `ret` to work
					POP_RBPCALLSTACK_TO_R64(RAX);
					PUSH_R64(RAX);
					RET();
				break;
				case INSTR_PUSH_IMM:
					PUSH_IMM32(instr.value);
				break;
				case INSTR_PRINT_CHAR:
					MOV_IMM32_TO_R64(1, RAX); // `write` syscall number
					MOV_IMM32_TO_R64(1, RDI); // `stdout` file descriptor
					MOV_R64_TO_R64(RSP, RSI); // ptr to string is stack ptr
					MOV_IMM32_TO_R64(1, RDX); // print 1 char
					SYSCALL();
					POP64_TO_R64(RAX); // discard the char
				break;
				case INSTR_DUP:
					POP64_TO_R64(RAX);
					PUSH_R64(RAX);
					PUSH_R64(RAX);
				break;
				case INSTR_DISCARD:
					POP64_TO_R64(RAX);
				break;
				case INSTR_ADD:
					POP64_TO_R64(RAX);
					POP64_TO_R64(RBX);
					ADD_R64_TO_R64(RAX, RBX);
					PUSH_R64(RBX);
				break;
				case INSTR_SUB:
					POP64_TO_R64(RAX);
					POP64_TO_R64(RBX);
					SUB_R64_TO_R64(RAX, RBX);
					PUSH_R64(RBX);
				break;
				case INSTR_IF_THEN_ELSE:
					// if-then-else here pops two things and a condition
					// and pushes back only one of the things, choosing according to condition
					POP64_TO_R64(RAX); // else
					POP64_TO_R64(RBX); // then
					POP64_TO_R64(RCX); // condition
					SUB_IMM32_TO_R64(0, RCX); // compare condition with 0 (set cc flags)
					CMOVE_R64_TO_R64(RAX, RBX); // result = condition == 0 ? else : then
					PUSH_R64(RBX);
				break;
				case INSTR_WHILE:
					POP64_TO_R64(RAX); // body function
					POP64_TO_R64(RCX); // condition function
					// save the body and condition functions to the callsatck because
					// calling them can trash %rax and %rcx
					PUSH_R64_TO_RBPCALLSTACK(RAX);
					PUSH_R64_TO_RBPCALLSTACK(RCX);
					{
						uint64_t loop_top = bin.len;
						
						// call condition function (top of spine call stack)
						MOV_IMM32_TO_R64(1, RAX);
						TURN_RBPCALLSTACK_R64_1INDEX_INTO_ADDR(RAX);
						MOV_MEMPOINTEDBY_R64_TO_R64(RAX, RAX);
						CALL_R64(RAX);

						// pop and break loop if zero
						POP64_TO_R64(RBX);
						SUB_IMM32_TO_R64(0, RBX);
						uint64_t jmpcc_break_rel8_ofs = JE_REL8(0);
						uint64_t jmpcc_break_ofs_base = bin.len;

						// call body function
						MOV_IMM32_TO_R64(2, RAX);
						TURN_RBPCALLSTACK_R64_1INDEX_INTO_ADDR(RAX);
						MOV_MEMPOINTEDBY_R64_TO_R64(RAX, RAX);
						CALL_R64(RAX);

						// loop back
						uint64_t jmp_loop_rel8_ofs = JMP_REL8(0);
						uint64_t loop_bottom = bin.len;

						// resolve relative jump distances
						OVWBYTES(jmpcc_break_rel8_ofs, loop_bottom - jmpcc_break_ofs_base);
						OVWBYTES(jmp_loop_rel8_ofs,
							SIGNED_BYTE((signed)loop_top - (signed)loop_bottom));
					}
					POP_RBPCALLSTACK_TO_R64(RAX); // discard
					POP_RBPCALLSTACK_TO_R64(RAX); // discard
				break;
				default:
					assert(false);
				break;
			}
		}
	}

	// Fill addresses of functions
	for (uint64_t i = 0; i < func_address_offsets.len; i++)
	{
		addr_ofs_t func_address_offset = func_address_offsets.arr[i];
		if (func_address_offset.size == 32)
		{
			OVWLE32(func_address_offset.offset,
				code_segment_address + func_offset[func_address_offset.value]);
		}
		else if (func_address_offset.size == 64)
		{
			OVWLE64(func_address_offset.offset,
				code_segment_address + func_offset[func_address_offset.value]);
		}
		else
		{
			assert(false);
		}
	}

	// End of code
	COMPLETE_CODE_SEGMENT_INFO(code_offset, bin.len - code_offset);

	#if 0
		printf("base address: 0x%x\n", code_offset);
		for (uint64_t i = code_offset; i < bin.len; i++)
		{
			printf("%02x ", bin.arr[i]);
		}
		printf("\n");
	#endif

	// Data
	#if 0
		buf_append_zeros(&bin, bin.len % (8 * 4096)); // Page align (is this necessary?)
	#endif
	uint64_t data_offset = bin.len;
	COMPLETE_DATA_SEGMENT_INFO(data_offset, data.len);
	buf_append(&bin, data.arr, data.len);

	// Correct addresses that are supposed to point to stuff in the data segment
	for (uint64_t i = 0; i < data_address_offsets.len; i++)
	{
		addr_ofs_t data_address_offset = data_address_offsets.arr[i];
		if (data_address_offset.size == 32)
		{
			OVWLE32(data_address_offset.offset, data_address_offset.value + data_offset);
		}
		else if (data_address_offset.size == 64)
		{
			OVWLE64(data_address_offset.offset, data_address_offset.value + data_offset);
		}
		else
		{
			assert(false);
		}
	}

	// Write to file
	FILE* file = fopen("bin/jaaj", "wb");
	assert(file != NULL);
	fwrite(bin.arr, 1, bin.len, file);
	fclose(file);

	return 0;
}
