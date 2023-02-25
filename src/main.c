
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
	#define RESIZE_DA(da_cap_, da_arr_, new_len_, size_of_elem_) \
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
			da_arr_ = realloc(da_arr_, (da_cap_) * (size_of_elem_)); \
		}
	RESIZE_DA(buf->cap, buf->arr, new_len, sizeof (uint8_t));
	memset(&buf->arr[buf->len], 0, size);
	uint64_t old_len = buf->len;
	buf->len += size;
	return old_len;
}

void buf_append_byte(buf_t* buf, uint8_t byte)
{
	RESIZE_DA(buf->cap, buf->arr, buf->len + 1, sizeof (uint8_t));
	buf->arr[buf->len] = byte;
	buf->len++;
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
	uint64_t ofs;   // offset in bin
	uint64_t size;  // size in bits of the value in bin
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
	RESIZE_DA(da->cap, da->arr, da->len + 1, sizeof (addr_ofs_t));
	da->arr[da->len] = data_addr_ofs;
	da->len++;
}

struct instr_t
{
	enum instr_type_t
	{
		INSTR_INIT_PROG,
		INSTR_HALT_PROG, // TODO test
		INSTR_PUSH_FUNC,
		INSTR_CALL_POP,
		INSTR_CALL_FUNC,
		INSTR_INIT_FUNC,
		INSTR_RETURN_FUNC, // TODO test
		INSTR_PUSH_IMM,
		INSTR_PUSH_SV, // special value
		INSTR_PUSH_DATA_ADDR_AND_SIZE, // -- ptr size
		INSTR_PRINT_CHAR,
		INSTR_SYSCALL6, // arg6 arg5 arg4 arg3 arg2 arg1 number -- result
		INSTR_DUP, // a -- a a
		INSTR_DISCARD, // a --
		INSTR_SWAP, // a b -- b a
		INSTR_PEEK, // ... i[n+1] h[n] g[n-1] ... b[1] a[0] n -- ... b a h(copied)
		INSTR_OVW, // ... g[n] ... a[0] h n -- ... h(g is overwritten) ... a
		INSTR_ADD, // a b -- (a+b)
		INSTR_SUB, // a b -- (a-b)
		INSTR_MUL, // a b -- (a*b)
		INSTR_DIV, // a b -- (a/b)
		INSTR_MOD, // a b -- (a%b)
		INSTR_IF_THEN_ELSE, // `<cond> <then> <else> i`
		INSTR_WHILE, // `[<cond>] [...] w` is `while(cond){...}`
		INSTR_READ, // ptr -- (*ptr)
		INSTR_WRITE, // ... val ptr -- ... ((*ptr) is overwritten with val)
	}
	type;
	uint64_t value;
};
typedef struct instr_t instr_t;

enum special_value_t
{
	SV_DATA_START,
};
typedef enum special_value_t special_value_t; 

struct da_instr_t
{
	uint64_t len, cap;
	instr_t* arr;
};
typedef struct da_instr_t da_instr_t;

void da_instr_append(da_instr_t* da, instr_t instr)
{
	RESIZE_DA(da->cap, da->arr, da->len + 1, sizeof (instr_t));
	da->arr[da->len] = instr;
	da->len++;
}

struct func_t
{
	da_instr_t code;
	char name;
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
	RESIZE_DA(da->cap, da->arr, da->len + 1, sizeof (func_t));
	da->arr[da->len] = func;
	da->len++;
}

struct da_buf_t
{
	uint64_t len, cap;
	buf_t* arr;
};
typedef struct da_buf_t da_buf_t;

void da_buf_append(da_buf_t* da, buf_t value)
{
	RESIZE_DA(da->cap, da->arr, da->len + 1, sizeof (buf_t));
	da->arr[da->len] = value;
	da->len++;
}

uint64_t parse_func(da_func_t* func_da, da_buf_t* buf_da,
	uint64_t self_index, char const* src, bool is_entry_point, char name)
{
	uint64_t rw_size = 64; // size for `?` and `!` instr
	assert(func_da->len == self_index);
	da_func_append(func_da, (func_t){0});
	func_t* func = &func_da->arr[self_index];
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
	func->name = name;
	uint64_t i = 0;
	while ((src[i] != '\0' && is_entry_point) || (src[i] != ']' && !is_entry_point))
	{
		if (src[i] == ' ' || src[i] == '\t' || src[i] == '\n')
		{
			i++;
		}
		else if (src[i] == '[')
		{
			// `[...]` pushes the address of a function that does `...`
			// one can use `c` to call it
			i++;
			uint64_t sub_func_index = func_da->len;
			i += parse_func(func_da, buf_da, sub_func_index, &src[i], false, '\0');
			func = &func_da->arr[self_index]; // realloc of the da might invalidate this ptr
			assert(src[i] == ']');
			i++;
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_PUSH_FUNC, .value = sub_func_index});
		}
		else if (src[i] == '@')
		{
			// define named function
			i++;
			char name = src[i];
			assert('A' <= name && name <= 'Z');
			i++;
			assert(src[i] == '[');
			i++;
			uint64_t sub_func_index = func_da->len;
			i += parse_func(func_da, buf_da, sub_func_index, &src[i], false, name);
			func = &func_da->arr[self_index]; // realloc of the da might invalidate this ptr
			assert(src[i] == ']');
			i++;
		}
		else if ('A' <= src[i] && src[i] <= 'Z')
		{
			// push named function address
			char name = src[i];
			i++;
			uint64_t func_index = UINT64_MAX;
			for (int64_t i = func_da->len-1; i >= 0; i--)
			{
				if (func_da->arr[i].name == name)
				{
					func_index = i;
					break;
				}
			}
			assert(func_index != UINT64_MAX);
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_CALL_FUNC, .value = func_index});
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
		else if (src[i] == '_')
		{
			i++;
			special_value_t sv;
			switch (src[i])
			{
				case 'd':
					sv = SV_DATA_START;
				break;
				default:
					assert(false);
				break;
			}
			i++;
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_PUSH_SV, .value = sv});
		}
		else if (src[i] == '\'')
		{
			i++;
			uint64_t char_ascii_code = src[i];
			i++;
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_PUSH_IMM, .value = char_ascii_code});
		}
		else if (src[i] == '\"')
		{
			i++;
			buf_t buf = {0};
			while (src[i] != '\"')
			{
				uint64_t char_ascii_code = src[i];
				buf_append_byte(&buf, char_ascii_code);
				i++;
			}
			i++; // terminating double-quote
			da_buf_append(buf_da, buf);
			uint64_t buf_index = buf_da->len-1;
			da_instr_append(&func->code,
				(instr_t){.type = INSTR_PUSH_DATA_ADDR_AND_SIZE, .value = buf_index});
		}
		else if (src[i] == '?' || src[i] == '!')
		{
			enum instr_type_t instr_type = src[i] == '?' ? INSTR_READ : INSTR_WRITE;
			i++;
			if (src[i] == 'b' || src[i] == 'q')
			{
				rw_size = src[i] == 'b' ? 8 : 64;
				i++;
			}
			da_instr_append(&func->code,
				(instr_t){.type = instr_type, .value = rw_size});
		}
		#define SIMPLE_INSTR(char_, instr_type_) \
			(src[i]==(char_)){i++;da_instr_append(&func->code, \
				(instr_t){.type=(instr_type_)});}
		else if SIMPLE_INSTR('p', INSTR_PRINT_CHAR)
		else if SIMPLE_INSTR('k', INSTR_SYSCALL6)
		else if SIMPLE_INSTR('c', INSTR_CALL_POP)
		else if SIMPLE_INSTR('h', INSTR_HALT_PROG)
		else if SIMPLE_INSTR('r', INSTR_RETURN_FUNC)
		else if SIMPLE_INSTR('d', INSTR_DUP)
		else if SIMPLE_INSTR('g', INSTR_DISCARD)
		else if SIMPLE_INSTR('s', INSTR_SWAP)
		else if SIMPLE_INSTR('n', INSTR_PEEK)
		else if SIMPLE_INSTR('o', INSTR_OVW)
		else if SIMPLE_INSTR('+', INSTR_ADD)
		else if SIMPLE_INSTR('-', INSTR_SUB)
		else if SIMPLE_INSTR('*', INSTR_MUL)
		else if SIMPLE_INSTR('/', INSTR_DIV)
		else if SIMPLE_INSTR('%', INSTR_MOD)
		else if SIMPLE_INSTR('i', INSTR_IF_THEN_ELSE)
		else if SIMPLE_INSTR('w', INSTR_WHILE)
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

char* read_file(char const* filepath)
{
	FILE* file = fopen(filepath, "r");
	if (file == NULL)
	{
		fprintf(stderr, "File error: failed to open \"%s\"\n", filepath);
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long const length = ftell(file);
	fseek(file, 0, SEEK_SET);
	char* buffer = malloc((length+1) * sizeof(char));
	size_t const length_read = fread(buffer, sizeof(char), length, file);
	fclose(file);
	if (length_read != (unsigned int)length)
	{
		fprintf(stderr, "File error: failed to properly read \"%s\"\n",
			filepath);
		free(buffer);
		return NULL;
	}
	buffer[length] = '\0';
	return buffer;
}

int main(int argc, char const* const* argv)
{
	assert(argc == 3);
	char const* src;
	if (strcmp(argv[1], "-c") == 0)
	{
		src = argv[2];
	}
	else if (strcmp(argv[1], "-f") == 0)
	{
		src = read_file(argv[2]);
	}
	else
	{
		assert(false);
	}

	// Parsing
	da_func_t func_da = {0};
	da_buf_t buf_da = {0};
	parse_func(&func_da, &buf_da, 0, src, true, '\0');

	// Buffer
	buf_t bin = {0};
	#define APPBYTES(...) \
		buf_append(&bin, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))
	#define OVWBYTES(ofs_, ...) \
		buf_overwrite(&bin, ofs_, (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))

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
	#define OVWLE16(ofs_, v_) \
		OVWBYTES(ofs_, GET_BYTE(v_, 0), GET_BYTE(v_, 1))
	#define OVWLE32(ofs_, v_) \
		OVWBYTES(ofs_, GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3))
	#define OVWLE64(ofs_, v_) \
		OVWBYTES(ofs_, GET_BYTE(v_, 0), GET_BYTE(v_, 1), GET_BYTE(v_, 2), GET_BYTE(v_, 3), \
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
	uint64_t entry_point_addr_ofs = APPLE64(0); // Entry point address
	uint64_t prog_header_table_ofs_ofs = APPLE64(0x40); // Program header table offset in binary
	APPLE64(0); // Section header table offset in binary (we don't have one)
	APPLE32(0); // Target architecture dependent flags
	uint64_t elf_header_size_ofs = APPLE16(0); // Size of this header
	APPLE16(0x38); // Size of a program header table entry (must be this value in 64bits?)
	uint64_t prog_header_table_len_ofs = APPLE16(0); // Number of entries in program header table
	APPLE16(0); // Size of a section header table entry (we don't have one)
	APPLE16(0); // Number of entries in section header table
	APPLE16(0); // Index of the section header table entry that has the section names
	uint64_t elf_header_size = bin.len;
	OVWLE16(elf_header_size_ofs, elf_header_size);

	// Program header table
	uint64_t prog_header_table_ofs = bin.len;
	OVWLE64(prog_header_table_ofs_ofs, prog_header_table_ofs);
	uint64_t prog_header_table_len = 0;

	// Code segment or something
	APPLE32(1); // Loadable segment
	APPLE32((1<<0/*Readable*/) | (1<<1/*Writable*/) | (1<<2/*Executable*/)); // Flags
	uint64_t code_seg_ofs_ofs = APPLE64(0); // Offset of segment in binary
	uint64_t code_seg_addr = 0x400000;
	uint64_t code_seg_addr_ofs_1 = APPLE64(0); // Address of segment in virtual memory
	uint64_t code_seg_addr_ofs_2 = APPLE64(0); // Address of segment in physical memory (wtf)
	uint64_t code_seg_size_ofs_1 = APPLE64(0); // Segment size in binary
	uint64_t code_seg_size_ofs_2 = APPLE64(0); // Segment size in memory
	APPLE64(0); // Alignment
	prog_header_table_len++;
	#define COMPLETE_CODE_SEGMENT_INFO(ofs_, size_) \
		OVWLE64(code_seg_ofs_ofs, (ofs_)); \
		OVWLE64(code_seg_addr_ofs_1, (ofs_) + code_seg_addr); \
		OVWLE64(code_seg_addr_ofs_2, (ofs_) + code_seg_addr); \
		OVWLE64(code_seg_size_ofs_1, (size_)); \
		OVWLE64(code_seg_size_ofs_2, (size_))

	// Data segment
	APPLE32(1); // Loadable segment
	APPLE32((1<<0/*Readable*/) | (1<<1/*Writable*/)); // Flags
	uint64_t data_seg_ofs_ofs = APPLE64(0); // Offset of segment in binary
	uint64_t data_seg_addr = 0x600000;
	uint64_t data_seg_addr_ofs_1 = APPLE64(0); // Address of segment in virtual memory
	uint64_t data_seg_addr_ofs_2 = APPLE64(0); // Address of segment in physical memory (wtf)
	uint64_t data_seg_size_ofs_1 = APPLE64(0); // Segment size in binary
	uint64_t data_seg_size_ofs_2 = APPLE64(0); // Segment size in memory
	APPLE64(0); // Alignment
	prog_header_table_len++;
	#define COMPLETE_DATA_SEGMENT_INFO(ofs_, size_) \
		OVWLE64(data_seg_ofs_ofs, (ofs_)); \
		OVWLE64(data_seg_addr_ofs_1, (ofs_) + data_seg_addr); \
		OVWLE64(data_seg_addr_ofs_2, (ofs_) + data_seg_addr); \
		OVWLE64(data_seg_size_ofs_1, (size_)); \
		OVWLE64(data_seg_size_ofs_2, (size_))

	// Spine call stack
	APPLE32(1); // Loadable segment
	APPLE32((1<<0/*Readable*/) | (1<<1/*Writable*/)); // Flags
	APPLE64(0); // Offset of segment in binary
	uint64_t call_stack_seg_addr = 0x800000;
	APPLE64(call_stack_seg_addr); // Address of segment in virtual memory
	APPLE64(call_stack_seg_addr); // Address of segment in physical memory (wtf)
	APPLE64(0); // Segment size in binary
	uint64_t call_stack_seg_size = 0x8000;
	APPLE64(call_stack_seg_size); // Segment size in memory
	APPLE64(0); // Alignment
	prog_header_table_len++;
	
	OVWLE16(prog_header_table_len_ofs, prog_header_table_len);

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

	struct da_addr_ofs_t data_addr_ofss = {0};
	#define APPDATAADDR32(v_) \
		da_addr_ofs_append(&data_addr_ofss, \
			(addr_ofs_t){.ofs = APPLE32(v_), .size = 32, .value = (v_)})

	struct da_addr_ofs_t func_addr_ofss = {0};
	#define APPFUNCADDR32(func_index_) \
		da_addr_ofs_append(&func_addr_ofss, \
			(addr_ofs_t){.ofs = APPLE32(func_index_), .size = 32, .value = (func_index_)})
	
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

	#define MOV_R8_TO_MEMPOINTEDBY_R64(reg8_src_, reg64_pointingto_dst_) \
		APPBYTES(0x88, MODRM(MOD01, (reg8_src_), (reg64_pointingto_dst_)), 0)
	#define MOV_MEMPOINTEDBY_R64_TO_R8(reg64_pointingto_src_, reg8_dst_) \
		APPBYTES(0x8a, MODRM(MOD01, (reg8_dst_), (reg64_pointingto_src_)), 0)

	#define PUSH_IMM32(imm32_) \
		APPBYTES(0x68); APPLE32(imm32_)
	#define PUSH_R64(reg64_) \
		APPBYTES(0x50 + reg64_)
	#define POP64_TO_R64(reg64_) \
		APPBYTES(0x58 + (reg64_))

	#define MOV_R64_TO_R64rN(reg64_, n_) \
		APPBYTES(REX(1,0,0,1), 0x89, MODRM(MOD11, reg64_, ((n_)-8)))
	#define MOV_R64_TO_R64r8(reg64_)  MOV_R64_TO_R64rN(reg64_, 8)
	#define MOV_R64_TO_R64r9(reg64_)  MOV_R64_TO_R64rN(reg64_, 9)
	#define MOV_R64_TO_R64r10(reg64_) MOV_R64_TO_R64rN(reg64_, 10)
	#define MOV_R64_TO_R64r11(reg64_) MOV_R64_TO_R64rN(reg64_, 11)
	#define MOV_R64_TO_R64r12(reg64_) MOV_R64_TO_R64rN(reg64_, 12)
	#define MOV_R64_TO_R64r13(reg64_) MOV_R64_TO_R64rN(reg64_, 13)
	#define MOV_R64_TO_R64r14(reg64_) MOV_R64_TO_R64rN(reg64_, 14)
	#define MOV_R64_TO_R64r15(reg64_) MOV_R64_TO_R64rN(reg64_, 15)
		
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
	// note that the spine call stack grows downward, and that index 1 here is top
	#define TURN_RBPCALLSTACK_R64_1INDEX_INTO_ADDR(reg64_) \
		IMUL_R64_WITH_IMM32_TO_R64(reg64_, 8, reg64_); \
		ADD_R64_TO_R64(RBP, reg64_)

	#define IDIV_RDXRAX_BY_R64_TO_RAX_DIV_RDX_MOD(reg64_) \
		APPBYTES(REX(1,0,0,0), 0xf7, MODRM(MOD11, 7, reg64_))

	// Program code
	uint64_t code_ofs = bin.len;
	OVWLE64(entry_point_addr_ofs, code_seg_addr + code_ofs);

	uint64_t func_ofs[func_da.len];
	for (uint64_t func_i = 0; func_i < func_da.len; func_i++)
	{
		func_ofs[func_i] = bin.len;
		for (uint64_t instr_i = 0; instr_i < func_da.arr[func_i].code.len; instr_i++)
		{
			instr_t instr = func_da.arr[func_i].code.arr[instr_i];
			switch (instr.type)
			{
				case INSTR_INIT_PROG:
					// %rbp is used as the spine call stack pointer
					// it grows downward
					MOV_IMM32_TO_R64(call_stack_seg_addr+call_stack_seg_size-8, RBP);
				break;
				case INSTR_HALT_PROG:
					MOV_IMM32_TO_R64(60, RAX); // `exit` syscall number
					MOV_IMM32_TO_R64(0, RDI); // exit code value
					SYSCALL();
				break;
				case INSTR_SYSCALL6:
					// argument order is %rdi, %rsi, %rdx, %r10, %r8, %r9
					// see https://stackoverflow.com/a/2538212
					POP64_TO_R64(RAX); // syscall number
					POP64_TO_R64(RDI); // arg1
					POP64_TO_R64(RSI); // arg2
					POP64_TO_R64(RDX); // arg3
					POP64_TO_R64(RBX); // arg4
					MOV_R64_TO_R64r10(RBX);
					POP64_TO_R64(RBX); // arg5
					MOV_R64_TO_R64r8(RBX);
					POP64_TO_R64(RBX); // arg6
					MOV_R64_TO_R64r9(RBX);
					SYSCALL(); // clobbers %rcx, %r11, and puts the result in %rax
					PUSH_R64(RAX); // syscall result
				break;
				case INSTR_PUSH_FUNC:
					MOV_FUNCADDR32_TO_R64(instr.value, RAX);
					PUSH_R64(RAX);
				break;
				case INSTR_CALL_POP:
					POP64_TO_R64(RAX);
					CALL_R64(RAX);
				break;
				case INSTR_CALL_FUNC:
					MOV_FUNCADDR32_TO_R64(instr.value, RAX);
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
				case INSTR_PUSH_SV:
					switch (instr.value)
					{
						case SV_DATA_START:
							MOV_DATAADDR32_TO_R64(data_seg_addr, RAX);
							PUSH_R64(RAX);
						break;
						default:
							assert(false);
						break;
					}
				break;
				case INSTR_PUSH_DATA_ADDR_AND_SIZE:
					{
						buf_t* buf = &buf_da.arr[instr.value];
						uint64_t addr = data_seg_addr +
							buf_append(&data, buf->arr, buf->len);
						MOV_DATAADDR32_TO_R64(addr, RAX);
						MOV_IMM32_TO_R64(buf->len, RBX);
					}
					PUSH_R64(RAX);
					PUSH_R64(RBX);
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
				case INSTR_SWAP:
					POP64_TO_R64(RAX);
					POP64_TO_R64(RBX);
					PUSH_R64(RAX);
					PUSH_R64(RBX);
				break;
				case INSTR_PEEK:
					POP64_TO_R64(RAX);
					IMUL_R64_WITH_IMM32_TO_R64(RAX, 8, RAX);
					ADD_R64_TO_R64(RSP, RAX);
					MOV_MEMPOINTEDBY_R64_TO_R64(RAX, RAX);
					PUSH_R64(RAX);
				break;
				case INSTR_OVW:
					POP64_TO_R64(RAX); // index
					POP64_TO_R64(RBX); // value
					IMUL_R64_WITH_IMM32_TO_R64(RAX, 8, RAX);
					ADD_R64_TO_R64(RSP, RAX);
					MOV_R64_TO_MEMPOINTEDBY_R64(RBX, RAX);
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
				case INSTR_MUL:
					POP64_TO_R64(RAX);
					POP64_TO_R64(RBX);
					IMUL_R64_TO_R64(RAX, RBX);
					PUSH_R64(RBX);
				break;
				case INSTR_DIV:
					POP64_TO_R64(RBX); // divisor
					POP64_TO_R64(RAX); // numerator
					MOV_IMM32_TO_R64(0, RDX); // high part of the 128-bits numerator
					IDIV_RDXRAX_BY_R64_TO_RAX_DIV_RDX_MOD(RBX);
					PUSH_R64(RAX); // quotient
				break;
				case INSTR_MOD:
					POP64_TO_R64(RBX); // divisor
					POP64_TO_R64(RAX); // numerator
					MOV_IMM32_TO_R64(0, RDX); // high part of the 128-bits numerator
					IDIV_RDXRAX_BY_R64_TO_RAX_DIV_RDX_MOD(RBX);
					PUSH_R64(RDX); // remainder
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
				case INSTR_READ:
					if (instr.value == 64)
					{
						POP64_TO_R64(RAX);
						MOV_MEMPOINTEDBY_R64_TO_R64(RAX, RAX);
						PUSH_R64(RAX);
					}
					else if (instr.value == 8)
					{
						MOV_IMM32_TO_R64(0, RBX); // necessary (mov r8 does not clear)
						POP64_TO_R64(RAX);
						MOV_MEMPOINTEDBY_R64_TO_R8(RAX, RBX);
						PUSH_R64(RBX);
					}
					else
					{
						assert(false);
					}
				break;
				case INSTR_WRITE:
					if (instr.value == 64)
					{
						POP64_TO_R64(RAX);
						POP64_TO_R64(RBX);
						MOV_R64_TO_MEMPOINTEDBY_R64(RBX, RAX);
					}
					else if (instr.value == 8)
					{
						POP64_TO_R64(RAX);
						POP64_TO_R64(RBX);
						MOV_R8_TO_MEMPOINTEDBY_R64(RBX, RAX);
					}
					else
					{
						assert(false);
					}
				break;
				default:
					assert(false);
				break;
			}
		}
	}

	// Fill addresses of functions
	for (uint64_t i = 0; i < func_addr_ofss.len; i++)
	{
		addr_ofs_t func_addr_ofs = func_addr_ofss.arr[i];
		if (func_addr_ofs.size == 32)
		{
			OVWLE32(func_addr_ofs.ofs,
				code_seg_addr + func_ofs[func_addr_ofs.value]);
		}
		else if (func_addr_ofs.size == 64)
		{
			OVWLE64(func_addr_ofs.ofs,
				code_seg_addr + func_ofs[func_addr_ofs.value]);
		}
		else
		{
			assert(false);
		}
	}

	// End of code
	COMPLETE_CODE_SEGMENT_INFO(code_ofs, bin.len - code_ofs);

	// Data
	#if 0
		buf_append_zeros(&bin, bin.len % (8 * 4096)); // Page align (is this necessary?)
	#endif
	uint64_t data_ofs = bin.len;
	COMPLETE_DATA_SEGMENT_INFO(data_ofs, data.len);
	buf_append(&bin, data.arr, data.len);

	#if 0
		printf("data at 0x%lx:\n", data_seg_addr + data_ofs);
		for (int i = 0; i < data.len; i++)
		{
			printf("%c", data.arr[i]);
		}
		printf("\n");
	#endif

	// Correct addresses that are supposed to point to stuff in the data segment
	for (uint64_t i = 0; i < data_addr_ofss.len; i++)
	{
		addr_ofs_t data_addr_ofs = data_addr_ofss.arr[i];
		if (data_addr_ofs.size == 32)
		{
			OVWLE32(data_addr_ofs.ofs, data_addr_ofs.value + data_ofs);
		}
		else if (data_addr_ofs.size == 64)
		{
			OVWLE64(data_addr_ofs.ofs, data_addr_ofs.value + data_ofs);
		}
		else
		{
			assert(false);
		}
	}

	#if 0
		printf("base address: 0x%lx\n", code_ofs);
		for (uint64_t i = code_ofs; i < data_ofs; i++)
		{
			printf("%02x ", bin.arr[i]);
		}
		printf("\n");
	#endif

	// Write to file
	FILE* file = fopen("bin/jaaj", "wb");
	assert(file != NULL);
	fwrite(bin.arr, 1, bin.len, file);
	fclose(file);

	return 0;
}
