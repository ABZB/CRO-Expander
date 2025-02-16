from tkinter.filedialog import askopenfilename, asksaveasfilename
import os
import hashlib

def load_file(title_text):
	search_array = []
	#file we are looking in
	source_file = askopenfilename(title = title_text)
	try:
		with open(source_file, "r+b") as f:
			f.seek(0, os.SEEK_END)
			file_end = f.tell()
			f.seek(0, 0)
			block = f.read(file_end)
		
			for ch in block:
				search_array.append(ch)
			return(search_array)
	except Exception as e:
		print('Encountered following error when opening file ', source_file, '\n', e)
		return([], [], [], [])
    
def save_file(data, path):
	with open(path, "w+b") as f:
		f.write(bytes(data))

def dec2hex(dec_array, padding):
	temp_str = ''
	try:
		for x in dec_array:
			temp_str += str(hex(x)[2:]).zfill(padding).upper()
		return(temp_str)
	except:
		return(str(hex(dec_array)[2:]).zfill(padding).upper())

def hex2dec(hex_array):
	temp = 0
	for offset, byte_digits in enumerate(hex_array):
		#assume little endian, each further offset is multiplied by 256 again
		temp += byte_digits*(256**offset)
	return(temp)

def write_dec_to_bytes(decimals, data, start, length = 4):
	temp = decimals
	for offset in range(length):
		#write the current lowest byte to appropriate offset
		data[start + offset] = decimals & 255
		#bitshift one byte to the right
		decimals = decimals >> 8

	#handle overflowing specified number of bytes
	if(decimals != 0):
		print('Warning, remainder of', decimals, 'left after writing', length, 'bytes', 'at address', start, '. Original value is dec ', temp, '/0x', dec2hex(temp,6))
		while True:
			proceed_bool = input('Proceed anyway?\nY/N\n').lower()
			if(proceed_bool == 'y'):
				break
			elif(proceed_bool == 'n'):
				print('Exiting program without writing')
				return(0)
			else:
				print('Please enter Y or N\n')
	return(data)


def update_offset_pointer(data, change, pointer_location, old_code_segment_end, pointer_length = 4, ignore_zero_pointer = True):
	
	temp = hex2dec(data[pointer_location:pointer_location + pointer_length])

	#ignore addresses that are zero or are before the inserted space
	if((ignore_zero_pointer and temp == 0) or temp < old_code_segment_end):

		return(data)
	else:
		return(write_dec_to_bytes(temp + change, data, pointer_location, pointer_length))



def header_hash(file, hash_write_offset,start_offset, stop_offset):
	
	#initialize hash object
	m = hashlib.sha256(bytes(file[start_offset:stop_offset]), usedforsecurity=False)

	hash_bytes = m.hexdigest()
	


	for offset in range(0x20):
		

		file[hash_write_offset + offset] = int(hash_bytes[2*offset:2*(offset + 1)], 16)

	return(file)


	
def main():
	
	while True:
		target_file = load_file('Select cro file to expand')

		file_size = len(target_file)
		section_to_expand = ''
		bytes_to_add = 0
		output_file = []


		while True:
			try:
				section_to_expand = input('Expand .code, .data, or .bss? (c/d/b):\n').lower()
				if(section_to_expand in {'c','d','b'}):
					break
				else:
					print(section_to_expand, 'is not a valid selection.')
			except:
				print(section_to_expand, 'is not understood.')
		
		match section_to_expand:
			case 'c':
				outstring = '.code'
			case 'd':
				outstring = '.data'
			case 'b':
				outstring = '.bss'
			case _:
				outstring = 'error'
				

		if(section_to_expand in {'c','d'}):
			print('You can only add space in pages, multiples of 0x1000 bytes')
			while True:
				try:
					pages_to_add = int(input('Enter number of pages to add:\n'))
					break
				except:
					print(pages_to_add, 'is not an integer.')
			bytes_to_add = pages_to_add*0x1000
		else:
			while True:
				try:
					pages_to_add = int(input('Enter number of words to add:\n'))
					bytes_to_add = pages_to_add*0x4
					break
				except:
					print(pages_to_add, 'is not an integer.')

	
		
		print('Adding',bytes_to_add,  'bytes to',outstring)

		#only need to do all of this if we are updating .code sine
		
		#get the address of end of code. Note that end-offset is actually the address of the first byte of the NEXT thing
		code_start_offset = hex2dec(target_file[0xB0:0xB4])
		if(section_to_expand == 'c'):


			#insert new code in the "text" at the very end. Need to add the offset to the size
			insertion_point = hex2dec(target_file[hex2dec(target_file[0xC8:0xCC]):hex2dec(target_file[0xC8:0xCC]) + 0x4]) + hex2dec(target_file[hex2dec(target_file[0xC8:0xCC]) + 0x4:hex2dec(target_file[0xC8:0xCC]) + 0x4 + 0x4])

	
	
			in_pointer = 0
			#first part of body is the code, about half will not change, so do just copy it
			for _ in range(code_start_offset):
				output_file.append(target_file[in_pointer])
				in_pointer += 1

			#now add the existing code until the start of rodata. in_pointer is now pointing to first byte of code after the previous for loop ended

			while True:
				#if our reading-pointer from the old file is now pointing at the start of the old rodata location, insert the new bytes and then exit the loop
				if(insertion_point == in_pointer):
					#add the new bytes to code
					for _ in range(bytes_to_add):
						output_file.append(0xFF)
					break
				else:
					output_file.append(target_file[in_pointer])
					in_pointer += 1

			#since we broke, in_pointer is still pointing at the start of rodata, while our appending continues at the new offset

			#add the rest of the data
			while True:
				output_file.append(target_file[in_pointer])
				in_pointer += 1
				if(in_pointer == file_size):
					break

			#update header file, move from start to end

			#name offset
			output_file = update_offset_pointer(output_file, bytes_to_add, 0x84, insertion_point)

			#new file size
			file_size += bytes_to_add
			write_dec_to_bytes(file_size, output_file, 0x90)

			#new code size
			output_file = update_offset_pointer(output_file, bytes_to_add, 0xB4, 0x0)

			#get the other 16 offsets, 4 bytes every 8 bytes from 0xB8
			for x in range(16):
				#x*8 because we are skipping over the size of each, since those are not changing
				output_file = update_offset_pointer(output_file, bytes_to_add, 0xB8 + x*8, insertion_point)

			#deal with various tables of pointers
			#point to table, table of pointer locations per entry, entry size
			update_pointer_tables_arr = [[0xD0, [0x0], 0x8], [0xF0, [0x0,0x4,0xC], 0x14], [0x100, [0x0, 0x4], 0x8], [0x110, [0x4], 0x8]]

			for table in update_pointer_tables_arr:
				#load the table's pointer
				pointer_pointer = hex2dec(output_file[table[0]:table[0] + 0x4])
				#number of entries
				entry_count = hex2dec(output_file[table[0] + 4:table[0] + 4 + 4])
				#print(pointer_pointer, entry_count)
				for pointer_number in range(entry_count):
					for sub_offset in table[1]:
						output_file = update_offset_pointer(output_file, bytes_to_add, pointer_number*table[2] + sub_offset + pointer_pointer, insertion_point)

			#for battle.cro, need to update a single additional address
			segment_table_offset = hex2dec(output_file[0xC8:0xCC])

			#first update the size of the text table
			output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset + 0x4, 0x0)
			#size is 0xC, need to go update the start offsets of the 2nd and 3rd entry
			segment_table_offset += 0xC
			output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset, insertion_point)
			segment_table_offset += 0xC
			output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset, insertion_point)


		#otherwise if we are updating just .data or .bss
		else:
			#no edits internally
			output_file = target_file.copy()
			segment_table_offset = hex2dec(output_file[0xC8:0xCC])


			#updating .data
			if(section_to_expand == 'd'):
				
				#check for unused padding at the end of .data

				#total .cro file length - (offset of .data + len(.data)). any extra space is the .data padding to get to a multiple of 0x1000
				free_padding_bytes = hex2dec(output_file[0x90:0x94]) - (hex2dec(output_file[segment_table_offset + 0x18:segment_table_offset + 0x1C]) + hex2dec(output_file[segment_table_offset + 0x1C:segment_table_offset + 0x1C + 0x4]))

				#update total file size less free padding bytes
				output_file = update_offset_pointer(output_file, bytes_to_add - free_padding_bytes, 0x90, 0x0)

				#update .data size in header
				output_file = update_offset_pointer(output_file, bytes_to_add, 0xBC, 0x0)

				#update .data size in segment table
				#0x18 is start of .data, +0x4 to its length
				output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset + 0x1C, 0x0)

				#extend the file
				output_file.extend([0xFF]*(bytes_to_add - free_padding_bytes))


			#otherwise expanding .bss
			else:
				#header .bss size
				output_file = update_offset_pointer(output_file, bytes_to_add, 0x94, 0x0)
				#segment table .bss size
				output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset + 0x28, 0x0)



		#redo hashes
		output_file = header_hash(output_file, 0x0, 0x80, code_start_offset)
		output_file = header_hash(output_file, 0x20, code_start_offset, hex2dec(target_file[0xC0:0xC4]))
		output_file = header_hash(output_file, 0x40, hex2dec(target_file[0xC0:0xC4]), hex2dec(target_file[0xB8:0xBC]))
		output_file = header_hash(output_file, 0x60, hex2dec(target_file[0xB8:0xBC]), -1)


		output_file_path = asksaveasfilename(title = 'Select output cro file')
		save_file(output_file, output_file_path)
		match section_to_expand:
			case 'c':
				print('Added', hex(bytes_to_add), 'bytes to the end of', outstring, 'which is', hex(bytes_to_add//4), 'instructions, starting at address', hex(insertion_point), '.\n\n')
			case 'd':
				print('Added', hex(bytes_to_add), 'bytes to the end of', outstring, 'starting at address', hex(hex2dec(output_file[0x90:0x94]) - bytes_to_add), '.\n\n')
			case 'b':
				print('Added', hex(bytes_to_add), 'bytes to the end of', outstring, '.\n\n')




		while True:
			again_bool = input('Expand another file?\nY/N\n').lower()
			if(again_bool == 'y'):
				break
			elif(again_bool == 'n'):
				return

main()