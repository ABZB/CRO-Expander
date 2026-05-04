from cro_expander import *

def expand_code(target_code_file, target_header_file, target_NCCH_file, section_to_expand, bytes_to_add, outstring, insertion_point = 0):
	output_file = []

	#print(section_to_expand)

	#only need to do all of this if we are updating .code sine
		
	#get the address of end of code. Note that end-offset is actually the address of the first byte of the NEXT thing
	if(section_to_expand in {'c', 'a', 'r'}):
		skip_check = 0
		#insert new bytes for .code
		if(section_to_expand == 'c'):
			
			#if code, insert new code in the "text" at the very end. Need to add the offset to the size, otherwise already defined this
			if(insertion_point == 0):
				insertion_point = target_header_file
			#grab the portion of the file before insertion
			output_file.extend(target_file[0:insertion_point])

			#add new bytes
			output_file.extend([0xCC]*bytes_to_add)

			skip_check = 0
		else:
			
			if(section_to_expand == 'r'):
				#inserting at address of .data, which immediately follows relocation patch table
				segment_table_offset = hex2dec(target_file[0xC8:0xCC])


				#patch table end = data start
				insertion_point = hex2dec(target_file[segment_table_offset + 0x18 : segment_table_offset + 0x18 + 4])

			#otherwise was manually defined
			output_file.extend(target_file[0:insertion_point])
			#outfile now has a copy of the date

			#add new bytes
			output_file.extend([0xCC]*bytes_to_add)

			skip_check = insertion_point
		#print(bytes_to_add, insertion_point, skip_check)
		
		print('Adding', hex(bytes_to_add), 'bytes to', outstring,'at',hex(insertion_point))

		#add the rest of the data
		output_file.extend(target_file[insertion_point:])

		#update header file, move from start to end

		#name offset
		output_file = update_offset_pointer(output_file, bytes_to_add, 0x84, insertion_point, skip_value = skip_check)

		#new file size
		file_size += bytes_to_add
		write_dec_to_bytes(file_size, output_file, 0x90)

		#new code size
		if(section_to_expand in {'c'}):
			output_file = update_offset_pointer(output_file, bytes_to_add, 0xB4)

		#if expanding code or relocation patch table, need to advance .data start
		if(section_to_expand in {'c','r'}):
				output_file = update_offset_pointer(output_file, bytes_to_add, 0xB8, insertion_point, skip_value = skip_check)


		#these only need to be repointed if expanding code
		if(section_to_expand in {'c'}):
			#get the other 15 offsets, 4 bytes every 8 bytes from 0xBC
			for x in range(15):
				#x*8 because we are skipping over the size of each, since those are not changing
				output_file = update_offset_pointer(output_file, bytes_to_add, 0xC0 + x*8, insertion_point, skip_value = skip_check)

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
					output_file = update_offset_pointer(output_file, bytes_to_add, pointer_number*table[2] + sub_offset + pointer_pointer, insertion_point, skip_value = skip_check)
		

		#segment table needed to update a single additional address
		segment_table_offset = hex2dec(output_file[0xC8:0xCC])

		#first update the size of the text table
		if(section_to_expand == 'c'):
			output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset + 0x4)
		#size is 0xC, need to go update the start offsets of the 2nd and 3rd entry

		#ROdata
		segment_table_offset += 0xC
		output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset, insertion_point, skip_value = skip_check)

		#.data
		segment_table_offset += 0xC
		output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset, insertion_point - 1, skip_value = skip_check - 1)


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
			output_file = update_offset_pointer(output_file, bytes_to_add, 0x90)

			#update .data size in header
			output_file = update_offset_pointer(output_file, bytes_to_add + free_padding_bytes, 0xBC)

			#update .data size in segment table
			#0x18 is start of .data, +0x4 to its length
			output_file = update_offset_pointer(output_file, bytes_to_add + free_padding_bytes, segment_table_offset + 0x1C)

			#extend the file
			output_file.extend([0xCC]*(bytes_to_add))


		#otherwise expanding .bss
		else:
			#header .bss size
			output_file = update_offset_pointer(output_file, bytes_to_add, 0x94)
			#segment table .bss size
			output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset + 0x28)
				
	match section_to_expand:
		case 'c':
			print('Added', hex(bytes_to_add), 'bytes to', outstring, 'which is', hex(bytes_to_add//4), 'instructions, starting at address', hex(insertion_point), '\n\n')
		case 'd':
			print('Added', hex(bytes_to_add), 'bytes to', outstring, 'starting at address', hex(hex2dec(output_file[0x90:0x94]) - bytes_to_add), '\n\n')
		case 'b':
			print('Added', hex(bytes_to_add), 'bytes to', outstring, '\n\n')
	
	return(output_file)

def code_expansion_user_input(target_code_file, target_header_file, target_NCCH_file, section_to_expand = '', pages_to_add = 0):


	while True:
		try:
			if(section_to_expand == ''):
				section_to_expand = input('Expand .code, .data, .bss? (c/d/b):\n').lower()
			if(section_to_expand in {'c','d','b'}):
				break
			else:
				print(section_to_expand, 'is not a valid selection.')
				section_to_expand = ''
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

					
	if(section_to_expand in {'c','d', 'r'}):
		print('You can only add space in pages, multiples of 0x1000 bytes')
		while True:
			try:
				if(pages_to_add == 0):
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

				
	return(expand_code(target_code_file, target_header_file, target_NCCH_file, section_to_expand, bytes_to_add, outstring))

def main():
	
	load_new_file = True
	save = True
	exit_next = False

	target_code_file = []
	target_header_file = []
	target_NCCH_file = []

	output_code_file = []
	output_header_file = []
	output_NCCH_file = []

	while True:
		if(load_new_file):
			target_code_file = load_file('Select code.bin')
			target_header_file = load_file('Select DecryptedExHeader.bin')
			target_NCCH_file = load_file('Select HeaderNCCH0.bin')
		else:
			target_code_file = output_code_file
			target_header_file = output_header_file
			target_NCCH_file = output_NCCH_file
		process_to_execute = ''
		while True:
			try:
				process_to_execute = input('Expand code.bin segment, move a table, or repoint a function: (s/t/f)\n').lower()
				if(process_to_execute in {'s','t','f'}):
					break
				else:
					print(process_to_execute, 'is not a valid selection.')
			except:
				print(process_to_execute, 'is not understood.')

		if(process_to_execute == 's'):
			output_code_file, output_header_file, output_NCCH_file = code_expansion_user_input(target_code_file, target_header_file, target_NCCH_file)
		#otherwise something in patch table
		else:
			output_file = repoint_expand(target_file, process_to_execute)





		while True:
			again_bool = input('Continue Editing?\nY = Continue Editing Current CRO\nS = Save & Select Another CRO\nN = Save & Exit Program\n').lower()
			if(again_bool == 'y'):
				load_new_file = False
				save = False
				break
			elif(again_bool == 's'):
				load_new_file = True
				save = True
				break
			elif(again_bool == 'n'):
				save = True
				exit_next = True
				break

		if(save):
			output_file_path = asksaveasfilename(title = 'Select output cro file')
			save_file(output_file, output_file_path)

		if(exit_next):
			break

	return(True)















































if __name__ == "__main__":
    main()