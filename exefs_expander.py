from cro_expander import *

def expand_code(target_code_file, target_header_file, target_NCCH_file, section_to_expand, bytes_to_add, outstring, insertion_point = 0):
	output_code_file = []
	output_header_file = []
	output_NCCH_file = []

	#print(section_to_expand)

	#only need to do all of this if we are updating .code sine
		
	#get the address of end of code. Note that end-offset is actually the address of the first byte of the NEXT thing
	if(section_to_expand in {'c', 'a'}):
		skip_check = 0
		#insert new bytes for .code
		if(section_to_expand == 'c'):
			
			#if code, insert new code in the "text" at the very end. Need to add the offset to the size, otherwise already defined this
			if(insertion_point == 0):
				#start + 4096*physical region size
				insertion_point = hex2dec(target_header_file[0x10:0x14])+ hex2dec(target_header_file[0x14:0x18])*4096


			#grab the portion of the file before insertion
			output_code_file.extend(target_code_file[0:insertion_point])

			#add new bytes
			output_code_file.extend([0xCC]*bytes_to_add)

			skip_check = 0
		else:

			#otherwise was manually defined
			output_code_file.extend(output_code_file[0:insertion_point])
			#outfile now has a copy of the date

			#add new bytes
			output_code_file.extend([0xCC]*bytes_to_add)

			skip_check = insertion_point
		#print(bytes_to_add, insertion_point, skip_check)
		
		print('Adding', hex(bytes_to_add), 'bytes to', outstring,'at',hex(insertion_point))

		#add the rest of the data
		output_code_file.extend(target_code_file[insertion_point:])


	#otherwise if we are updating just .data or .bss
	else:
		#no edits internally
		output_code_file = target_code_file.copy()


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