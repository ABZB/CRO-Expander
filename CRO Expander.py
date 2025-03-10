from tkinter.filedialog import askopenfilename, asksaveasfilename
import os
#import hashlib

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


def update_offset_pointer(data, change, pointer_location, old_code_segment_end, pointer_length = 4, ignore_zero_pointer = True, skip_value = 0):
	
	temp = hex2dec(data[pointer_location:pointer_location + pointer_length])

	#if we past this value, don't update it
	if(temp < skip_value):
		return(data)

	#ignore addresses that are zero or are before the inserted space
	if((ignore_zero_pointer and temp == 0) or temp < old_code_segment_end):

		return(data)
	else:
		return(write_dec_to_bytes(temp + change, data, pointer_location, pointer_length))



def expand_cro(target_file, section_to_expand, bytes_to_add, outstring, file_size, insertion_point = 0):
	
	output_file = []
	print('Adding', bytes_to_add, 'bytes to', outstring)

	print(section_to_expand)

	#only need to do all of this if we are updating .code sine
		
	#get the address of end of code. Note that end-offset is actually the address of the first byte of the NEXT thing
	if(section_to_expand in {'c', 'a'}):

		#insert new bytes for .code
		if(section_to_expand == 'c'):
			
			#if code, insert new code in the "text" at the very end. Need to add the offset to the size, otherwise already defined this
			if(insertion_point == 0):
				insertion_point = hex2dec(target_file[hex2dec(target_file[0xC8:0xCC]):hex2dec(target_file[0xC8:0xCC]) + 0x4]) + hex2dec(target_file[hex2dec(target_file[0xC8:0xCC]) + 0x4:hex2dec(target_file[0xC8:0xCC]) + 0x4 + 0x4])
			#grab the portion of the file before insertion
			output_file.extend(target_file[0:insertion_point])

			#add new bytes
			output_file.extend([0xFF]*bytes_to_add)

			skip_check = 0
						
		else:
				
			#grab the portion of the file before insertion
			output_file.extend(target_file[0:insertion_point])
			#outfile now has a copy of the date

			#add new bytes
			output_file.extend([0xCC]*bytes_to_add)

			skip_check = insertion_point
		print(bytes_to_add, insertion_point, skip_check)
				
		#add the rest of the data
		output_file.extend(target_file[insertion_point:])

		#update header file, move from start to end

		#name offset
		output_file = update_offset_pointer(output_file, bytes_to_add, 0x84, insertion_point, skip_value = skip_check)

		#new file size
		file_size += bytes_to_add
		write_dec_to_bytes(file_size, output_file, 0x90)

		#new code size
		if(section_to_expand == 'c'):
			output_file = update_offset_pointer(output_file, bytes_to_add, 0xB4, 0x0)

		#get the other 16 offsets, 4 bytes every 8 bytes from 0xB8
		for x in range(16):
			#x*8 because we are skipping over the size of each, since those are not changing
			output_file = update_offset_pointer(output_file, bytes_to_add, 0xB8 + x*8, insertion_point, skip_value = skip_check)

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

		#segment table need to update a single additional address
		segment_table_offset = hex2dec(output_file[0xC8:0xCC])

		#first update the size of the text table
		if(section_to_expand == 'c'):
			output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset + 0x4, 0x0)
		#size is 0xC, need to go update the start offsets of the 2nd and 3rd entry

		#ROdata
		segment_table_offset += 0xC
		output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset, insertion_point, skip_value = skip_check)

		#if we expanded rodata, expand its size as needed
		if(section_to_expand == 'a' and hex2dec(output_file[segment_table_offset + 4 :segment_table_offset + 8]) + hex2dec(output_file[segment_table_offset:segment_table_offset + 4]) <= skip_check):
			output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset + 0x4, 0x0)
		#else:
			#print('You have tried to expand something by manual entry that is not in rodata, this might go horribly wrong, please ensure you have a backup.')
				
		#.data
		segment_table_offset += 0xC
		output_file = update_offset_pointer(output_file, bytes_to_add, segment_table_offset, insertion_point, skip_value = skip_check)


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
				
	match section_to_expand:
		case 'c':
			print('Added', hex(bytes_to_add), 'bytes to ', outstring, 'which is', hex(bytes_to_add//4), 'instructions, starting at address', hex(insertion_point), '.\n\n')
		case 'd':
			print('Added', hex(bytes_to_add), 'bytes to ', outstring, 'starting at address', hex(hex2dec(output_file[0x90:0x94]) - bytes_to_add), '.\n\n')
		case 'b':
			print('Added', hex(bytes_to_add), 'bytes to ', outstring, '.\n\n')
	
	return(output_file)


def cro_expansion_user_input(target_file, file_size):
	
	while True:
		try:
			section_to_expand = input('Expand .code, .data, .bss, or insert into specific address? (c/d/b/a):\n').lower()
			if(section_to_expand in {'c','d','b', 'a'}):
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
		case 'a':
			outstring = 'specific address'
		case _:
			outstring = 'error'

	insertion_point = 0

	if(section_to_expand == 'a'):
		while True:
			try:
				insertion_point = input('Enter address to insert at (value at that address will be pushed forwards):\n')

				try:
					insertion_point = int(insertion_point)
				except:
					insertion_point = int(insertion_point, 16)

				print('Inserting at', hex(insertion_point),'\n')
				break
			except:
				print(insertion_point, 'is not an integer.')


					
	if(section_to_expand in {'c','d', 'a'}):
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

				
	return(expand_cro(target_file, section_to_expand, bytes_to_add, outstring, file_size, insertion_point = 0))

def repoint_expand(target_file, process_to_execute, file_size):
	
	output_file = target_file.copy()

	segment_table_offset = hex2dec(target_file[0xC8:0xCC])

	code_start = hex2dec(target_file[segment_table_offset:segment_table_offset + 4])
	rodata_start = hex2dec(target_file[segment_table_offset + 0xC:segment_table_offset + 0xC + 4])
	data_start = hex2dec(target_file[segment_table_offset + 0xC + 0xC:segment_table_offset + 0xC + 0xC + 4])
	bss_start = hex2dec(target_file[segment_table_offset + 0xC + 0xC + 0xC:segment_table_offset + 0xC + 0xC + 0xC + 4])

	code_len = hex2dec(target_file[segment_table_offset + 4:segment_table_offset + 4 + 4])
	rodata_len = hex2dec(target_file[segment_table_offset + 0xC + 4:segment_table_offset + 0xC + 4 + 4])
	data_len = hex2dec(target_file[segment_table_offset + 0xC + 0xC + 4:segment_table_offset + 0xC + 0xC + 4 + 4])
	bss_len = hex2dec(target_file[segment_table_offset + 0xC + 0xC + 0xC + 4:segment_table_offset + 0xC + 0xC + 0xC + 4 + 4])

	start_table = [code_start, rodata_start, data_start, bss_start]
	len_table = [code_len, rodata_len, data_len, bss_len]

	patch_table_offset = hex2dec(target_file[0x128:0x12C])
	patch_table_item_count = hex2dec(target_file[0x12C:0x130])
			
	find_value = 0

	target_segment = 0
	target_addend = 0

	#we can find the thing we are repointing or expanding either by searching by an address it's written to, or by the value it points to once written (e.g. a function by either the place where its pointer is written, or by the actual address the pointer points to)

	while True:
		try:
			find_method = input('Search by either a location where the table/function address is written TO, or by the actual address of the table/function (w/a) :\n').lower()
			if(find_method in {'w','a'}):
				break
			else:
				print(find_method, 'is not a valid selection.')
		except:
			print(find_method, 'is not understood.')

	while True:
		try:
			if(find_method == 'w'):
				find_value = input('Enter an address where the pointer to your table/function is written to:\n')
			elif(find_method == 'a'):
				find_value = input('Enter the address of your table/function:\n')
			try:
				find_value = int(find_value)
			except:
				find_value = int(find_value, 16)

			print('Looking for', hex(find_value),'\n')
			break
		except:
			print(find_value, 'is not an integer.')

	target_patch = 0
	#look for our function
	if(find_method == 'w'):
		for line in range(patch_table_item_count):
			line_thing = target_file[line*0xC + patch_table_offset:line*0xC + patch_table_offset + 0xC]
			temp = hex2dec(line_thing[0:4])

			#low 4 bits are the segment table id, the rest needs to be bitshifted to the right to get correct offset in that segment
			temp_address = (temp >> 4) + start_table[temp & 0xF]

			if(temp_address == find_value):
				target_segment = line_thing[0x5]
				target_addend = hex2dec(line_thing[0x8:0xC])
				target_patch = line*0xC + patch_table_offset
				break
	#method a, we need to find the entry where addend + segment_start == entry
	elif(find_method == 'a'):
		for line in range(patch_table_item_count):
			line_thing = target_file[line*0xC + patch_table_offset:line*0xC + patch_table_offset + 0xC]
			temp = hex2dec(line_thing[0x8:0xC])

			temp_address = temp + start_table[line_thing[0x5]]

			if(temp_address == find_value):
				target_segment = line_thing[0x5]
				target_addend = hex2dec(line_thing[0x8:0xC])
				target_patch = line*0xC + patch_table_offset
				break

	if(target_addend == 0):
		print('Error, no value found')
		return([])

	while True:
		try:
			if(process_to_execute == 't'):
				update_value = input('Enter the number of bytes by which to expand your table:\n')
			elif(process_to_execute == 'f'):
				update_value = input('Enter the absolute address to which you want to repoint the function:\n')
			try:
				update_value = int(update_value)
			except:
				update_value = int(update_value, 16)

			print('Using', hex(update_value),'\n')
			break
		except:
			print(update_value, 'is not an integer.')
			
	#now cycle through the entire table. In case function, just update the value to new location. If it is table, push forward by X bytes

	#Function case
	if(process_to_execute == 'f'):
		function_list = []
		for line in range(patch_table_item_count):
			line_thing = target_file[line*0xC + patch_table_offset:line*0xC + patch_table_offset + 0xC]
			#found instance



			if(hex2dec(line_thing[0x8:0xC]) == target_addend and line_thing[0x5] == target_segment):
				function_list.append(line*0xC + patch_table_offset)

		temp_len = len(function_list)
		if(temp_len > 1):
			print('Found ', temp_len, ' calls to this function.')
			while True:
				try:
					function_all = input('Update all, or select one?:\n(u/n)').lower()
					if(function_all in {'u', 'n'}):
						break
				except:
					print(function_all, ' is not a valid selection')

			if(function_all == 'u'):
				#subtract segment offset from target address
				update_value -= start_table[target_segment]
				for address in function_list:
					output_file = write_dec_to_bytes(update_value - start_table[target_file[address + 0x5]], target_file, address + 8, length = 4)
			else:
				#print all the addreses where the call appears
				while True:
	
					print('The following are the addresses\m')
					for x, address in enumerate(function_list):
						print(x,': ',hex(dec2hex(target_file[address:address + 4])),'\n')
					try:
						update_target = input('Enter the line number of the particular address you want to update:\n')
						try:
							update_target = int(update_target)
						except:
							update_target = int(update_target, 16)

						print('Updating', hex(update_target),'\n')
						break
					except:
						print(update_target, 'is not an integer.')

				output_file = write_dec_to_bytes(update_value - start_table[target_file[function_list[x] + 0x5]], target_file, function_list[x] + 8, length = 4)
		else:
			output_file = write_dec_to_bytes(update_value - start_table[target_file[function_list[0] + 0x5]], target_file, function_list[0] + 8, length = 4)

	
	#table expansion case
	else:

		#latest point to insert the balancing bytes is the end of this section
		lowest_next_table = start_table[target_segment] + len_table[target_segment]


		for line in range(patch_table_item_count):
			line_thing = target_file[line*0xC + patch_table_offset:line*0xC + patch_table_offset + 0xC]


			#offset that this line is writing
			temp_line_target_offset = hex2dec(line_thing[0x8:0xC])

			#look for something with greater value in its own segment, or in .rodata if .code
			if(temp_line_target_offset > target_addend and (line_thing[0x5] == target_segment or (target_segment == 0 and line_thing[0x5] == 1))):

				#if this is nearer then the current lowest next table, replace it
				if(temp_line_target_offset < lowest_next_table):
					lowest_next_table = temp_line_target_offset

				#temp_segment_offset = start_table[line_thing[0x5]]

				#move the table forward by update_value bytes
				#output_file = write_dec_to_bytes(temp_line_target_offset + update_value, target_file, line*0xC + patch_table_offset + 8, length = 4)

				#print(line*0xC + patch_table_offset + 8, temp_line_target_offset, update_value)

		section_to_expand = ''
		outstring = ''
		match target_segment:
			case 0:
				section_to_expand = 'c'
				outstring = '.code table'
			case 1:
				section_to_expand = 'a'
				outstring = '.rodata table'
			case 2:
				section_to_expand = 'd'
				outstring = '.data table'
			case 3:
				section_to_expand = 'b'
				outstring = '.bss table'
			case _:
				outstring = 'error'
		
		end_bytes = 0x1000
		#inserts bytes between end of current table and start of the next
		if(lowest_next_table != 0):
			output_file = expand_cro(output_file, section_to_expand, update_value, outstring, file_size, insertion_point = lowest_next_table + start_table[target_segment])
			#need to pad with extra bytes to avoid crash
			end_bytes -= update_value
		else:
			#this happens if it's the last table in the segment, just stick them after the end of the table. in rodata in particular, this will cause problems without manual entry

			while True:
				
				print('Table is last entry in its segment, please manually locate the address of the first byte after the table (e.g. if the last byte of the table is at 0x100, enter 0x101)')
				try:
					insert_target = input('Enter address:\n')
					try:
						insert_target = int(insert_target)
					except:
						insert_target = int(insert_target, 16)

					print('Updating', hex(insert_target),'\n')
					break
				except:
					print(insert_target, 'is not an integer.')

		#just in case expand a table by exactly 0x1000
		if(end_bytes > 0):
			output_file.extend([0xCC]*end_bytes)
		#check if end is more than 0x1000 0xCC bytes past end of .data, if so delete them and update total length

	ptr = len(output_file) - 1
	ctr = 0
	data_end = output_file[0xb8:0xb8 + 4] + output_file[0xBC:0xBC + 4]

	#remove padding in multiples of 0x1000
	while True:
		if(output_file[ptr] == 0xCC):
			ctr += 1
		else:
			break
		if(ptr <= data_end):
			break
		ptr -= 1
	if(ctr >= 0x1000):
		ctr = int(ctr // 0x1000)*0x1000
		output_file = output_file[:-ctr]
		write_dec_to_bytes(hex2dec(output_file[0xB4: 0xB4 + 4]) - ctr, output_file, 0xB4, length = 4)



	return(output_file)

def main():
	
	while True:
		target_file = load_file('Select cro file')

		file_size = len(target_file)
		section_to_expand = ''
		bytes_to_add = 0
		output_file = []
		process_to_execute = ''
		while True:
			try:
				process_to_execute = input('Expand .cro segment, expand a table, or repoint a function: (s/t/f)\n').lower()
				if(process_to_execute in {'s','t','f'}):
					break
				else:
					print(process_to_execute, 'is not a valid selection.')
			except:
				print(process_to_execute, 'is not understood.')

		if(process_to_execute == 's'):
			output_file = cro_expansion_user_input(target_file, file_size)
		#otherwise something in patch table
		else:
			output_file = repoint_expand(target_file, process_to_execute, file_size)

		if(output_file != []):

			output_file_path = asksaveasfilename(title = 'Select output cro file')
			save_file(output_file, output_file_path)
		else:
			print('Empty output!')



		while True:
			again_bool = input('Do something more?\nY/N\n').lower()
			if(again_bool == 'y'):
				break
			elif(again_bool == 'n'):
				return

main()