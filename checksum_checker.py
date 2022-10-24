# Samson DeVol, cs372 project5, 10-20-22

# open and read text file returning read lines
def open_read_text_file(text_file):
  with open(text_file) as f:
    lines = f.readlines()
  return lines

# open and read dat file returning data and length
def open_read_dat_file(data_file):
  with open(data_file, "rb") as fp:
    tcp_data = fp.read()
    tcp_length = len(tcp_data)  # <-- right here
  return tcp_data, tcp_length

# gets source and destination addresses from file line
def get_source_and_dest_addr(file_line):
  source_address = file_line[0].split(' ')[0]
  destination_address = file_line[0].split(' ')[1].rstrip()
  return source_address, destination_address

# converts the dots-and-numbers IP addresses into bytestrings.
def addr_to_bytestring(addr):
  bytestring_address = b''
  for byte in addr.split('.'):
    bytestring_address += int(byte).to_bytes(1, 'big')
  return bytestring_address

# generates the IP pseudo header bytes from the IP addresses from tcp_addrs_0.txt and the TCP length from the tcp_data_0.dat file.
def generate_ip_pseudo_header(source, dest, tcp_l):
  zero = b'\x00'
  ptcl = b'\x06'
  tcp_len = tcp_l.to_bytes(2, 'big')
  return source + dest + zero + ptcl + tcp_len

# compute tcp checksum
def get_tcp_checksum(tcp_data):
  tcp_checksum = tcp_data[16:18]
  tcp_checksum = int.from_bytes(tcp_checksum, "big")
  return tcp_checksum

# build a new version of the TCP data that has the checksum set to zero.
def generate_tcp_zero_checksum(tcp_data):
  tcp_zero_checksum = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]
  return tcp_zero_checksum

# append extra byte \x00 if odd length
def make_tcp_even_length(tcp_zero_checksum):
  if len(tcp_zero_checksum) % 2 == 1:
    tcp_zero_checksum += b'\x00'
  return tcp_zero_checksum

# compute checksum from pseudo header and tcp data
def checksum(pseudo_header, tcp_data):
    data = pseudo_header + tcp_data
    total = 0
    offset = 0   # byte offset into data
    while offset < len(data):
      word = int.from_bytes(data[offset:offset + 2], "big")
      total += word
      total = (total & 0xffff) + (total >> 16)  # carry around
      offset += 2   # Go to the next 2-byte value   
    return (~total) & 0xffff  # one's complement

# determine match of checksums
def get_match_status(calc_csum, tcp_csum):
  if calc_csum == tcp_csum:
    print("PASS")
  else: 
    print("FAIL")

# run a comparison for given text and dat file
def run_checksum_comp(text_file, dat_file):
  file = open_read_text_file('tcp_data/tcp_addrs_{}.txt'.format(i))
  source, dest = get_source_and_dest_addr(file)
  source_addr_bytes = addr_to_bytestring(source)
  dest_addr_bytes = addr_to_bytestring(dest)
  tcp_data, tcp_length = open_read_dat_file('tcp_data/tcp_data_{}.dat'.format(i))
  pseudo_header = generate_ip_pseudo_header(source_addr_bytes, dest_addr_bytes, tcp_length)
  tcp_checksum = get_tcp_checksum(tcp_data)
  tcp_zero_checksum = generate_tcp_zero_checksum(tcp_data)
  tcp_zero_checksum = make_tcp_even_length(tcp_zero_checksum)
  calculated_checksum = checksum(pseudo_header, tcp_zero_checksum)
  get_match_status(calculated_checksum, tcp_checksum)

# run all 10 given comps
for i in range(10):
  run_checksum_comp('tcp_data/tcp_addrs_{}.txt'.format(i), 'tcp_data/tcp_data_{}.dat'.format(i))

