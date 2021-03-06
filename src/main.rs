extern crate byteorder;
extern crate elf;
use std::path::PathBuf;

extern crate rbpf;
use rbpf::helpers;

fn main() {
    // Load a program from an ELF file, e.g. compiled from C to eBPF with
    // clang/LLVM. Some minor modification to the bytecode may be required.
    let filename = concat!(env!("OUT_DIR"), "/index_of_hello.o");

    let path = PathBuf::from(filename);
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    // Here we assume the eBPF program is in the ELF section called
    // ".classifier".
    let text_scn = match file.get_section(".classifier") {
        Some(s) => s,
        None => panic!("Failed to look up .classifier section"),
    };

    let prog = &text_scn.data;

    // This is our data: a real packet, starting with Ethernet header
    let mut packet = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x08, 0x00,             // ethertype
        0x45, 0x00, 0x00, 0x3b, // start ip_hdr
        0xa6, 0xab, 0x40, 0x00,
        0x40, 0x06, 0x96, 0x0f,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x99, 0x99, 0xc6, 0xcc, // start tcp_hdr
        0xd1, 0xe5, 0xc4, 0x9d,
        0xd4, 0x30, 0xb5, 0xd2,
        0x80, 0x18, 0x01, 0x56,
        0xfe, 0x2f, 0x00, 0x00,
        0x01, 0x01, 0x08, 0x0a, // start data
        0x00, 0x23, 0x75, 0x89,
        0x48, 0x45, 0x4c, 0x4c, // ASCII: H E L L
        0x4f, 0x64, 0x66, 0x73, // O
        0x64, 0x66, 0x0a
    ];

    // This is an eBPF VM for programs using a virtual metadata buffer, similar
    // to the sk_buff that eBPF programs use with tc and in Linux kernel.
    // We must provide the offsets at which the pointers to packet data start
    // and end must be stored: these are the offsets at which the program will
    // load the packet data from the metadata buffer.
    let mut vm = rbpf::EbpfVmFixedMbuff::new(prog, 0x40, 0x50);

    // We register a helper function, that can be called by the program, into
    // the VM.
    // FIXME: We should be passing helpers::BPF_TRACE_PRINTK_IDX as first parameter instead of 0
    // but VM calls helper 0 for bpf_trace_printk call.
    vm.register_helper(0, helpers::bpf_trace_printf);

    // This kind of VM takes a reference to the packet data, but does not need
    // any reference to the metadata buffer: a fixed buffer is handled
    // internally by the VM.
    let res = vm.prog_exec(& mut packet);
    println!("Program returned: {:?} ({:#x})", res, res);
}
