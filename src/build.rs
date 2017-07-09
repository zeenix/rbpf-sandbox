// build.rs

use std::env;
use std::io::Write;
use std::path::Path;
use std::fs::File;

use std::process::{Command, Stdio};

use std::io::Read;

fn main() {
    let clang_out = Command::new("clang")
                     .arg("-O2")
                     .arg("-emit-llvm")
                     .arg("-c")
                     .arg("src/load_elf__block_a_port.c")
                     .arg("-o")
                     .arg("-")
                     .output()
                     .expect("failed to execute process");

    let out_dir = env::var("OUT_DIR").unwrap();
    let tmp_path = Path::new(&out_dir).join("load_elf__block_a_port.o.tmp");
    let dest_path = Path::new(&out_dir).join("load_elf__block_a_port.o");

    let mut process = match Command::new("llc")
                     .arg("-march=bpf")
                     .arg("-filetype=obj")
                     .arg("-o")
                     .arg(& tmp_path)
                     .stdin(Stdio::piped())
                     .stdout(Stdio::piped())
                     .spawn() {
        Err(why) => panic!("couldn't spawn llc: {}", why),
        Ok(process) => process,
    };

    if let Err(why) = process.stdin.as_mut().unwrap().write_all(& clang_out.stdout) {
        panic!("couldn't write to wc stdin: {}", why);
    }
    process.wait().unwrap();

    let xxd_out = Command::new("xxd")
                     .arg(& tmp_path)
                     .output()
                     .expect("failed to execute process");

    let mut sed_process = match Command::new("sed")
                     .arg("-e s/6112 5000 0000 0000/7912 5000 0000 0000/")
                     .arg("-e s/6111 4c00 0000 0000/7911 4000 0000 0000/")
                     .arg("-e s/6111 2200 0000 0000/7911 2200 0000 0000/")
                     .stdin(Stdio::piped())
                     .stdout(Stdio::piped())
                     .spawn() {
        Err(why) => panic!("couldn't spawn sed: {}", why),
        Ok(sed_process) => sed_process,
    };

    if let Err(why) = sed_process.stdin.as_mut().unwrap().write_all(& xxd_out.stdout) {
        panic!("couldn't write to wc stdin: {}", why);
    }
    sed_process.wait().unwrap();

    let mut sed_out: Vec<u8> = vec!();
    sed_process.stdout.unwrap().read_to_end(& mut sed_out).unwrap();

    let mut rxxd_process = match Command::new("xxd")
                     .arg("-r")
                     .stdin(Stdio::piped())
                     .stdout(Stdio::piped())
                     .spawn() {
        Err(why) => panic!("couldn't spawn sed: {}", why),
        Ok(rxxd_process) => rxxd_process,
    };

    if let Err(why) = rxxd_process.stdin.as_mut().unwrap().write_all(& sed_out) {
        panic!("couldn't write to wc stdin: {}", why);
    }
    rxxd_process.wait().unwrap();

    let mut rxxd_out: Vec<u8> = vec!();
    rxxd_process.stdout.unwrap().read_to_end(& mut rxxd_out).unwrap();

    let mut f = File::create(&dest_path).unwrap();
    if let Err(why) = f.write_all(& rxxd_out) {
        panic!("couldn't write to binary file: {}", why);
    }
    f.flush().unwrap();

    println!("Wrote {} bytes!", rxxd_out.len());
}
