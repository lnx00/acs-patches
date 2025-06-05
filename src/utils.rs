use ntapi::ntmmapi::NtProtectVirtualMemory;
use ntapi::winapi::shared::ntdef::{HANDLE, NT_SUCCESS, NTSTATUS, ULONG};
use ntapi::winapi::um::winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, PROCESS_VM_OPERATION, PVOID};
use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ACCESS_RIGHTS};

pub fn patch_bytes(address: usize, bytes: &[u8]) -> Result<(), String> {
    unsafe {
        let old_protect = libmem::prot_memory(address, 0, libmem::Prot::XRW)
            .ok_or("failed to change protection")?;

        libmem::write_memory(address, bytes);

        libmem::prot_memory(address, 0, old_protect).ok_or("failed to restore protection")?;
    }

    Ok(())
}

pub fn patch_bytes_nt(address: usize, bytes: &[u8]) -> Result<(), String> {
    unsafe {
        // Get current process ID
        let process_id = GetCurrentProcessId();

        // Open handle to current process with PROCESS_VM_OPERATION privileges
        let process_handle = OpenProcess(
            PROCESS_ACCESS_RIGHTS(PROCESS_VM_OPERATION),
            false,
            process_id,
        );
        // Convert Windows HANDLE to ntapi HANDLE type
        let process_handle = process_handle.expect("failed to get handle").0 as HANDLE;

        //let process_handle = -1isize as HANDLE;

        let mut base_address = address as PVOID;
        let mut size = bytes.len();
        let mut old_protect = 0;

        let status = NtProtectVirtualMemory(
            process_handle,
            &mut base_address,
            &mut size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if !NT_SUCCESS(status) {
            return Err(format!(
                "NtProtectVirtualMemory failed with status: {:#x}",
                status
            ));
        }

        libmem::write_memory(address, bytes);

        let status = NtProtectVirtualMemory(
            process_handle,
            &mut base_address,
            &mut size,
            old_protect,
            &mut old_protect,
        );

        if !NT_SUCCESS(status) {
            return Err(format!(
                "NtProtectVirtualMemory failed with status: {:#x}",
                status
            ));
        }
    }

    Ok(())
}
