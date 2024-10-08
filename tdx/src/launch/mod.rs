// SPDX-License-Identifier: Apache-2.0

mod linux;

use kvm_bindings::{kvm_enable_cap, KVM_CAP_MAX_VCPUS, KVM_CAP_SPLIT_IRQCHIP};
use linux::{Capabilities, Cmd, CmdId, CpuidConfig, InitVm, TdxError};

use bitflags::bitflags;
use kvm_ioctls::VmFd;

// Defined in linux/arch/x86/include/uapi/asm/kvm.h
pub const KVM_X86_TDX_VM: u64 = 2;

/// Handle to the TDX VM file descriptor
pub struct TdxVm {}

impl TdxVm {
    /// Create a new TDX VM with KVM
    pub fn new(vm_fd: &VmFd, max_vcpus: u64) -> Result<Self, TdxError> {
        // TDX requires that MAX_VCPUS and SPLIT_IRQCHIP be set
        let mut cap: kvm_enable_cap = kvm_enable_cap {
            cap: KVM_CAP_MAX_VCPUS,
            ..Default::default()
        };
        cap.args[0] = max_vcpus;
        vm_fd.enable_cap(&cap).unwrap();

        cap.cap = KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = 24;
        vm_fd.enable_cap(&cap).unwrap();

        cap.cap = kvm_bindings::KVM_CAP_X2APIC_API;
        cap.args[0] = (1 << 0) | (1 << 1);
        vm_fd.enable_cap(&cap).unwrap();

        Ok(Self {})
    }

    /// Retrieve information about the Intel TDX module
    pub fn get_capabilities(&self, fd: &VmFd) -> Result<TdxCapabilities, TdxError> {
        let caps = Capabilities::default();
        let mut cmd: Cmd = Cmd::from(&caps);

        unsafe {
            fd.encrypt_op(&mut cmd)?;
        }

        Ok(TdxCapabilities {
            attributes: Attributes {
                fixed0: AttributesFlags::from_bits_truncate(caps.attrs_fixed0),
                fixed1: AttributesFlags::from_bits_truncate(caps.attrs_fixed1),
            },
            xfam: Xfam {
                fixed0: XFAMFlags::from_bits_truncate(caps.xfam_fixed0),
                fixed1: XFAMFlags::from_bits_truncate(caps.xfam_fixed1),
            },
            supported_gpaw: caps.supported_gpaw,
            cpuid_configs: Vec::from(caps.cpuid_configs),
        })
    }

    /// Do additional VM initialization that is specific to Intel TDX
    pub fn init_vm(&self, fd: &VmFd, cpuid: kvm_bindings::CpuId) -> Result<(), TdxError> {
        let mut cpuid_entries: Vec<kvm_bindings::kvm_cpuid_entry2> = cpuid.as_slice().to_vec();

        // resize to 256 entries to make sure that InitVm is 8KB
        cpuid_entries.resize(256, kvm_bindings::kvm_cpuid_entry2::default());

        // patch cpuid
        // for entry in cpuid_entries.as_mut_slice() {
        //     if entry.function == 0xD && entry.index == 0 {
        //         const XFEATURE_MASK_XTILE: u32 = (1 << 17) | (1 << 18);
        //         if (entry.eax & XFEATURE_MASK_XTILE) != XFEATURE_MASK_XTILE {
        //             entry.eax &= !XFEATURE_MASK_XTILE;
        //         }
        //     }

        //     if entry.function == 0xD && entry.index == 1 {
        //         entry.ecx &= !(1 << 15);
        //         const XFEATURE_MASK_CET: u32 = (1 << 11) | (1 << 12);
        //         if entry.ecx & XFEATURE_MASK_CET > 0 {
        //             entry.ecx |= XFEATURE_MASK_CET;
        //         }
        //     }
        // }

        cpuid_entries[0].eax = 31;
        cpuid_entries[0].ebx = 1970169159;
        cpuid_entries[0].ecx = 1818588270;
        cpuid_entries[0].edx = 1231384169;

        cpuid_entries[1].function = 1;
        cpuid_entries[1].eax = 788210;
        cpuid_entries[1].ebx = 2048;
        cpuid_entries[1].ecx = 4160369175;
        cpuid_entries[1].edx = 799800319;

        cpuid_entries[2].function = 2;
        cpuid_entries[2].index = 0;
        cpuid_entries[2].flags = 6;
        cpuid_entries[2].eax = 1;
        cpuid_entries[2].ebx = 0;
        cpuid_entries[2].ecx = 77;
        cpuid_entries[2].edx = 2895997;

        cpuid_entries[3].function = 4;
        cpuid_entries[3].index = 0;
        cpuid_entries[3].flags = 1;
        cpuid_entries[3].eax = 289;
        cpuid_entries[3].ebx = 29360191;
        cpuid_entries[3].ecx = 63;
        cpuid_entries[3].edx = 1;

        cpuid_entries[4].function = 4;
        cpuid_entries[4].index = 1;
        cpuid_entries[4].flags = 1;
        cpuid_entries[4].eax = 290;
        cpuid_entries[4].ebx = 29360191;
        cpuid_entries[4].ecx = 63;
        cpuid_entries[4].edx = 1;

        cpuid_entries[5].function = 4;
        cpuid_entries[5].index = 2;
        cpuid_entries[5].flags = 1;
        cpuid_entries[5].eax = 323;
        cpuid_entries[5].ebx = 62914623;
        cpuid_entries[5].ecx = 4095;
        cpuid_entries[5].edx = 1;

        cpuid_entries[6].function = 4;
        cpuid_entries[6].index = 3;
        cpuid_entries[6].flags = 1;
        cpuid_entries[6].eax = 355;
        cpuid_entries[6].ebx = 62914623;
        cpuid_entries[6].ecx = 16383;
        cpuid_entries[6].edx = 6;

        cpuid_entries[7].function = 4;
        cpuid_entries[7].index = 4;
        cpuid_entries[7].flags = 1;
        cpuid_entries[7].eax = 0;
        cpuid_entries[7].ebx = 0;
        cpuid_entries[7].ecx = 0;
        cpuid_entries[7].edx = 0;

        cpuid_entries[8].function = 5;
        cpuid_entries[8].index = 0;
        cpuid_entries[8].flags = 0;
        cpuid_entries[8].eax = 0;
        cpuid_entries[8].ebx = 0;
        cpuid_entries[8].ecx = 3;
        cpuid_entries[8].edx = 0;

        cpuid_entries[9].function = 6;
        cpuid_entries[9].index = 0;
        cpuid_entries[9].flags = 0;
        cpuid_entries[9].eax = 4;
        cpuid_entries[9].ebx = 0;
        cpuid_entries[9].ecx = 0;
        cpuid_entries[9].edx = 0;

        cpuid_entries[10].function = 7;
        cpuid_entries[10].index = 0;
        cpuid_entries[10].flags = 1;
        cpuid_entries[10].eax = 1;
        cpuid_entries[10].ebx = 4055830457;
        cpuid_entries[10].ecx = 457269070;
        cpuid_entries[10].edx = 4291380240;

        cpuid_entries[11].function = 7;
        cpuid_entries[11].index = 1;
        cpuid_entries[11].flags = 1;
        cpuid_entries[11].eax = 7216;
        cpuid_entries[11].ebx = 0;
        cpuid_entries[11].ecx = 0;
        cpuid_entries[11].edx = 0;

        cpuid_entries[12].function = 11;
        cpuid_entries[12].index = 0;
        cpuid_entries[12].flags = 1;
        cpuid_entries[12].eax = 0;
        cpuid_entries[12].ebx = 1;
        cpuid_entries[12].ecx = 256;
        cpuid_entries[12].edx = 0;

        cpuid_entries[13].function = 11;
        cpuid_entries[13].index = 1;
        cpuid_entries[13].flags = 1;
        cpuid_entries[13].eax = 0;
        cpuid_entries[13].ebx = 1;
        cpuid_entries[13].ecx = 513;
        cpuid_entries[13].edx = 0;

        cpuid_entries[14].function = 11;
        cpuid_entries[14].index = 2;
        cpuid_entries[14].flags = 1;
        cpuid_entries[14].eax = 0;
        cpuid_entries[14].ebx = 0;
        cpuid_entries[14].ecx = 2;
        cpuid_entries[14].edx = 0;

        cpuid_entries[15].function = 13;
        cpuid_entries[15].index = 0;
        cpuid_entries[15].flags = 1;
        cpuid_entries[15].eax = 393959;
        cpuid_entries[15].ebx = 11008;
        cpuid_entries[15].ecx = 11008;
        cpuid_entries[15].edx = 0;

        cpuid_entries[16].function = 13;
        cpuid_entries[16].index = 1;
        cpuid_entries[16].flags = 1;
        cpuid_entries[16].eax = 31;
        cpuid_entries[16].ebx = 11504;
        cpuid_entries[16].ecx = 0;
        cpuid_entries[16].edx = 0;

        cpuid_entries[17].function = 13;
        cpuid_entries[17].index = 2;
        cpuid_entries[17].flags = 1;
        cpuid_entries[17].eax = 256;
        cpuid_entries[17].ebx = 576;
        cpuid_entries[17].ecx = 0;
        cpuid_entries[17].edx = 0;

        cpuid_entries[18].function = 13;
        cpuid_entries[18].index = 5;
        cpuid_entries[18].flags = 1;
        cpuid_entries[18].eax = 64;
        cpuid_entries[18].ebx = 1088;
        cpuid_entries[18].ecx = 0;
        cpuid_entries[18].edx = 0;

        cpuid_entries[19].function = 13;
        cpuid_entries[19].index = 6;
        cpuid_entries[19].flags = 1;
        cpuid_entries[19].eax = 512;
        cpuid_entries[19].ebx = 1152;
        cpuid_entries[19].ecx = 0;
        cpuid_entries[19].edx = 0;

        cpuid_entries[20].function = 13;
        cpuid_entries[20].index = 7;
        cpuid_entries[20].flags = 1;
        cpuid_entries[20].eax = 1024;
        cpuid_entries[20].ebx = 1664;
        cpuid_entries[20].ecx = 0;
        cpuid_entries[20].edx = 0;

        cpuid_entries[21].function = 13;
        cpuid_entries[21].index = 9;
        cpuid_entries[21].flags = 1;
        cpuid_entries[21].eax = 8;
        cpuid_entries[21].ebx = 2688;
        cpuid_entries[21].ecx = 0;
        cpuid_entries[21].edx = 0;

        cpuid_entries[22].function = 13;
        cpuid_entries[22].index = 15;
        cpuid_entries[22].flags = 1;
        cpuid_entries[22].eax = 808;
        cpuid_entries[22].ebx = 0;
        cpuid_entries[22].ecx = 1;
        cpuid_entries[22].edx = 0;

        cpuid_entries[23].function = 13;
        cpuid_entries[23].index = 17;
        cpuid_entries[23].flags = 1;
        cpuid_entries[23].eax = 64;
        cpuid_entries[23].ebx = 2752;
        cpuid_entries[23].ecx = 2;
        cpuid_entries[23].edx = 0;

        cpuid_entries[24].function = 13;
        cpuid_entries[24].index = 18;
        cpuid_entries[24].flags = 1;
        cpuid_entries[24].eax = 8192;
        cpuid_entries[24].ebx = 2816;
        cpuid_entries[24].ecx = 6;
        cpuid_entries[24].edx = 0;

        cpuid_entries[25].function = 13;
        cpuid_entries[25].index = 63;
        cpuid_entries[25].flags = 1;
        cpuid_entries[25].eax = 0;
        cpuid_entries[25].ebx = 0;
        cpuid_entries[25].ecx = 0;
        cpuid_entries[25].edx = 0;

        cpuid_entries[26].function = 18;
        cpuid_entries[26].index = 0;
        cpuid_entries[26].flags = 1;
        cpuid_entries[26].eax = 0;
        cpuid_entries[26].ebx = 0;
        cpuid_entries[26].ecx = 0;
        cpuid_entries[26].edx = 0;

        cpuid_entries[27].function = 18;
        cpuid_entries[27].index = 1;
        cpuid_entries[27].flags = 1;
        cpuid_entries[27].eax = 0;
        cpuid_entries[27].ebx = 0;
        cpuid_entries[27].ecx = 0;
        cpuid_entries[27].edx = 0;

        cpuid_entries[28].function = 18;
        cpuid_entries[28].index = 2;
        cpuid_entries[28].flags = 1;
        cpuid_entries[28].eax = 0;
        cpuid_entries[28].ebx = 0;
        cpuid_entries[28].ecx = 0;
        cpuid_entries[28].edx = 0;

        cpuid_entries[29].function = 20;
        cpuid_entries[29].index = 0;
        cpuid_entries[29].flags = 1;
        cpuid_entries[29].eax = 0;
        cpuid_entries[29].ebx = 0;
        cpuid_entries[29].ecx = 0;
        cpuid_entries[29].edx = 0;

        cpuid_entries[30].function = 29;
        cpuid_entries[30].index = 0;
        cpuid_entries[30].flags = 1;
        cpuid_entries[30].eax = 1;
        cpuid_entries[30].ebx = 0;
        cpuid_entries[30].ecx = 0;
        cpuid_entries[30].edx = 0;

        cpuid_entries[31].function = 29;
        cpuid_entries[31].index = 1;
        cpuid_entries[31].flags = 1;
        cpuid_entries[31].eax = 67117056;
        cpuid_entries[31].ebx = 524352;
        cpuid_entries[31].ecx = 16;
        cpuid_entries[31].edx = 0;

        cpuid_entries[32].function = 30;
        cpuid_entries[32].index = 0;
        cpuid_entries[32].flags = 1;
        cpuid_entries[32].eax = 0;
        cpuid_entries[32].ebx = 16400;
        cpuid_entries[32].ecx = 0;
        cpuid_entries[32].edx = 0;

        cpuid_entries[33].function = 2147483648;
        cpuid_entries[33].index = 0;
        cpuid_entries[33].flags = 0;
        cpuid_entries[33].eax = 2147483656;
        cpuid_entries[33].ebx = 1970169159;
        cpuid_entries[33].ecx = 1818588270;
        cpuid_entries[33].edx = 1231384169;

        cpuid_entries[34].function = 2147483649;
        cpuid_entries[34].index = 0;
        cpuid_entries[34].flags = 0;
        cpuid_entries[34].eax = 788210;
        cpuid_entries[34].ebx = 0;
        cpuid_entries[34].ecx = 289;
        cpuid_entries[34].edx = 739248128;

        cpuid_entries[35].function = 2147483650;
        cpuid_entries[35].index = 0;
        cpuid_entries[35].flags = 0;
        cpuid_entries[35].eax = 1163152969;
        cpuid_entries[35].ebx = 693250124;
        cpuid_entries[35].ecx = 1329944608;
        cpuid_entries[35].edx = 693250126;

        cpuid_entries[36].function = 2147483651;
        cpuid_entries[36].index = 0;
        cpuid_entries[36].flags = 0;
        cpuid_entries[36].eax = 1280263968;
        cpuid_entries[36].ebx = 892674116;
        cpuid_entries[36].ecx = 5583409;
        cpuid_entries[36].edx = 0;

        cpuid_entries[37].function = 2147483653;
        cpuid_entries[37].index = 0;
        cpuid_entries[37].flags = 0;
        cpuid_entries[37].eax = 33489407;
        cpuid_entries[37].ebx = 33489407;
        cpuid_entries[37].ecx = 1073873216;
        cpuid_entries[37].edx = 1073873216;

        cpuid_entries[38].function = 2147483654;
        cpuid_entries[38].index = 0;
        cpuid_entries[38].flags = 0;
        cpuid_entries[38].eax = 0;
        cpuid_entries[38].ebx = 1107313152;
        cpuid_entries[38].ecx = 33587520;
        cpuid_entries[38].edx = 8421696;

        cpuid_entries[39].function = 2147483656;
        cpuid_entries[39].index = 0;
        cpuid_entries[39].flags = 0;
        cpuid_entries[39].eax = 14640;
        cpuid_entries[39].ebx = 512;
        cpuid_entries[39].ecx = 0;
        cpuid_entries[39].edx = 0;

        println!("cpuid entries: {:#?}", &cpuid_entries[..40]);
        // println!("this is going to trigger the invalid operand to go from 41 to 40");

        let mut cmd = Cmd::from(&InitVm::new(&cpuid_entries));
        unsafe {
            let res = fd.encrypt_op(&mut cmd);
            println!("cmd.error: {:x}", cmd.error);
            println!("cmd: {:#?}", cmd);
            println!("res: {:#?}", res);
            res?;
        }

        Ok(())
    }

    /// Encrypt a memory continuous region
    pub fn init_mem_region(
        &self,
        fd: &VmFd,
        gpa: u64,
        nr_pages: u64,
        attributes: u32,
        source_addr: u64,
    ) -> Result<(), TdxError> {
        const TDVF_SECTION_ATTRIBUTES_MR_EXTEND: u32 = 1u32 << 0;
        let mem_region = linux::TdxInitMemRegion {
            source_addr,
            gpa,
            nr_pages,
        };

        let mut cmd = Cmd::from(&mem_region);

        // determines if we also extend the measurement
        cmd.flags = if attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND > 0 {
            1
        } else {
            0
        };

        unsafe {
            fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }

    /// Complete measurement of the initial TD contents and mark it ready to run
    pub fn finalize(&self, fd: &VmFd) -> Result<(), TdxError> {
        let mut cmd = Cmd {
            id: CmdId::FinalizeVm as u32,
            ..Default::default()
        };
        unsafe {
            fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct AttributesFlags: u64 {
        /// TD Under Debug (TUD) group

        /// Bit 0. Guest TD runs in off-TD debug mode
        const DEBUG = 1;

        /// Bits 3:1. Reserved for future TUD flags
        const TUD_RESERVED = 0x7 << 1;

        /// TD Under Profiling (TUP) group

        /// Bit 4. The TD participates in HGS+ operation
        const HGS_PLUS_PROF = 1 << 4;

        /// Bit 5. The TD participates in system profiling using performance monitoring
        /// counters
        const PERF_PROF = 1 << 5;

        /// Bit 6. The TD participates in system profiling using core out-of-band
        /// telemetry
        const PMT_PROF = 1 << 6;

        /// Bits 15:7. Reserved for future TUP flags
        const TUP_RESERVED = 0x1FF << 7;

        /// Security (SEC) group

        /// Bits 22:16. Reserved for future SEC flags that will indicate positive impact on
        /// TD security
        const SEC_RESERVED_P = 0x7F << 16;

        /// Bits 23:26. Reserved for future SEC flags that will indicate negative impact on
        /// TD security
        const SEC_RESERVED_N = 0xF << 23;

        /// Bit 27. TD is allowed to use Linear Address Space Separation
        const LASS = 1 << 27;

        /// Bit 28. Disable EPT violation conversion to #VE on guest TD access of
        /// PENDING pages
        const SEPT_VE_DISABLE = 1 << 28;

        /// Bit 29. TD is migratable (using a Migration TD)
        const MIGRATABLE = 1 << 29;

        /// Bit 30. TD is allowed to use Supervisor Protection Keys
        const PKS = 1 << 30;

        /// Bit 31. TD is allowed to use Key Locker
        const KL = 1 << 31;

        /// RESERVED Group

        /// Bits 55:32. Reserved for future expansion of the SEC group
        const SEC_EXP_RESERVED = 0xFFFFFF << 32;

        /// OTHER group

        /// Bits 61:32. Reserved for future OTHER flags
        const OTHER_RESERVED = 0x3FFFFFFF << 32;

        /// Bit 62. The TD is a TDX Connet Provisioning Agent
        const TPA = 1 << 62;

        /// Bit 63. TD is allowed to use Perfmon and PERF_METRICS capabilities
        const PERFMON = 1 << 63;
    }

    #[derive(Debug)]
    pub struct XFAMFlags: u64 {
        /// Bit 0. Always enabled
        const FP = 1;

        /// Bit 1. Always enabled
        const SSE = 1 << 1;

        /// Bit 2. Execution is directly controlled by XCR0
        const AVX = 1 << 2;

        /// Bits 4:3. Being deprecated
        const MPX = 0x3 << 3;

        /// Bits 7:5. Execution is directly contrtolled by XCR0. May be enabled only if
        /// AVX is enabled
        const AVX512 = 0x7 << 5;

        /// Bit 8. Execution is controlled by IA32_RTIT_CTL
        const PT = 1 << 8;

        /// Bit 9. Execution is controlled by CR4.PKE
        const PK = 1 << 9;

        /// Bit 10. Execution is controlled by IA32_PASID MSR
        const ENQCMD = 1 << 10;

        /// Bits 12:11. Execution is controlled by CR4.CET
        const CET = 0x3 << 11;

        /// Bit 13. Hardware Duty Cycle is controlled by package-scope IA32_PKG_HDC_CTL
        /// and LP-scope IA32_PM_CTL1 MSRs
        const HDC = 1 << 13;

        /// Bit 14. Execution is controlled by CR4.UINTR
        const ULI = 1 << 14;

        /// Bit 15. Execution is controlled by IA32_LBR_CTL
        const LBR = 1 << 15;

        /// Bit 16. Execution of Hardware-Controlled Performance State is controlled by
        /// IA32_HWP MSRs
        const HWP = 1 << 16;

        /// Bits 18:17. Advanced Matrix Extensions (AMX) is directly controlled by XCR0
        const AMX = 0x3 << 17;
    }
}

/// Reflects the Intel TDX module capabilities and configuration and CPU
/// capabilities
#[derive(Debug)]
pub struct Attributes {
    pub fixed0: AttributesFlags,
    pub fixed1: AttributesFlags,
}

/// Determines the set of extended features available for use by the guest TD
#[derive(Debug)]
pub struct Xfam {
    pub fixed0: XFAMFlags,
    pub fixed1: XFAMFlags,
}

/// Provides information about the Intel TDX module
#[derive(Debug)]
pub struct TdxCapabilities {
    pub attributes: Attributes,
    pub xfam: Xfam,

    /// supported Guest Physical Address Width
    pub supported_gpaw: u32,

    pub cpuid_configs: Vec<CpuidConfig>,
}

/// Manually create the wrapper for KVM_MEMORY_ENCRYPT_OP since `kvm_ioctls` doesn't
/// support `.encrypt_op` for vcpu fds
use vmm_sys_util::*;
ioctl_iowr_nr!(
    KVM_MEMORY_ENCRYPT_OP,
    kvm_bindings::KVMIO,
    0xba,
    std::os::raw::c_ulong
);

pub struct TdxVcpu<'a> {
    pub fd: &'a mut kvm_ioctls::VcpuFd,
}

impl<'a> TdxVcpu<'a> {
    pub fn init_raw(fd: &kvm_ioctls::VcpuFd, hob_address: u64) -> Result<(), TdxError> {
        let mut cmd = Cmd {
            id: linux::CmdId::InitVcpu as u32,
            flags: 0,
            data: hob_address as *const u64 as _,
            error: 0,
            _unused: 0,
        };
        let ret = unsafe { ioctl::ioctl_with_mut_ptr(fd, KVM_MEMORY_ENCRYPT_OP(), &mut cmd) };
        if ret < 0 {
            // can't return `ret` because it will just return -1 and not give the error
            // code. `cmd.error` will also just be 0.
            return Err(TdxError::from(errno::Error::last()));
        }
        Ok(())
    }

    pub fn init(&self, hob_address: u64) -> Result<(), TdxError> {
        let mut cmd = Cmd {
            id: linux::CmdId::InitVcpu as u32,
            flags: 0,
            data: hob_address as *const u64 as _,
            error: 0,
            _unused: 0,
        };
        let ret = unsafe { ioctl::ioctl_with_mut_ptr(self.fd, KVM_MEMORY_ENCRYPT_OP(), &mut cmd) };
        if ret < 0 {
            // can't return `ret` because it will just return -1 and not give the error
            // code. `cmd.error` will also just be 0.
            return Err(TdxError::from(errno::Error::last()));
        }
        Ok(())
    }
}

impl<'a> TryFrom<(&'a mut kvm_ioctls::VcpuFd, &'a mut kvm_ioctls::Kvm)> for TdxVcpu<'a> {
    type Error = TdxError;

    fn try_from(
        value: (&'a mut kvm_ioctls::VcpuFd, &'a mut kvm_ioctls::Kvm),
    ) -> Result<Self, Self::Error> {
        // need to enable the X2APIC bit for CPUID[0x1] so that the kernel can call
        // KVM_SET_MSRS(MSR_IA32_APIC_BASE) without failing
        let mut cpuid = value
            .1
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
        for entry in cpuid.as_mut_slice().iter_mut() {
            if entry.index == 0x1 {
                entry.ecx &= 1 << 21;
            }
        }
        value.0.set_cpuid2(&cpuid)?;
        Ok(Self { fd: value.0 })
    }
}
