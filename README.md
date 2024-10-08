# tdx-vmm-testing

### Failure
There's different behavior displayed by the TDX crate compiled with debug symbols versus when it's compiled with compiler optimizations. This most likely means there is some undefined behavior somewhere.

For example, if you run `cargo test --release` and leave https://github.com/jakecorrenti/tdx-vmm-testing/blob/f5271175d565cb24500637b9f8deb3934960f6f2/tdx/src/launch/mod.rs#L402 uncommented, the TDX Module will return `0xc000010000000040` as the error code. However, if you comment out that line and do `cargo test --release` again, you will get the error code `0xc000010000000041`. Additionally, if you simply just run `cargo test`, it will all pass.

I theorize the culprit has to be: https://github.com/jakecorrenti/tdx-vmm-testing/blob/f5271175d565cb24500637b9f8deb3934960f6f2/tdx/src/launch/mod.rs#L63 The only other functions I wrote, are: https://github.com/jakecorrenti/tdx-vmm-testing/blob/f5271175d565cb24500637b9f8deb3934960f6f2/tdx/src/launch/mod.rs#L19 https://github.com/jakecorrenti/tdx-vmm-testing/blob/f5271175d565cb24500637b9f8deb3934960f6f2/tdx/src/launch/mod.rs#L40 `TdxVm::new()` is just a few `kvm-ioctls` calls, which shouldn't be participating in any undefined behavior. `get_capabilities` isn't required for `KVM_TDX_INIT_VM`, so that also shouldn't be an issue. This leaves `init_vm`...

### Building/running TDX with Libkrun
```bash
cd libkrun
./build_tdx.sh
```
