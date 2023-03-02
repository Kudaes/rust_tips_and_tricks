# rust_tips_and_tricks
This repo is just a collection of Rust tips and tricks **useful to interact with the Windows API.** 

**This is not a tutorial, the content in this repo won't teach you how to code in Rust.** The only goal of this repo is to share the knowledge that I have obtained during the last years implementing offensive tools in Rust, hoping that this tips and tricks help you to solve some of the annoying issues that I have found at the time of interacting with Windows API from this language. 
Also, below I add a snippet of how to start a new project of these characteristics using Dinvoke_rs, hoping that this will solve any pending doubts and will allow anyone to start using the project.

I don't consider myself an expert or guru in Rust, which means that they could be better ways of doing things as I show them here. However, I've found very useful to know all these techniques and I hope they save you all the time that I had to invest in order to make my code work.

## Tips, Tricks and Issues resolution

- [Getting started with DInvoke_rs](#DInvoke_rs)
- [Structs and Types](#structs-and-types)
  - [Definition of structs](#definition-of-structs)
  - [Instantiation of structs](#instantiation-of-structs)
  - [NTSTATUS](#ntstatus)
- [Pointers](#pointers)
  - [Casting](#casting)
  - [Memory addresses](#memory-addresses)
  - [Arithmetic operations](#arithmetic-operations)
- [Compiling your code](#resources)
  - [Release](#release)
  - [Compile to dll](#compile-to-dll)
  - [PE size](#pe-size)
- [Issues](#issues)
  - [Default() and transmute()](#default()-and-transmute())
  - [VCRuntime](#vcruntime)
  - [Nightly](#nightly)
  - [ASM](#asm)
  - [Wide char string](#wide-char-string) -> utf8 en rust
  - [Compile to dll](#compile-to-dll)
  - [PE size](#pe-size)
  - [Encrypt string literals](#encrypt-string-literals)
- [Resources](#resources)
- [Contribution](#contribution)

# DInvoke_rs
To me, the most straighforward way to create a new tool in Rust that requires the interaction with the Windows API is to download the [Dinvoke_rs](https://github.com/Kudaes/DInvoke_rs/tree/main/dinvoke_rs) project and use it as a template, adding my code on top of it. Dinvoke_rs offers three main functionalities:

* **DInvoke**: It allows to dynamically find and execute unmanaged code. This is perfect since it allows us to call any function of WinAPI withtout leaving any trace in the final PE IAT, increasing our OPSEC.
* **Manualmap**: Manually maps any PE as LoadLibrary (or the operative system) would do, both from disk and memory.
* **Overload**: It manually maps a PE in a file-backed memory section of the current process.

In case that you only need the DInvoke functionality, I have created a [minimalist branch]() on the repository that contains the minimum code required in order to use that crate. In case that you want to use the rest of the functionalities described before, just download the code from the main branch.

Once we have the DInvoke_rs project, we can start calling any WinApi function that we need. For that, it is required to follow these simple steps (the steps below show how to call **ntdll!NtAllocateVirtualMemory**):

1) Define the function signature in the crate data (check the Structs and Types section to know how to easily obtain these function signatures):
```rust
pub type NtWriteVirtualMemory = unsafe extern "system" fn (HANDLE, PVOID, PVOID, usize, *mut usize) -> i32;

```
In many cases, you will also need to [define structs and data types]() used as input/output parameters by the function that you are calling. The best practice is to define them in the same data crate.

2) Create a small function in the dinvoke crate that dynamically obtains the base address of ntdll, and then calls the macro `dynamic_invoke!()`:
```rust
/// Dynamically calls NtAllocateVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_allocate_virtual_memory (handle: HANDLE, base_address: *mut PVOID, zero_bits: usize, size: *mut usize, allocation_type: u32, protection: u32) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtAllocateVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtAllocateVirtualMemory"),func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }   
}
```

3) Define in `src::main.rs` the required parameters and call the function:
```rust
let ba = usize::default();
let base_address: *mut PVOID = std::mem::transmute(&ba);
let zero_bits = 0 as usize;
let dwsize = 354 as usize; // Allocate as much memory as you need
let size: *mut usize = std::mem::transmute(&dwsize);
let handle = HANDLE {0 : -1}; // Current process
let ret = dinvoke::nt_allocate_virtual_memory(
          handle, 
          base_address, 
          zero_bits, 
          size, 
          MEM_COMMIT | MEM_RESERVE, 
          PAGE_READWRITE);

if ret == 0
{
    println!("Success!");
}
else
{
    println!("rip");
}
``` 

You just need to repeat these steps for any other WinAPI call that you want to use.

If you don't care about or do not need the advantages that DInvoke_rs offers, it may be better for you to directly import the crates [windows](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html) and/or [ntapi](https://docs.rs/ntapi/latest/ntapi/) instead of loosing your time defining types, structs and function signatures. These crates will act like some sort of "PInvoke" for both Win32 (windows) and NT API (ntapi), allowing you to directly call any WinAPI function at the expense of losing a little bit of stealth and OPSEC.

# Structs and Types
## Definition of structs
In many situations you will need to use several structs in order to interact with WinAPI. The easiest way to use these structs is by import them directly from the official crates [windows](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html) and [ntapi](https://docs.rs/ntapi/latest/ntapi/). By doing so, you won't need to define them manually.

Although this is very convenient, I have noticed that not all the structs in those crates are well defined. The vast majority of cases where the struct definition was wrong is due to an incorrect number of fields which prevents to use the struct efficiently, but in some cases even the size of the struct was wrong.

Either the struct is poorly defined or it is not defined at all, you can define your own structs very easily (preferably in the `data` crate):

```rust
#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub number_of_handles: u32,
    pub handles: Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO>,
}
```
By default, you will need to add the `#[repr(C)]` attribute to keep the fields order, otherwise Rust may change that order randomly at compilation. 

On the other hand, some structs have fields that are arrays of an undetermined size and those fields are commonly defined in Rust as an array of one single element. For example:
```rust
#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub NumberOfHandles: ULONG,
    pub Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 1],
}
```
In this scenario, I have noticed that is way better to manually define the struct in your code instead of directly import it as it is from the official crates, which will allow you to replace the one element array with a dynamic size vector:
```rust
#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub number_of_handles: u32,
    pub handles: Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO>,
}
```

Finally, I recommend to add the trait Default for any defined struct in case that you need to instantiate it somewhere else in your code. If the struct is solely composed of basic type fields, you will be able to automatically create this method by using the `#[derive(Copy, Clone, Default)]` attribute; otherwise, you will need to manually implement it:
```rust
// Automatically provided Default trait
#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetNamespace {
    pub unused: [u8;12],
    pub count: i32, // offset 0x0C
    pub entry_offset: i32, // offset 0x10
}

// Example of how to manually implement the trait Default
#[derive(Clone)]
#[repr(C)]
pub struct PeMetadata {
    pub pe: u32,
    pub is_32_bit: bool,
    pub image_file_header: IMAGE_FILE_HEADER,
    pub opt_header_32: IMAGE_OPTIONAL_HEADER32,
    pub opt_header_64: IMAGE_OPTIONAL_HEADER64,
    pub sections: Vec<IMAGE_SECTION_HEADER> 
}

impl Default for PeMetadata {
    fn default() -> PeMetadata {
        PeMetadata {
            pe: u32::default(),
            is_32_bit: false,
            image_file_header: IMAGE_FILE_HEADER::default(),
            opt_header_32: IMAGE_OPTIONAL_HEADER32::default(),
            opt_header_64: IMAGE_OPTIONAL_HEADER64::default(),
            sections: Vec::default(),  
        }
    }
}
```

## Instantiation of structs
The best way of intantiating a struct in case that you need to modify its fields before sending it as an input for some WinAPI call is to use the trait `Default`:
```rust
let handle: HANDLE = HANDLE::default();
```
Other ways of instantiating a struct, specially if you are gonna use it only as an ouput parameter (and therefore you just need to reserve the corresponding memory) are these two:
```rust
let create_info: PS_CREATE_INFO = std::mem::zeroed();
```
```rust
let unused: Vec<u8> = vec![0;size_of::<HANDLE>()];
let handle: *mut HANDLE = std::mem::transmute(unused.as_ptr());
```
Obviously, this last option is only good when you need to directly create a pointer to the struct. In any other case is better to use the other two alternatives.

## NTSTATUS
NTSTATUS is a struct heavily used in the NT API, and in Rust you can define it as an `i32`. There is not much mistery on this topic, just know that you can obtain the hex value of a NTSTATUS printing it like this:
```rust
let ret = dinvoke::nt_allocate_virtual_memory(
          handle, 
          base_address, 
          zero_bits, 
          size, 
          MEM_COMMIT | MEM_RESERVE, 
          PAGE_READWRITE);

println!("NTSTATUS: {:x}", ret);

```
Then you can check this hex value in the [official documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) and get a little bit of info about why is your code failing (warning: It is probable that you will end up crying loudly after obtaining the tenth "Invalid Parameter" NTSTATUS in a row).
### 





## Contribution
