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
  - [Function signatures](#function-signatures)
- [Pointers](#pointers)
  - [Casting](#casting)
  - [Memory addresses](#memory-addresses)
  - [Arithmetic operations](#arithmetic-operations)
- [Compile](#compile)
  - [Reducing PE size](#reducing-pe-size)
  - [Compile to dll](#compile-to-dll)
- [Issues resolution](#issues-resolution)
  - [default() and transmute()](#default()-and-transmute())
  - [VCRuntime](#vcruntime)
  - [Nightly](#nightly)
  - [ASM](#asm)
  - [Wide char string](#wide-char-string) -> utf8 en rust
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
In this situation, I have noticed that is way better to manually define the struct in your code instead of directly import it as it is from the official crates, which will allow you to replace the one element array with a dynamic size vector:
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
Obviously, this very last option is only good when you need to directly create a pointer to the struct. In any other case, it is better to use the other two alternatives.

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

## Function signatures
If you are using DInvoke to make WinAPI calls, you will need to define the signature for every function that you are dynamically calling. This is something similar to what is done in C#, where in order to create a Delegate you first need to know the input and output parameters of the function located at certain memory address.
Defining a WinAPI function signature is very easy:
* If this call is contained in what we know as Win32 (documented Windows API), then look for the signature in the crate [windows](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html).
* If the call belongs to the undocumented part of the WinAPI, get the signature from the crate [ntapi](https://docs.rs/ntapi/latest/ntapi/).
* If it is not defined in any of those crates, you will need to manually create the signature. Take a look at the existing examples in DInvoke in order to success in this task.

Once you know which parameters are expected and returned, go to the `data` crate and just define the function as a new data type:
```rust
pub type SomeFunction = unsafe extern "system" fn (HANDLE, *mut PVOID, usize, *mut usize, u32, u32) -> i32; 
```
Very often you will find that some parameters are not directly defined:
```rust
pub unsafe extern "system" fn NtWriteVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    BufferSize: SIZE_T,
    NumberOfBytesWritten: PSIZE_T
) -> NTSTATUS
``` 

[Here](https://docs.rs/ntapi/latest/ntapi/ntmmapi/fn.NtWriteVirtualMemory.html) for example, the parameter BufferSize is defined as a `SIZE_T`. If you follow the link, you will see that the `SIZE_T` is defined this way:
```rust
type SIZE_T = ULONG_PTR;
```
And then, you need to follow another link to obtain the real basic type behind that parameter:
```rust
type ULONG_PTR = usize;
```
Here you have several options in order to add the signature for `NtWriteVirtualMemory`:
1) You can import the types defined in the crate `ntapi`, but you will add that dependency to your project.
2) You can manually define the `SIZE_T` data type. Very tedious if you have a huge amount of new data types.
3) **Or you can do what I usually do**. You can define the parameter BufferSize as a `usize`, and everything will work perfectly.

The same way, sometimes you will find that some parameters are defined as structs of a single field. For example, you could have certain WinAPI function that expects as an input parameter a struct defined this way:
```rust
#[repr(C)]
pub struct Struct {
    pub 0: i32
}
```
Here you have almost the same situation than before. If you want, you can import the struct from the corresponding crate, or you can define the struct manually, but for me the simplest way of doing this is to consider that the WinAPI function expects an `i32` direvtly, getting rid of the struct and making it easier to implement the code. 

I think that the only struct like this that I keep in my projects is [HANDLE](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Foundation/struct.HANDLE.html) (which has a single field, an isize), and I do so because it is a very commonly used struct and I feel like its presence makes the final code easier to read for other people. 

# Pointers
## Casting
Usually you will need to cast between different types of pointers. The most common case is when you have a struct pointer and you have to cast it to a PVOID pointer (which in Rust is defined as *mut c_void) before passing it to any WinAPI call.
When you are dealing with basic type pointers, you can cast between them using the keyword `as`: 
```rust
let a: *mut i32 = get_i32_mut();
let b: *mut u64 = a as *mut u64;
```
However, this only works when you are dealing with basic type pointers, and most of the time you will be dealing with WinAPI structs and types pointers. In this case, you can use the function `std::mem::transmute()`:
```rust
let a: *mut ComplexStruct = get_complexstruct_pointer();
let b: PVOID = std::mem::transmute(a);
```
You can also use the method `transmute()` to get a pointer to a struct or any other data type using the special character `&`:
```rust
let a: i32 = 238i32;
let b: PVOID = std::mem::transmute(&a);
let c: *mut PVOID = std::mem::transmute(&b);
```
```rust
let a: ComplexStruct = ComplexStruct::default();
let b: *mut ComplexStruct = std::mem::transmute(&a);
```
## Memory addresses
Since memory addresses have different size depending on the system architecture, the best way to deal with them is using the type `usize` or `isize`. These data types have a 4/8 bytes size depending on whether the operative system is x86 or x64, which makes them perfect for the task. Also, they will allow you to perform arithmetic operations over the memory address as we will see in the next section.

You can directly convert any pointer into an `usize` using the keyword `as`. Also, memory addresses can be printed using the hex format placeholder `{:x}`:
```rust
let handle: *mut HANDLE = get_pointer();
let handle_addr = handle as usize;
println!("The memory address that the variable handle is pointing to is {:x}", handle_addr);
```
You can also obtain the memory address of a function or a basic type variable this way:
```rust
fn main() 
{
    unsafe
    {
        let addr: usize = (main as *const()) as usize;
        println!("main() base memory address 0x{:x}", addr);
        let number = 15i32;
        let number_addr = (number as *const i32) as usize;
        println!("Memory address of the variable number: 0x{:x}", number_addr);
    }
}
```
To obtain the memory address of a varible that is not of a basic data type, you need to use once again the method `transmute`:
```rust
let handle: HANDLE = HANDLE::default();
let handle_addr: usize = std::mem::transmute(&handle);
println!("The memory address where the variable handle is located is 0x{:x}", handle_addr);
```
## Arithmetic operations
There are several ways to increment/decrement a pointer in Rust, and this is required in many situations that involve the WinAPI. To me, the best way to increment or decrement a pointer is by using the functions `add()` and `sub()`. These functions expect one single input parameter, which is the offset to calculate from the starting pointer. 

Take into account that the final offset is different depending on the type of the pointer. A `add(1)` will increment by 8 bits a `*mut i8`, by 32 bits a `*mut i32 and by `size_of::<T>()` a `*mut T` pointer.
```rust
let mut ptr: *mut u8 = get_pointer_to_buffer();
println!("{}", *ptr); // First u8 in the buffer
ptr = ptr.add(1); // Now ptr points to start_of_buffer + 8 cause u8 has a size of 8 bites;
println!("{}", *ptr); // Second u8 in the buffer
ptr = ptr.add(2); // ptr points to start_of_buffer + (8 * 3);
println!("{}", *ptr); // Fourth u8 in the buffer
```
You can also cast the pointer into a `usize`, then add or sub any desired offset (in bits):
```rust
let ptr: usize = get_pointer_to_buffer() as usize; // get_pointer_to_buffer() returns a basic type pointer, thats why it can be casted to usize without using transmute()
let ptr2: *mut u32 = (ptr + 2) as *mut u32;
println!("{}", *ptr2); // Here we would be printing the 32 bits unsigned number located at start_of_buffer + 2;
```
Just remember that the keyword `as` can only be used with basic type pointers; in any other case, use `transmute()`.

# Compile
## Reducing PE size
By default, rust compiler optimizes for execution speed, compilation speed and ease of debugging. This leads to bigger binaries size, which can be inappropiate for offensive tools.
There are several compiling options you can use to reduce the final binary size. For that, you just need to add the following to `Cargo.toml`:
```rust
[profile.release]
opt-level = 'z'     # Optimize for size
lto = true          # Enable link-time optimization
codegen-units = 1   # Reduce number of codegen units to increase optimizations
panic = 'abort'     # Abort on panic
strip = true        # Strip symbols from binary*
``` 
Then, all you have to do is to compile in release mode using `cargo build --release`. This info has been obtained from [this answer](https://stackoverflow.com/questions/29008127/why-are-rust-executables-so-huge) where you can also find additional tips on this topic.

Take into account that you might not want to use some of those flags in your project by default (for example, `panic = 'abort'` will reduce de binary size by removing unwind data, making it impossible to recover from an unexpected exception). In my experience, the safest flags that you can use without worrying are `opt-level = 'z'` and `strip = true`; for the others, make sure you test the resulting binary before using it on a production environment or a client.

## Compile to dll
Rust projects can be compiled to different artifacts: .lib, .exe, .dll, .so, etc. By default, your code will be compiled to .exe format, but I have found very useful to be able to compile my code into a native dll, as I would do from other languages like C or C++.

To do so, you have to add the following lines to `Cargo.toml`:
```rust
[lib]
crate-type = ["cdylib"]
```
Then, you just need to rename the default `main.rs` file to `lib.rs`. After that, simply compile your code as you would normally do to get a C style dll.

If you want that the final dll exports certain function of your code, you can do so by changing the function's signature like this:
```rust
#[no_mangle]
pub extern fn run()
{
    ...      
}
``` 
The final dll will export a function named `run` that can be called as usual (for example, with LoadLibrary + GetProcAddress or through DInvoke).

# Issues resolution
I wasn`t sure how to name this section, but here I will add both some extra tricks that do not have their own section and also troubleshooting tips.

You will see that I don't really know the origin/cause of some of the issues I will comment below, but at the end the important thing is to show you how you can solve them.
## default() and transmute()
Let's have a look at the following code:
```rust
let handle = GetCurrentProcess();
let base_address: *mut PVOID = std::mem::transmute(&usize::default());
let zero_bits = 0 as usize;
let size: *mut usize = std::mem::transmute(&dwsize);
let ret = dinvoke::nt_allocate_virtual_memory(handle, base_address, zero_bits, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```
Here I'm just calling NtAllocateVirtualMemory to allocate a certain amount of memory. Well, this code will work 99% of the times, but the remaining 1% will fail unexpectedly leading to every sort of unexpected behavior. 

Don't ask me why this happens because I don't know it, but this situation arises when you use the trait `default()` directly into the method `transmute()`. So the best way to remove that 1% chance of unexpected failure is to rewrite the previous code like this:
```rust
let handle = GetCurrentProcess();
let a = usize::default(); // This is the key line
let base_address: *mut PVOID = std::mem::transmute(&a);
let zero_bits = 0 as usize;
let size: *mut usize = std::mem::transmute(&dwsize);
let ret = dinvoke::nt_allocate_virtual_memory(handle, base_address, zero_bits, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```
Here you can see that first I store the output from the trait `default()` in a temporal variable `a`, and then I pass that variable's reference to the method `transmute()`. This code will never experience the same erratic behavior commented before, so I recommend you to always add that extra line to your code.
