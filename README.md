# rust_tips_and_tricks
This repo is just a collection of Rust tips and tricks **useful to interact with the Windows API** and develop offensive security tools for that specific operative system.

**This is not a tutorial, the content in this repo won't teach you how to code in Rust.** The only goal of this repo is to share the knowledge that I have obtained during the last years implementing offensive tools in Rust, hoping that this tips and tricks help you to solve some of the annoying issues that I have found at the time of interacting with Windows API from this language. 
Also, below I add a snippet of how to start a new project of these characteristics using Dinvoke_rs, hoping that this will solve any pending doubts and will allow anyone to start using the project.

I don't consider myself an expert or guru in Rust, which means that they could be better ways of doing things as I show them here. However, I've found very useful to know all these techniques and I hope that they save you all the time that I had to invest in order to make my code work.

## Content

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
  - [Define target architecture](#define-target-architecture)
- [Issues resolution](#issues-resolution)
  - [transmute()](#transmute)
  - [VCRuntime](#vcruntime)
  - [Nightly](#nightly)
  - [ASM](#asm)
  - [Wide char strings](#wide-char-strings)
  - [Encrypt string literals](#encrypt-string-literals)
  - [Remove absolute paths](#remove-absolute-paths)
  - [Debug prints](#debug-prints)
- [Resources](#resources)
- [Contribution](#contribution)

# DInvoke_rs
To me, the most straighforward way to create a new offensive security tool in Rust that requires the interaction with the Windows API is to import the [Dinvoke_rs](https://github.com/Kudaes/DInvoke_rs/tree/main/dinvoke_rs) crate adding the following line to `cargo.toml`:

```rust
[dependencies]
dinvoke_rs = "*"
```

Dinvoke_rs offers three main functionalities:

* **DInvoke**: It allows to dynamically find and execute unmanaged code. This is perfect since it allows us to call any function of WinAPI without leaving any trace in the final PE IAT, increasing our OPSEC.
* **Manualmap**: Manually maps any PE as LoadLibrary (or the operative system) would do, both from disk and memory.
* **Overload**: It manually maps a PE in a file-backed memory section of the current process. This crate allows to perform both module and template stomping techniques.

Once we have imported the DInvoke_rs crate, we can start calling any WinApi function that we need. For that, it is required to follow these simple steps (the steps below show how to call **ntdll!NtAllocateVirtualMemory**):

1) Define the function's prototype (check the [Structs and Types](#function-signatures) section to know how to easily obtain these function signatures):
```rust
pub type NtWriteVirtualMemory = unsafe extern "system" fn (HANDLE, PVOID, PVOID, usize, *mut usize) -> i32;

```
In many cases, you will also need to [define the required structs and data types](#structs-and-types) used as input/output parameters.

2) Create a small wrapper that dynamically obtains the base address of `ntdll` and then calls the macro `dynamic_invoke!()`:
```rust
/// Dynamically calls NtAllocateVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_allocate_virtual_memory (handle: HANDLE, base_address: *mut PVOID, zero_bits: usize, size: *mut usize, allocation_type: u32, protection: u32) -> i32 {

    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: dinvoke_rs::data::NtAllocateVirtualMemory;
        let ntdll = dinvoke_rs::dinvoke::get_module_base_address("ntdll.dll");
        dinvoke_rs::dinvoke::dynamic_invoke!(ntdll,"NtAllocateVirtualMemory",func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }   
}
```

3) Define the required parameters and make the call:
```rust
...

let ba = usize::default();
let base_address: *mut PVOID = std::mem::transmute(&ba);
let zero_bits = 0 as usize;
let dwsize = 354 as usize; // Allocate as much memory as you need
let size: *mut usize = std::mem::transmute(&dwsize);
let handle = HANDLE {0 : -1}; // Current process
let ret = nt_allocate_virtual_memory(
          handle, 
          base_address, 
          zero_bits, 
          size, 
          MEM_COMMIT | MEM_RESERVE, 
          PAGE_READWRITE);

if ret == 0 {
    println!("Success!");
}
else {
    println!("rip");
}
``` 

You just need to repeat these steps for any other WinAPI call that you need to call. A considerable amount of wrappers are already defined in `DInvoke_rs::dinvoke` (and I keep adding new ones with each update), so before trying to define them in your code check if they exist already.

If you don't care about or do not need the advantages that DInvoke_rs offers, it may be better for you to directly import the crates [windows](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html) and/or [ntapi](https://docs.rs/ntapi/latest/ntapi/) instead of loosing your time defining types, structs and function signatures. These crates will act like some sort of "PInvoke" for both Win32 (windows) and NT API (ntapi), allowing you to directly call any WinAPI function at the expense of losing a little bit of stealth and OPSEC.

# Structs and Types
## Definition of structs
In many situations you will need to use several structs in order to interact with the WinAPI. The easiest way to use these structs is by import them directly from the official crates [windows](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html) and [ntapi](https://docs.rs/ntapi/latest/ntapi/). By doing so, you won't need to define them manually.

Although this is very convenient, I have noticed that not all the structs in those crates are well defined. The vast majority of cases where the struct definition is wrong is due to an incorrect number of fields which prevents to use the struct efficiently (you can't access directly to the fields you are interested on...), but in some cases even the size of the struct was wrong.

Either the struct is poorly defined or it is not defined at all, you can define your own structs very easily:

```rust
#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub number_of_handles: u32,
    pub handles: Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO>,
}
```
By default, you will need to add the `#[repr(C)]` attribute to keep the order of the fields, otherwise Rust may change that order randomly at compilation time. 

On the other hand, some structs have fields that are arrays of an undetermined size and those fields are commonly defined in Rust as an array of one single element. For example:
```rust
#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub NumberOfHandles: ULONG,
    pub Handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 1],
}
```
In this situation, I have noticed that is way better to manually define the struct in your code instead of directly import it as it is from the official crates, which will allow you to replace the one element array with a dynamic size `vector`:
```rust
#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub number_of_handles: u32,
    pub handles: Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO>,
}
```

Finally, I recommend to add the trait Default for any manually defined struct in case that you need to instantiate it somewhere else in your code. If the struct is solely composed of basic type fields, you will be able to automatically derive this trait by using the `#[derive(Copy, Clone, Default)]` attribute; otherwise, you will need to manually implement it:
```rust
// Example of how to automatically derive the trait Default
#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Debug, Eq)]
pub struct ApiSetNamespace {
    pub unused: [u8;12],
    pub count: i32, 
    pub entry_offset: i32,
}

// Example of how to manually implement the trait Default
#[repr(C)]
#[derive(Clone)]
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
The best way of intantiating a struct is to use the method `default()` in case that the trait is defined:
```rust
let handle: HANDLE = HANDLE::default();
```
Another two ways of instantiating a struct, specially if you are going to use it only as an ouput parameter (and therefore you just need to reserve the corresponding memory) are these two:
```rust
let create_info: PS_CREATE_INFO = std::mem::zeroed(); // Good if you can't use the method default
```
```rust
let unused: Vec<u8> = vec![0;size_of::<HANDLE>()];
let handle: *mut HANDLE = std::mem::transmute(unused.as_ptr());
```
Obviously, this very last option is only appropiate when you need to create a pointer to the struct. In any other case, it is better to use the other two alternatives.

## NTSTATUS
NTSTATUS is a struct heavily used in the NT API, and in Rust you can define it as a `i32`. There is not much mistery on this topic, just know that you can obtain the hex value of a NTSTATUS printing it like this:
```rust
let ret: i32 = dinvoke::nt_allocate_virtual_memory(
          handle, 
          base_address, 
          zero_bits, 
          size, 
          MEM_COMMIT | MEM_RESERVE, 
          PAGE_READWRITE);

println!("NTSTATUS returned by NtAllocateVirtualMemory: {:x}", ret);

```
Then you can search for this hex value in the [official documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) and get a little bit of info about why is your code failing (WARNING: You may end up loosing your mind after receiving the tenth "Invalid Parameter" NTSTATUS in a row).

## Function signatures
If you are using DInvoke to call WinAPI, you will need to define the signature for every function that you are dynamically calling. This is something similar to what is done in C#, where in order to create a Delegate you need to define the input and output parameters of the function.
Defining a WinAPI function's prototype is very easy:
* If this call is contained in what we know as Win32 (documented Windows API), then look for the signature in the crate [windows](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html).
* If the call belongs to the undocumented part of the WinAPI, get the signature from the crate [ntapi](https://docs.rs/ntapi/latest/ntapi/).
* If it is not defined in any of those crates, you will need to manually create the signature. Take a look at the existing examples in `DInvoke_rs::dinvok` in order to success in this task.

Once you know which parameters are expected and returned, just define the function's prototype as a new data type:
```rust
pub type NewWinApiFunction = unsafe extern "system" fn (HANDLE, *mut PVOID, usize, *mut usize, u32, u32) -> i32; 
```
Very often you will see that the type of some parameters are not directly defined:
```rust
pub unsafe extern "system" fn NtWriteVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    BufferSize: SIZE_T,
    NumberOfBytesWritten: PSIZE_T
) -> NTSTATUS
``` 

[Here](https://docs.rs/ntapi/latest/ntapi/ntmmapi/fn.NtWriteVirtualMemory.html) for example, the parameter BufferSize is defined as a `SIZE_T`. If you follow the link, you will see that the `SIZE_T` is defined this other way:
```rust
type SIZE_T = ULONG_PTR;
```
Then, you need to follow another link to obtain the real basic type behind that parameter:
```rust
type ULONG_PTR = usize;
```
Here you have several options in order to deal with this situation:
1) You can import the types required directly from the official crates, but you will add that dependencies to your project.
2) You can manually define the `SIZE_T` data type. Very tedious if you have a huge amount of new types.
3) **Or you can do what I usually do**. You can define the parameter BufferSize as a `usize` which is the underlaying basic type, and everything will work perfectly.

The same way, sometimes you will find that some parameters are defined as structs of one single field. For example, you could have certain WinAPI function that expects as an input parameter a struct defined this way:
```rust
#[repr(C)]
pub struct Struct {
    pub 0: i32
}
```
Here you have almost the same situation than before. If you want, you can import the struct from the corresponding crate, or you can define the struct manually in your code, but for me the simplest way of dealing with this is to consider that the WinAPI function expects a `i32` directly, getting rid of the struct and making it easier to implement the code. 

I think that the only struct like this that I keep in my projects is [HANDLE](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Foundation/struct.HANDLE.html) (which has a single field, an isize), and I do so because it is a very commonly used struct and I feel like its presence makes the final code easier to understand for other people. 

# Pointers
## Casting
Usually you will need to cast between different types of pointers when working with the WinAPI. The most common case is when you have a struct pointer and you have to cast it to a PVOID (which in Rust is defined as `*mut c_void`) before passing it to any WinAPI call.

When you are dealing with basic type pointers, you can cast between them using the keyword `as`: 
```rust
let a: *mut i32 = get_i32_mut();
let b: *mut u64 = a as *mut u64;
```
However, most of the time you will be dealing with WinAPI structs and pointers. In that case, you can use the function `std::mem::transmute()` or use once again the keyword `as`:
```rust
// Example 1
let a: *mut ComplexStruct = get_complexstruct_pointer();
let b: *mut HANDLE = std::mem::transmute(a);

// Example 2
let a: *mut ComplexStruct = get_complexstruct_pointer();
let b: *mut HANDLE = a as *mut HANDLE;

// Example 3
let a: *mut ComplexStruct = get_complexstruct_pointer();
let b: *mut HANDLE = a as *mut _;
```
You can also use `transmute()` to get a pointer to a struct or any other data type using the special character `&`:
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
Since memory addresses have different size depending on the system architecture, the best way to deal with them is using the type `usize` or `isize`. These data types have a 4/8 bytes size depending on whether the operative system is x86 or x64, which makes them perfect for the task. Also, they will allow you to perform arithmetic operations over any given memory address as we will see in the next section.

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
        println!("main()'s base address 0x{:x}", addr);
        let number = 15i32;
        let number_addr = (number as *const i32) as usize;
        println!("Memory address of the variable number: 0x{:x}", number_addr);
    }
}
```
To obtain the memory address of a varible that is not of a basic data type, you need to use once again the method `transmute` to cast it into a `usize`:
```rust
let handle: HANDLE = HANDLE::default();
let handle_addr: usize = std::mem::transmute(&handle);
println!("The memory address where the variable handle is located is 0x{:x}", handle_addr);
```
The last code can be simplified in case that you only want to print the memory address:
```rust
let handle: HANDLE = HANDLE::default();
println!("The memory address where the variable handle is located is 0x{:p}", &handle);
```
## Arithmetic operations
There are several ways to increment/decrement a pointer in Rust, and this is required in many situations that involve the WinAPI. To me, the best way to increment or decrement a pointer is by using the functions `add()` and `sub()`. These functions expect one single input parameter, which is the offset to calculate from the starting address. 

Take into account that the final offset is different depending on the type of the pointer. A `add(1)` will increment by 8 bits a `*mut i8`, by 32 bits a `*mut i32` and by `size_of::<T>()` a `*mut T` pointer.
```rust
let mut ptr: *mut u8 = get_pointer_to_buffer();
println!("{}", *ptr); // First u8 in the buffer
ptr = ptr.add(1); // Now ptr points to start_of_buffer + 8 cause u8 has a size of 8 bites;
println!("{}", *ptr); // Second u8 in the buffer
ptr = ptr.add(2); // ptr points to start_of_buffer + (8 * 3);
println!("{}", *ptr); // Fourth u8 in the buffer
```
You can also cast the pointer into a `usize` and then add or sub any desired offset (in bytes):
```rust
let ptr: usize = get_pointer_to_buffer() as usize;
let ptr2: *mut u32 = (ptr + 2) as *mut u32;
println!("{}", *ptr2); // Here we would be printing the 32 bits unsigned number located at address start_of_buffer + 2;
```

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

Take into account that you might not want to use some of those flags in your project by default (for example, `panic = 'abort'` will reduce de binary size by removing unwinding data, making it impossible to recover from an unexpected exception). In my experience, the only flag that you can use without worrying at all is `strip = true`; for the others, make sure you test the resulting binary before using it on a production environment or a client. 

## Compile to dll
Rust projects can be compiled to different artifacts: .lib, .exe, .dll, .so, etc. By default, in Windows your code will be compiled to .exe format, but I have found very useful to be able to compile my code into a native dll as I would do from other languages like C or C++.

To do so, you have to add the following lines to `Cargo.toml`:
```rust
[lib]
crate-type = ["cdylib"]
```
Then, you just need to rename the default `main.rs` file to `lib.rs`. After that, simply compile your code as you would normally do to get a C style dll.

These two steps won't be required if at the time of creating the project with cargo, you specify the tag `--lib` (you would be creating a library), although that would make it harder to debug your code and I do not recommend it at first.

If you want that the final dll exports a certain function of your code, you can do so by changing the function's signature like this:
```rust
#[no_mangle]
pub extern fn run()
{
    ...      
}
``` 
The final dll will export a function named `run` that can be called as usual (for example, with LoadLibrary + GetProcAddress or through DInvoke).

## Define target architecture
If you want to compile to a different system architecture (for example, compile a 32 bits binary from x64 machine) you can create a `.cargo` folder in the root of your project, and place a `config` file inside of it. In this config file you can define the toolchain that you want to use:
```rust
[build]
target = "x86_64-pc-windows-msvc" 
```
By default, the two toolchains (from the stable channel) that I normally use are:
* `x86_64-pc-windows-msvc` to target a x64 architecture.
* `i686-pc-windows-msvc` to create a 32 bits binary.

You can list the toolchains installed on your system with the command `rustup toolchain list`. You can install any additional toolchain with `rustup install <toolchain>`.

# Issues resolution
I wasn't sure how to name this section, but here I will add both some extra tricks that do not have their own section and also troubleshooting tips.

You will see that I don't really know the origin/cause of some of the issues I will comment below, but at the end the important thing is to show you how you can solve them.
## transmute
Let's have a look at the following code:
```rust
let handle = HANDLE(-1);
let base_address: *mut PVOID = std::mem::transmute(&usize::default());
let zero_bits = 0 as usize;
let size: *mut usize = std::mem::transmute(&dwsize);
let ret = dinvoke_rs::dinvoke::nt_allocate_virtual_memory(handle, base_address, zero_bits, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```
Here I'm just calling NtAllocateVirtualMemory to allocate a certain amount of memory. Well, this code will work 99% of the times, but the remaining 1% will fail "for no reason" leading to all sort of unexpected behavior. 

Don't ask me why it happens because I don't really know, but this situation arises when you pass the output of the method `default()` as a reference directly into the method `transmute()`. So the best way to remove that 1% chance of unexpected failure is to rewrite the previous code like this:
```rust
let handle = HANDLE(-1);
let a = usize::default(); // This is the key line
let base_address: *mut PVOID = std::mem::transmute(&a);
let zero_bits = 0 as usize;
let size: *mut usize = std::mem::transmute(&dwsize);
let ret = dinvoke::nt_allocate_virtual_memory(handle, base_address, zero_bits, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```
Here you can see that first I store the output from the trait `default()` in a temporary variable `a`, and then I pass that variable's reference to the method `transmute()` in order to get a `PVOID`. This code will never experience the same erratic behavior commented before, so I recommend you to always add that extra line to your code.

## VCRuntime
Many times you will receive the error message "The code execution cannot proceed because VCRUNTIME140.dll was not found" at the time of running your binaries on remote machines.

To fix this, you need to statically link that dll. First, add the following line to `Cargo.toml`:
```rust
[build-dependencies]
static_vcruntime = "2.0"
```
Then, add a file named `build.rs` at the root of your project with this content:
```rust
 fn main() {
    static_vcruntime::metabuild();
}
```
Then recompile and the issue will be gone. **This method only seems to be working to compile dlls**. 

Another way to accomplish the same goal is to create a `.cargo` folder in the root of the project, and place a `config` file inside of it with the following content. This second method is recommended if you are compiling your project into a `.exe`:
```rust
rustflags = ["-C", "target-feature=+crt-static"]
```

## Nightly
Some experimental features are only available using the nightly channel. For example, in [Unwinder](https://github.com/Kudaes/Unwinder) I used the intrinsic `llvm.addressofreturnaddress` in order to get the memory address where the next return address was located in the stack. This intrinsic was only available in the nightly channel, but it was pretty useful and made my life way easier.

If you want to use some cool feature only available in nightly, you just need to install the corresponding toolchain:
```
rustup install nightly
```
Once you have the toolchain installed, you can set it up for a specific project (you could also set it up globally, but I do not recommend it):
```
cd ~/yourproject/
rustup override add nightly
```
This way, you will be able to use any nightly feature on that specific project. 

## ASM
Rust allows to insert assembly code in your projects as well. To do so, I use the crate `cc-rs`. To use this crate, first add the dependency in `Cargo.toml`:
```rust
[build-dependencies]
cc = "*"
```
Next, you have to create a `build.rs` file in the root of the project where you will indicate the .asm files that you want to compile together with the Rust code:
```rust
fn main()
{
    // Use the `cc` crate to build a C file and statically link it.
    cc::Build::new()
        .file("src/stub.asm")
        .compile("stub");
}
```
Now, you can create a `src::stub.asm` file and insert any desired code on it:
```asm
.code

     FancyFunction PROC FRAME
        push rbp
        .pushreg rbp
        mov rbp, rsp
        .setframe rbp, 0 
        .endprolog

        ...

        mov rsp, rbp
        pop rbp
        ret
    FancyFunction ENDP

end
```
Finally, you can call from Rust any of the functions defined in the .asm file by adding the corresponding `extern` signatures:
```rust
extern "C"
{
    fn FancyFunction(address: *const c_void, size: usize, protection: u32, old: *mut u32, virtual_protect: *mut c_void) -> bool;
}

...

pub fn main()
{
  let ret = FancyFunction(param1, param2...);
  if ret == true
  {
    println!("Alright!");
  }
}
```

## Wide char strings
In rust, strings (both `&str` and `String`) are utf8 encoded. However, in the Windows API are widely used the so called wide char strings, which are utf16 encoded (2 bytes for each char). This kind of strings can be found, for instance, in the well know `UNICODE_STRING` struct.

So, you can convert any Rust string to an utf16 encoded string this way:
```rust
let mut module_path_utf16: Vec<u16> = "any text".encode_utf16().collect();
module_path_utf16.push(0);
``` 
Okay, I know what you are going to say: this is not a `String`, it is a `Vector`. But at the end it's almost the same, just a memory buffer with some random content which now will be utf16 encoded. And from this, you can easily obtain a `UNICODE_STRING` which is probably what you are trying to achieve at this point:
```rust
let unicode = UNICODE_STRING::default();
let object_name: *mut UNICODE_STRING = std::mem::transmute(&unicode);
dinvoke::rtl_init_unicode_string(object_name, module_path_utf16.as_ptr());
let unicode_object = *object_name; // Completely unnecessary
``` 
## Encrypt string literals
Good OPSEC demands string literals encryption to avoid giving away certain information that can be used to detect the malicious behaviour of your payload.

I personally like to use the crate [litcrypt2](https://github.com/Kudaes/litcrypt.rs) to hide the strings literals of my code, specially when I am using DInvoke_rs. I find it very easy to use and it seems very reliable, never had any issue using it.

If you want to do the same, just add the dependency in `Cargo.toml`:
```rust
[dependencies]
litcrypt2 = "0.1.0"
```
Then you just need to initialize the macro by adding this code in your crate:
```rust
#[macro_use]
extern crate litcrypt2;
use_litcrypt!();
```
From there, you can call the macro `lc!()` which will encrypt your string literals at compilation time and will unencrypt them at runtime:
```rust
/// Dynamically calls NtWriteVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_write_virtual_memory (handle: HANDLE, base_address: PVOID, buffer: PVOID, size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtWriteVirtualMemory;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        // What would be the point of using DInvoke if I publish all the WinAPI functions that I am using
        // through the string literals on my code? :) 
        dynamic_invoke!(ntdll,&lc!("NtWriteVirtualMemory"),func_ptr,ret,handle,base_address,buffer,size,bytes_written);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }

}
```
This is just an example, but you can use it almost everywhere you have a sensitive string literal.

By default, `litcrypt2` will randomly generate an encryption key during compilation. In case that you want to use a specific value as your encryption key, remember to set the environment variable LITCRYPT_ENCRYPT_KEY before compiling your code:
```
 set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"
 ```
## Remove absolute paths
Most of the times, rust binaries will contain undesired absolute paths on them as a result of the compilation process. These strings could potentially leak the OS username that was used to compile the project, which may impact on your operation's OPSEC.
The best way to remove these absolute paths is by using the compilation flag `--remap-path-prefix`. You can pass this flag directly to rustc or, as I prefer, add it to the `.cargo\config` file of your project and compile as usual using `cargo build --release`. 
```rust
[build]
rustflags = ["--remap-path-prefix", "C:\\Users\\YourUser="] # This will remove any occurrence of C:\Users\YourUser in the resulting binary.
```
The only absolute path not affected by this flag is the .pdb path. To remove this whole string, remember to add the following line to your `cargo.toml` file:
```rust
[profile.release]
strip = true 
...
```
## Debug prints
For those situations where stdout/stderr do not work but you still want to print message to debug your code (e.g. you are implementing a COM object or a DLL that will be loaded by a service) it may be useful to use the crate [windebug_logger](https://docs.rs/windebug_logger/latest/windebug_logger/). With this crate, you can "redirect all messages to OutputDebugStringW", allowing you to retrieve them using [dbgview](https://learn.microsoft.com/es-es/sysinternals/downloads/debugview) or any other alike tool.

To use this crate, your first need to call the function `init`. This function should be called **only once** during the process lifespan, so make sure to implement some sort of control mechanism to prevent successive calls:
```rust
if CONTROL == 0 // Not safe for multithreaded executions
{
  CONTROL = 1;
  let _ = windebug_logger::init();
}
```
Once the logger has been initializated, the `debug!()` macro can be called to generate debug prints that can be retrieved with dbgview:
```rust
windebug_logger::log::debug!("This print can be retrieved with dbgview!");
```

# Resources
* [windows](https://microsoft.github.io/windows-docs-rs/doc/windows/index.html) and [ntapi](https://docs.rs/ntapi/latest/ntapi/index.html) crates.
* [At the end of this post](https://sebnilsson.com/blog/from-csharp-to-rust-code-basics/) you can find a primitives comparison between C# and Rust data types, very useful to carry out a port of code between the two languages.
* Rust also has [macros](https://doc.rust-lang.org/1.30.0/book/first-edition/macros.html) that are a very powerful feature for offensive tools development.
* Check out [this post](https://kerkour.com/rust-position-independent-shellcode) if you want to create PIC shellcode.
* Again, [a very interesting discussion](https://stackoverflow.com/questions/29008127/why-are-rust-executables-so-huge) about Rust executable's size and how to minimize them.
* [More](https://github.com/johnthagen/min-sized-rust) about minimizing Rust binaries.
* A little bit of extra info about [nightly channel](https://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/second-edition/ch01-03-how-rust-is-made-and-nightly-rust.html).

# Contribution
I will try to keep this repo updated and add other valuable tips and tricks in the near future. Feel free to make a pull request if you think you have some interesting tips to share with the community, but keep in mind that your contribution should be Windows related and that this repo is more like a cheatsheet and not a Rust tutorial.  
