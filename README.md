# ***Welcome to Mini_AV***



## Introduction

Welcome to Mini Anti-Virus project, this program is written in C/C++. <br>
MiniAV is a basic Windows-based antivirus implemented as a kernel driver and a user-mode application. <br>
It provides functionalities such as blacklisting and whitelisting processes, dumping process memory, and killing processes. <br>
The project showcases how to interact with kernel-level components from user-mode applications using IOCTL commands. <br><br>


**Warning**

The techniques demonstrated by this project are powerful and can be misused if applied maliciously. This tool is provided with the intention of advancing knowledge and should only be used in ethical hacking scenarios where explicit permission has been obtained. Misuse of this software can result in significant harm and legal consequences. By using this software, you agree to do so responsibly, ethically, and within legal boundaries.

<br><br>




## Service Control Manager (SCM):

Like any other service in Windows, the kernel drivers are managed like services using SCM. <br>

In order to work with services in Windows OS, to create a service and start, stop or delete it you need to get familiar a little bit with Service Control Manager(SCM). <br>

The Service Control Manager (SCM) is a special system process that manages all services on a Windows machine. It handles the following:

1. Starting and stopping services.
2. Sending control requests to services (pause, resume, stop).
3. Maintaining the status of each service.

The `sc` command-line tool is used to communicate with the SCM to install, start, stop, and delete services.

<br><br>




## Key Components

1. **Kernel Driver:** Implements the core antivirus functionalities at the kernel level.

2. **User-Mode Application:** Provides a command-line interface to interact with the kernel driver.

3. **Process Management:** Handles process creation notifications and enforces blacklisting and whitelisting rules.
   
4. **Memory Dumping and Process Termination:** Allows dumping of process memory and termination of processes.

<br><br>




## Features

1. **MiniAV:** it has a cpp file called [MiniAV.cpp](https://github.com/eliyaballout/Mini_AV/blob/main/MiniAV/MiniAV/MiniAV.cpp), Main kernel driver implementation.
   
2. **MiniAVconsole:** it has a cpp file called [MiniAVconsole.cpp](https://github.com/eliyaballout/Mini_AV/blob/main/MiniAVConsole/MiniAVConsole/MiniAVConsole.cpp), User-mode application to send commands to the kernel driver.

<br><br>




## Requirements, Installation & Usage

**I will explain here the requirements, installation and the usage of this Mini AV:** <br>

**Requirements:**
1. Ensure you have a C++ compiler, Windows SDK, and WDK (Windows Driver Kit) installed.

2. **Enable Test Mode on Windows:** <br>
    By default, Windows only allows loading of signed drivers to ensure the integrity and authenticity of the drivers being loaded. Enabling Test Mode bypasses this restriction, allowing you to test and debug your driver without needing a digital signature. <br>
    So before installing and running the MiniAV driver, you need to enable Test Mode on Windows. This allows you to load unsigned drivers, which is necessary for development and testing purposes.
    1. **Open Command Prompt(cmd) as Administrator**
   
    2. **Enable Test Mode:**
        ```
        bcdedit /set testsigning on
        ```

    3. **Restart Your Computer:** Restart your computer to apply the changes.
   
    4. **Verify Test Mode:** After restarting, you should see "Test Mode" displayed in the bottom-right corner of your desktop.

<br><br>


**Installation:**
1. Download and extract the [ZIP file](https://github.com/eliyaballout/Mini_AV/archive/refs/heads/main.zip).<br>
2. Navigate to **MiniAV --> x64 --> Debug**, you will find the `MiniAV.sys` file, this is a kernel driver that you need to install on your computer.
3. Navigate to **MiniAConsole --> x64 --> Debug**, you will find the `MiniAVConsole.exe` file, this is the executable file that you need to run in order to activate and run the AV.

<br><br>


**Usage:**

**Make sure you run the executable in cmd with administrator privileges (Run as Administrator)** <br>

**Creating or installing the kernel driver:**

```
sc create av type= kernel binPath= "C:\Path\To\MiniAV.sys"
```
where `"C:\Path\To\MiniAV.sys"` should be the full path of the kernel driver (which is located in **MiniAV --> x64 --> Debug**).

<br>


**Starting the driver:** <br>
```
sc start av
```
<br>


**Initializing antivirus:**
```
MiniAVconsole.exe -init
```
<br>


**Adding process to blacklist:** <br>

**MiniAV can support only one blacklisted process name, that means you can block only one process per run, for example: if you run the command for blocking notepad and then run the same command for blocking chrome, the notepad will be unblocked and only chrome will be blocked.**
```
MiniAVconsole.exe -blacklist <filename.exe>
```
where `<filename.exe>` should be the process you want to block (e.g. notepad.exe).
<br><br>


**Adding process to whitelist:** <br>

**MiniAV can support only one whitelisted process name (the same concept as the `blacklist` command).**
```
MiniAVconsole.exe -whitelist <filename.exe>
```
where `<filename.exe>` should be the process you want to whitelisted (e.g. chrome.exe).
<br><br>


**Dump process memory:**
```
MiniAVconsole.exe -dump <pid> -size <n> -file <dumpfile>
```
where `<pid>` should be the process ID that you want to dump its memory. <br>
`<n>` should be the number of the first n bytes that you want to dump. <br>
And `<dumpfile>` should be the full path of the output file that you want to save the memory to.
<br><br>


**Kill process:**
```
MiniAVconsole.exe -kill <pid>
```
where `<pid>` should be the process ID that you want to terminate.


<br><br>



**You also can stop and even delete the kernel driver:**

**Stop:**
```
sc stop av
```
<br>


**delete:**
**Make sure you have stopped the driver before deleting it.**
```
sc delete av
```
<br>



## Ethical Considerations

This tool is intended for educational use only to demonstrate techniques commonly used by antivirus systems. It should be used in a controlled environment, such as a penetration testing lab, where explicit permission has been granted. Always practice responsible disclosure and use ethical hacking principles.<br><br>




## Technologies Used
<img src="https://github.com/devicons/devicon/blob/master/icons/c/c-original.svg" title="c" alt="c" width="40" height="40"/>&nbsp;
<img src="https://github.com/devicons/devicon/blob/master/icons/cplusplus/cplusplus-original.svg" title="c++" alt="c++" width="40" height="40"/>&nbsp;
<br><br><br>




## Demonstration of the antivirus



<br>
