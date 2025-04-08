# Fearsome
Bleeding Edge Runtime Ransomware Detection &amp; Termination Tool Without Relying on Signatures

**Still Work In Progress Project**

*Please report any bugs you found*

**How It Works**

First of all, Fearsome has three parts to work on.
Those are basically...

**The DLL Injector!**
  - Custom DLL Injector will inject a user-mode Fearsome dll to each process, and then monitor for new processes at real-time.

**Obviously, Custom DLL!**
  - Fearsome user-mode DLL hooks NtWriteFile function and keeps track of opened files. If any unusual activity is detected, write a log file and terminate it!

**Last but not least, InitFearsome**

  - While developing this application, I wanted it to be portable and more easier to use. (I'm kinda lazy actually... why should I right-click and run as Administrator twice for both x64 and x86 builds while I can use a single executable to lunch both?)  
  Well, InitFearsome literally starts both architecture versions of the Fearsome DLL Injector.
   
  

Now we talked about the basics, let's dive into more technical details!  
The core of the Fearsome is user-mode dll, which determines if the process is malicious or not.  
But it's not a magic and not bullet-proof, still Advanced Persistent Threat actors can be able to adjust their code to bypass Fearsome's mechanic.  
The problem is, in order to evade from Fearsome, you have to make ransomware way more slower. So ransomware must sacrifice from it's speed.  
And also there is a second bypass method, which is directly calling syscall or checking and patching first byte of the hooked function. Example: (if JMP is in the first line of the NtWriteFile, call patch();)

More detailed information about the second bypass method:

https://malwaretech.com/2023/12/an-introduction-to-bypassing-user-mode-edr-hooks.html

https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs


Fearsome is a hobby project I begin to code after thinking about if it's possible to end almost each ransomware...


# Pwned Ransomwares
  
  Well, I'm really proud about the performance of this application!  
  It literally blocks almost every ransomware sample I've tried on MalwareBazaar and VX-Underground!
  
  It destroys most common and powerful ransomwares such as **LockBit**, **Akira**, **Conti**, **Sodinokibi**, **BlackByte** and so on... without any signature detection!  
  So Fearsome combats-back when EDR / AV solution is not enough to detect newly and specially crafted ransomwares which targets enterprise.  
  Detection is not only limited with new ransomwares, but classic old ones such as **WannaCry** and so on!  

  In the source-code, I'll provide a zip file with the *infected* as password.  
  Inside this zip file, there will be some ransomwares I've tried and be successful (also there is one ransomware sample where Fearsome unable to detect and neutralize).

# Limitations

  It's important to change DLL Injector's process name (don't forget to modify InitFearsome to lunch brand-new named DLL Injector) so Threat-Actor will not kill the process and stop dll injection.  
  Or you can adjust some code to set this process critical, so it'll BSOD whenever Threat-Actor tries to terminate DLL Injector process.  
  But still it may possible to inject dll and break how DLL Injector works, so making it Protected Process Light does the trick!  
  Also there may be few ransomwares which fix NtWriteFile and bypass the hooked function, so it's best to use Fearsome with already existing EDR / AV solution.  

  Since me, the single developer of Fearsome is a student and has limited time, this project may get updates slower (or not at all actually... But I'll try to help community!).  
  It's kinda hard to maintain it, I can't focus and code the entire day anymore... Yeah, I made most code of Fearsome in 3 days non-break coding session (literally sleeping and coding).

  _________________________________________________________
  
  W.I.P. / Still writing the README.md || Please Check Later
