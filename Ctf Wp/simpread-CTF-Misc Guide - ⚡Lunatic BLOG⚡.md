> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [goodlunatic.github.io](https://goodlunatic.github.io/posts/1ad9200/#python%E4%B8%ADstr%E7%B1%BB%E5%9E%8B%E5%92%8Cbyte%E7%B1%BB%E5%9E%8B)

This is a simple Guide for CTF in Misc Area.

**This is a simple Guide for CTF in Misc Area.**

Misc Guide

**最开始接触 CTF 时，学的最多的就是 Misc，各种编码各种加密还有各种软件的使用…**

**但无奈 MIsc 涉及的范围实在太广了，于是就萌生了一边学习一边记录的想法，甚至还想为此写一本指南。**

[](#%e4%b8%80%e4%ba%9b%e5%a5%87%e5%a5%87%e6%80%aa%e6%80%aa%e7%9a%84%e7%bb%8f%e5%8e%86)一些奇奇怪怪的经历：
------------------------------------------------------------------------------------------------

1、一段字符串，用 base64 异或脚本跑，找正常的字符串

2、rockstar 编程语言，在 github 上面可以找到，然后在本地用 pip 安装库，把 rock 文件转换为 py 文件，运行即可得到 flag

3、给你一个. exe 安装包文件，flag 藏在安装之前的一大串协议中

4、实在做不出来的时候，可以把 flag 的格式转其他的编码和题目中的信息比对找规律

5、给你一个 gpx 文件，在线网站 https://www.gpsvisualizer.com/map_input 解密，然后地名的首字母连起来就是 flag

[](#ctf%e4%b8%ad%e7%9a%84%e5%b8%b8%e7%94%a8%e5%85%b3%e9%94%ae%e8%af%8d)CTF 中的常用关键词
----------------------------------------------------------------------------------

```
# 要搜索的字符列表
search_terms = [
    "key", "password", "dasctf", "k3y", "p@ssword", "passw0rd",
    "p@ssw0rd", "secret", "s3cret", "s3cr3t", "s3cre4","F14ggg"
    # 遇到⼀个加⼀个，CTFer的好习惯
]
```

```
# 各种常用关键字的bash64编码
flag                          Zmxh
F14g                          RjE0
DASCTF                        REFTQ1RGe
s3cr3t                        czNjcjN0
secret                        c2VjcmV0
password                      cGFzc3dvc
PNG文件头                      iVBORw0KGgo
ZIP文件头                      UEsDBA
```

[](#%e5%90%84%e7%a7%8d%e5%8a%a0%e5%af%86%e7%bc%96%e7%a0%81)各种加密 / 编码：
---------------------------------------------------------------------

### [](#base%e5%ae%b6%e6%97%8f)base 家族

详细请看：https://www.cnblogs.com/0yst3r-2046/p/11962942.html

```
1、base16                       flag         666C6167
2、base32[A-Z2-7]               flag         MZWGCZY=
3、base36                       flag         727432
4、base58                       flag         3cr9Ae
5、base64                       flag         Zmxh
6、base85                       flag         Ao(mg
7、base91                       flag         @iH<Z
8、base92                       flag         F#S<I
9、base100                      flag         👝👣👘👞
10、base1024                    flag
11、base2048                    flag         ڥڊװ
12、base65535                   flag         ꍦ鱡
```

base64 还可以换表 (表中的字符要求不重复) 编码，例如

```
sQ+3ja02RchXLUFmNSZoYPlr8e/HVqxwfWtd7pnTADK15Evi9kGOMgbuIzyB64CJ
SjaoNgS0xgagUTpwe3QwHn4MrbkD/OUwqOQG/bpveg6Mqa4WH0k46
第一行是表，第二行是编码后的密文
cyberchef解密即可得到flag
```

Tips：base64 可以与其他文件格式互相转换（比如图片 [会有很多行的 base64]），使用在线网站或者随波逐流转换即可 如果出现了很多层乱七八糟的 base 编码，连 CyberChef 都识别不出来的话，可以试试用 BaseCrack 这个开源工具 输入 python basecrack.py -m 运行即可

![](https://goodlunatic.github.io/posts/1ad9200/imgs/basecrack.png)

### [](#md5%e5%8a%a0%e5%af%86)MD5 加密

```
明文：admin
32位小写21232f297a57a5a743894a0e4a801fc3 
32位大写21232F297A57A5A743894A0E4A801FC3 
16位小写7a57a5a743894a0e 
16位大写7A57A5A743894A0E 
Tips：十六位其实就是取32位的8-24位
```

MD5 加密后的密文应该是 纯数字 + 纯字符

有些 MD5 的 HASH 值可以直接在 somd5 或者 cmd5 上查

### [](#python%e4%b8%adstr%e7%b1%bb%e5%9e%8b%e5%92%8cbyte%e7%b1%bb%e5%9e%8b)python 中 str 类型和 byte 类型：

```
\>>> a = '寒鸦小站'
\>>> type(a)
<class 'str'>
\>>> b = a.encode()
\>>> b
b'\xe5\xaf\x92\xe9\xb8\xa6\xe5\xb0\x8f\xe7\xab\x99'
\>>> type(b)
<class 'bytes'>
```

### [](#emoji-aes%e7%bc%96%e7%a0%81)emoji-aes 编码：

密文由一大串 emoji 表情组成，解密需要密钥，例如

已知 key：th1sisKey，直接使用在线网站解密即可，在线网站源码也可以下载到本地

```
🙃💵🌿🎤🚪🌏🐎🥋🚫😆😍🔬👣🖐🌏😇🥋😇😊🍎🏹👌🌊☃🦓🌏🐅🥋🚨📮🐍🎈📮📂✅🐍⏩⌨🎈😍🌊😇🐍☺💧🥋🍌🎤🍍😇👁🦓😇🍍📮📂🎅😡🍵✖✉🏹⌨🍵🎤😆🍵🚹🏹🍎🚨ℹ☃👑🎤🚪💵😎😀😎🔬💵🦓🏹👉🦓✖😀🐘🔪⌨🎈🥋👌🍌🚹😂✉🍎🍌🏎👌🏹💵👌👁🎃🗒
```

[https://aghorler.github.io/emoji-aes/](https://aghorler.github.io/emoji-aes/)

### [](#%e8%af%8d%e9%a2%91%e5%88%86%e6%9e%90)词频分析：

一堆文字，看着什么编码都不像的，可能是词频分析，用在线网站跑 https://quipqiup.com/

### [](#%e5%ad%97%e9%a2%91%e5%88%86%e6%9e%90)字频分析：

用随波逐流直接分析

### [](#%e6%91%a9%e6%96%af%e7%94%b5%e7%a0%81)摩斯电码：

```
#第二种情况，加入/或者空格来替换换行符
.--/./.-../-.-./---/--/./-/---/-./-.-/-.-./-/..-./--..--/-/...././.--./.-/.../.../.--/---/.-./-../../.../.----/-..../-.../-.--/-/./.../.-./.-/-./-../---/--/.-../-.--/--././-././.-./.-/-/./-../--..-
```

### [](#vigenere%e7%bb%b4%e5%90%89%e5%b0%bc%e4%ba%9a%e5%af%86%e7%a0%81)vigenere(维吉尼亚) 密码：

1. 给了密文和 Key

直接拉到 cyberchef 中解密即可

2. 给了密文，没给密钥，但是知道目标明文的格式

先用 B 神的脚本爆破出 Key，然后再把这个 Key 放到 cyberchef 中解密

3. 根据对照表，手搓密钥的前几位

![](https://goodlunatic.github.io/posts/1ad9200/imgs/vigenere.png)

### [](#%e5%b8%8c%e5%b0%94%e5%af%86%e7%a0%81)希尔密码：

解密网站: http://www.metools.info/code/hillcipher243.html

已知密文和密钥，并且密钥 (key) 是一个网址，如 http://www.verymuch.net

已知密文和密钥，并且密钥是四个数字

```
密文：ymyvzjtxswwktetpyvpfmvcdgywktetpyvpfuedfnzdjsiujvpwktetpyvnzdjpfkjssvacdgywktetpyvnzdjqtincduedfpfkjssne
密钥：3 4 19 11
```

### [](#rabbi%e5%af%86%e7%a0%81)Rabbi 密码：

已知密文和密钥，密文有点像 base64 编码的 (可能有 + 号)

### [](#%e4%ba%91%e9%9a%90%e5%af%86%e7%a0%81)云隐密码：

特征是：密文只由 01248 组成

用随波逐流或者 CTFD 中的脚本直接跑

### [](#%e6%9b%bc%e5%bd%bb%e6%96%af%e7%89%b9%e4%b8%8e%e5%b7%ae%e5%88%86%e6%9b%bc%e5%bd%bb%e6%96%af%e7%89%b9%e7%bc%96%e7%a0%81)曼彻斯特与差分曼彻斯特编码:

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240529203318823.png)

> 1.  曼彻斯特码：从高到低表示 1，从低到高表示 0
> 2.  差分曼彻斯特码：在每个时钟周期的起始处（虚线处）有跳变表示 0；无跳变则表示 1。

可以直接使用 曼彻斯特编码 转换工具转换

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240529203746999.png)

例题 1 2016CISCN - 传感器 1

> 5555555595555A65556AA696AA6666666955
> 
> 这是某压力传感器无线数据包解调后但未解码的报文 (hex)
> 
> 已知其 ID 为 0xFED31F，请继续将报文完整解码，提交 hex。
> 
> 提示 1：曼联

```
enc = "5555555595555A65556AA696AA6666666955"
res = ''
flag = ''
flag_final = ''
for item in enc:
    # tmp = bin(int(item, 16))[2:].rjust(4, '0')
    # print(tmp, end=' ')
    res += str(bin(int(item, 16))[2:].rjust(4, '0'))
# print(res)
for i in range(0, len(res), 2):
    if res[i:i+2] == '01':
        flag += '1'
    elif res[i:i+2] == '10':
        flag += '0'
# print(flag)
# 这里需要每8位进行一次反转，要不然无法得到校验ID:0xFED31F
for i in range(0, len(flag), 8):
    flag_final += hex(int(flag[i:i+8][::-1], 2))[2:]

print(flag_final.upper())
# FFFFFED31F645055F9
```

例题 2 2016CISCN - 传感器 2

> 现有某 ID 为 0xFED31F 的压力传感器，已知测得  
> 压力为 45psi 时的未解码报文为：5555555595555A65556A5A96AA666666A955  
> 压力为 30psi 时的未解码报文为：5555555595555A65556A9AA6AA6666665665  
> 请给出 ID 为 0xFEB757 的传感器在压力为 25psi 时的解码后报文

和上面那题的思路一样，就是最后多了一步压力位算法和校验位算法猜测

压力位算法：压力每增加 5psi 压力值增加 11

校验位算法：校验值为从 ID 开始每字节相加的和模 256 的十六进制值即为校验值

例题 3 2017CISCN - 传感器 1

> 已知 ID 为 0x8893CA58 的温度传感器的未解码报文为：3EAAAAA56A69AA55A95995A569AA95565556  
> 此时有另一个相同型号的传感器，其未解码报文为：3EAAAAA56A69AA556A965A5999596AA95656  
> 请解出其 ID，提交 flag{不含 0x 的 hex 值}

开头的 3E 提示了差分曼彻斯特编码，就是根据上图中的跳变位置解码

```
# enc = "3EAAAAA56A69AA55A95995A569AA95565556"
enc = "3EAAAAA56A69AA556A965A5999596AA95656"
res = ''
flag = ''
flag_final = ''
for item in enc:
    # tmp = bin(int(item, 16))[2:].rjust(4, '0')
    # print(tmp, end=' ')
    res += str(bin(int(item, 16))[2:].rjust(4, '0'))
print(res)
for i in range(8, len(res), 2):
    if res[i:i+2][0] != res[i-1]:
        flag += '0'
    else:
        flag += '1'
print(hex(int(flag, 2))[2:].upper())
# 24D8845ABF34119
# 8845ABF3
```

例题 4 2017CISCN - 传感器 2

> 已知 ID 为 0x8893CA58 的温度传感器未解码报文为：3EAAAAA56A69AA55A95995A569AA95565556  
> 为伪造该类型传感器的报文 ID（其他报文内容不变），请给出 ID 为 0xDEADBEEF 的传感器 1 的报文校验位（解码后 hex）
> 
> 以及 ID 为 0xBAADA555 的传感器 2 的报文校验位（解码后 hex），并组合作为 flag 提交。  
> 例如，若传感器 1 的校验位为 0x123456，传感器 2 的校验位为 0xABCDEF，则 flag 为 flag{123456ABCDEF}。

解码步骤和上题一样，就是多考察了一个校验位算法（CRC8）

在最后的结果前面补一个 0，然后再计算 CRC8 即可

### [](#%e7%a4%be%e4%bc%9a%e4%b8%bb%e4%b9%89%e6%a0%b8%e5%bf%83%e4%bb%b7%e5%80%bc%e8%a7%82%e5%af%86%e7%a0%81)社会主义核心价值观密码：

解密网址：http://www.hiencode.com/cvencode.html

公正民主公正文明公正和谐：abc

### [](#outguess%e8%a7%a3%e5%af%86%e5%9b%be%e7%89%87)outguess 解密图片：

在 kali 中下载 outguess：outguess -k ‘abc’ -r mmm.jpg -t flag.txt

outguess -k ‘key’ -r 加密后的图片. jpg -t 明文. txt

### [](#%e7%9b%b2%e6%96%87)盲文：

使用 https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=mangwen 在线翻译

### [](#base64%e9%9a%90%e5%86%99)base64 隐写：

直接用 CTFD 中的脚本跑出答案就行

### [](#%e6%96%87%e6%9c%ac%e5%8a%a0%e5%af%86%e4%b8%ba%e9%9f%b3%e4%b9%90%e7%ac%a6%e5%8f%b7)文本加密为音乐符号：

Tips：这里要注意，加密的密文一定是以 = 结尾的，有时候需要自己把 = 加上

eg：♭♯♪‖¶♬♭♭♪♭‖‖♭♭♬‖♫♪‖♩♬‖♬♬♭♭♫‖♩♫‖♬♪♭♭♭‖¶∮‖‖‖‖♩♬‖♬♪‖♩♫♭♭♭♭♭§‖♩♩♭♭♫♭♭♭‖♬♭‖¶§♭♭♯‖♫∮‖♬¶‖¶∮‖♬♫‖♫♬‖♫♫§=

直接用在线网站解密：https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=yinyue

敲击码：

![](https://goodlunatic.github.io/posts/1ad9200/imgs/%E6%95%B2%E5%87%BB%E7%A0%81.jpeg)

….. ../… ./… ./… ../ 5,2 3,1 3,1 3,2 W L L M

### [](#polybius%e5%af%86%e7%a0%81%e8%af%a6%e8%a7%81ctfwiki)Polybius 密码 (详见 CTFwiki)

类似于 11，22，11，24 这样的

去逗号改成空格，拉入随波逐流直接解密

### [](#des%e5%8a%a0%e5%af%86%e7%ae%97%e6%b3%95)DES 加密算法

例子：

```
密文：AK5O3BaZi+p1ci0JxythDZWToTXkFj4dexQ3cOAmYfUwtUVyJahFOcNroC8nAsHyCnmiuOOpJYyOWBV5npW3pg==
密钥：hristina
```

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20241105212634286.png)

### [](#aes%e5%8a%a0%e5%af%86%e7%ae%97%e6%b3%95)AES 加密算法

在线网站解密：

1.  [https://tool.lmeee.com/jiami/aes](https://tool.lmeee.com/jiami/aes)
2.  [https://www.sojson.com/encrypt_aes.html](https://www.sojson.com/encrypt_aes.html)

#### [](#aes-ecb%e4%b8%8d%e9%9c%80%e8%a6%81iv)AES-ECB(不需要 IV)

CyberChef 解密 AES-ECB 时需要将 IV 设置为`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`

如果 `key` 不足 16 字节可以尝试在后面补 0

#### [](#aes-cbc%e9%9c%80%e8%a6%81%e5%a1%ab%e5%86%99iv)AES-CBC(需要填写 IV)

密钥不足 16 字节时需要 padding 补齐 16 字节

可以使用能自动补齐的在线网站解密 [https://www.sojson.com/encrypt_aes.html](https://www.sojson.com/encrypt_aes.html)

![](https://goodlunatic.github.io/posts/1ad9200/imgs/aes1.png)

可以将密文和 key 拉入`CaptfEncoder-win-x64-1.3.0`解密

![](https://goodlunatic.github.io/posts/1ad9200/imgs/aes2.png)

### [](#%e5%9f%83%e7%89%b9%e5%b7%b4%e4%bb%80%e7%a0%81atbash)埃特巴什码 (Atbash)

类似于：(+w)v&LdG_FhgKhdFfhgahJfKcgcKdc_eeIJ_gFN

拉入厨子直接解密

```
flag{ ==> Atbash加密 ==> UOZT{
```

### [](#dna%e7%bc%96%e7%a0%81)DNA 编码

1、使用 CTFD 中的 DNAcode 脚本解密

[https://github.com/omemishra/DNA-Genetic-Python-Scripts-CTF](https://github.com/omemishra/DNA-Genetic-Python-Scripts-CTF)

2、网上找的脚本（红明谷杯 2023——hacker）

```
table = 'ACGT'
dic = {'AAA': 'a', 'AAC': 'b', 'AAG': 'c',
       'AAT': 'd', 'ACA': 'e', 'ACC': 'f', 'ACG': 'g', 'ACT': 'h', 'AGA': 'i', 'AGC': 'j', 'AGG': 'k', 'AGT': 'l', 'ATA': 'm', 'ATC': 'n', 'ATG': 'o', 'ATT': 'p', 'CAA': 'q', 'CAC': 'r', 'CAG': 's', 'CAT': 't', 'CCA': 'u', 'CCC': 'v', 'CCG': 'w', 'CCT': 'x', 'CGA': 'y', 'CGC': 'z', 'CGG': 'A', 'CGT': 'B', 'CTA': 'C', 'CTC': 'D', 'CTG': 'E', 'CTT': 'F', 'GAA': 'G', 'GAC': 'H', 'GAG': 'I', 'GAT': 'J', 'GCA': 'K', 'GCC': 'L', 'GCG': 'M', 'GCT': 'N', 'GGA': 'O', 'GGC': 'P', 'GGG': 'Q', 'GGT': 'R', 'GTA': 'S', 'GTC': 'T', 'GTG': 'U', 'GTT': 'V', 'TAA': 'W', 'TAC': 'X', 'TAG': 'Y', 'TAT': 'Z', 'TCA': '1', 'TCC': '2', 'TCG': '3', 'TCT': '4', 'TGA': '5', 'TGC': '6', 'TGG': '7', 'TGT': '8', 'TTA': '9', 'TTC': '0', 'TTG': ' '}
cipher = 'TCATCAACAAAT'
plain = ''
for i in range(0, len(cipher), 3):
    plain += dic[cipher[i:i+3]]
print(plain)
```

### [](#text-encoding-brute-force)Text Encoding Brute Force

如果赛博厨子转完两次 Hex 后依然是乱码，可以用 Text Encoding Brute Force 爆破试试看

例子：红明谷杯 2023——阿尼亚

### [](#decabit%e7%bc%96%e7%a0%81)Decabit 编码

正常的 Decabit 编码 是十个字符一组的，如果不是十个一组，就很可能不是 Decabit 编码

+-+-++–+- ++—+-++- -+–++-++- +–++-++– –+++++— ++-++—+- +++-+-+— +-+-+—++ —+++-++- -+–++-++- -+–+++-+- -+–++-++- -+–++-++- ++-+-+-+– -+–+++-+- ++-++—+- -++++—+- -+–++-++- ++-+-+-+– +-+++—+- +++-++—- —+++-++- +-+-+—++ ++-+-+-+– +-+-+–++- ++–+–++- -++++—+- +—+++-+- ++-+-+-+– -++++—+- -+–+++-+- +–+-+-++- +++-+-+— +-+++—+- -+–+-+++- -+–++-++- —+++-++- ++++—-+- -++++—+- -+–+++-+- -+–++-++- —-+++++-

直接使用 [在线网站](https://www.dcode.fr/decabit-code) 解密即可

如果不是 Decabit 编码，可以试试看把 +- 分别用 01 替换 [2023 楚慧杯 - Easy_zip]

### [](#%e4%bb%bf%e5%b0%84%e5%af%86%e7%a0%81)仿射密码

有两个 key，key-a 为必须是 (1,3,5,7,9,11,15,17,19,21,23,25) 中的一个, key-b 是 0~25 的数字

可以使用在线网站 [CTF 在线工具 - 在线仿射密码加密 | 在线仿射密码解密 | 仿射密码算法 | Affine Cipher (hiencode.com)](http://www.hiencode.com/affine.html) 或者随波逐流解密

```
gezx{j13p5oznp_1t_z_900y_k3z771h_k001}
key-a=17	key-b=77
flag{w13e5hake_1s_a_900d_t3a771c_t001}
```

### [](#brainfuck%e7%bc%96%e7%a0%81)BrainFuck 编码

可以直接使用在线网站解码，但是 flag 可能会藏在内存中然后被删去导致无法输出 flag，因此可以用下面这个代码输出之前放在内存中的 flag

```
#define  _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
char s[30000]={0};
char code[2000];
int len = 0;
int stack[10000];
int stack_len=0;
int main()
{
    char c;
    int i=0,j,k,x=0;
    FILE* f;
    char* p=s+10000;
    f=fopen("./bf.txt","r");
    while(fread(&code[len],1,1,f)==1)
	{
        len++;
    }
    setbuf(stdout,NULL);
    while(i<len) {
        switch(code[i]) {
            case '+':
                (*p)++;
                break;
            case '-':
                (*p)--;
                break;
            case '>':
                p++;
                break;
            case '<':
                p--;
                break;
            case '.':
                putchar((int)(*p));
                break;
            case ',':
                *p=getchar();
                break;
            case '[':
                if(*p) {
                    stack[stack_len++]=i;
                } else {
                    for(k=i,j=0;k<len;k++) {
                        code[k]=='['&&j++;
                        code[k]==']'&&j--;
                        if(j==0)break;
                    }
                    if(j==0)
                        i=k;
                    else {
                        fprintf(stderr,"%s:%dn",__FILE__,__LINE__);
                        return 3;
                    }
                }
                break;
            case ']':
                i=stack[stack_len-- - 1]-1;
                break;
            default:
                break;
        }
        i++;
        x++;
    }
    for(int i = 0; i < stack_len; i++) {
		printf("%c", stack[i]);
	}
    printf("\n");
    for(int i = 0; i < 30000; i++) {
		printf("%c", s[i]);
	}
    return 0;
}
```

### [](#gronsfeld%e5%af%86%e7%a0%81)Gronsfeld 密码

```
# 解密脚本
from pycipher import Gronsfeld

cipher = 'TGLBOMSJNSRAJAZDEZXGHSJNZWHG'
key = [1,50,61,8,9,20,63,41]
secret = Gronsfeld(key).decipher(cipher)

print(secret)
```

### [](#uuencode%e7%bc%96%e7%a0%81)UUencode 编码

看起来有点像 base85，直接使用在线网站解密即可

```
=8S4U,3DR8SDY,C`S-F5F-C(S,S<R-C`Q9F8S87T`
# c55192c992036ef623372601ff3a}
```

### [](#aaencode%e7%bc%96%e7%a0%81)AAencode 编码

### [](#xxencode%e7%bc%96%e7%a0%81)XXencode 编码

随波逐流直接解密即可 [2023 浙江省赛决赛]

### [](#%e6%97%a0%e5%ad%97%e5%a4%a9%e4%b9%a6whitespace%e6%88%96%e8%80%85snow%e9%9a%90%e5%86%99)无字天书 (whitespace) 或者 snow 隐写

一个文件打开都是空白字符

可以使用在线网站解密：https://vii5ard.github.io/whitespace/ 复制进去直接 run 即可

snow 隐写，到 snowdos32 工具目录下运行 SNOW.EXE -C -p password flag.txt 命令即可

### [](#%e4%b8%ad%e6%96%87%e7%94%b5%e6%8a%a5%e4%b8%ad%e6%96%87%e7%94%b5%e7%a0%81)中文电报（中文电码）

类似于下面这种四位数一组的编码，直接在线网站解码即可

5337 5337 2448 2448 0001 2448 0001 2161 1721 1869 6671 0008 3296 4430 0001 3945 0260 3945 1869 4574 5337 0344 2448 0037 5337 5337 0260 0668 5337 6671 0008 3296 1869 6671 0008 3296 1869 2161 1721

### [](#quote-printable%e7%bc%96%e7%a0%81)Quote-Printable 编码

类似于下面这样的编码，直接使用 [在线网站](https://try8.cn/tool/code/qp) 解密即可

flag{ichunqiu_=E6=8A=80=E6=9C=AF=E6=9C=89=E6=B8=A9=E5=BA=A6}

flag{ichunqiu_技术有温度}

### [](#unicode%e7%bc%96%e7%a0%81)Unicode 编码

这个编码有很多种格式，比如`+U、\u、\x、&#`啥的

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20241101155218913.png)

可以使用这个在线网站解码：https://r12a.github.io/app-conversion/

### [](#%e4%b8%ad%e6%96%87ascii%e7%a0%81)中文 ascii 码

```
27880 30693 25915 21892 38450 23454 39564 23460 21457 36865 112 108 98 99 116 102 33719 21462 21069 27573 102 108 97 103 20851 27880 79 110 101 45 70 111 120 23433 20840 22242 38431 22238 22797 112 108 98 99 116 102 33719 21462 21518 27573 102 108 97 103
```

加上 &# 和分号，直接 CyberChef 或者 [在线网站](https://www.xuhuhu.com/beautify/ascii/) 解密即可

```
注知攻善防实验室发送plbctf获取前段flag关注One-Fox安全团队回复plbctf获取后段flag
```

### [](#%e5%9f%b9%e6%a0%b9%e5%af%86%e7%a0%81)培根密码

由 a、b 或者 A、B 或者 0、1 组成的密文，密文中只有两种字符，可以直接使用 随波逐流 解密

Tips：CyberChef 的培根密码解密可能会有点问题，这里建议用随波逐流解密

### [](#%e9%94%9f%e6%96%a4%e6%8b%b7)锟斤拷

这个东西的成因是 Unicode 的替换字符（Replacement Character，�）于 UTF-8 编码下的结果 EF BF BD 重复，在 GBK 编码中被解释为汉字 “锟斤拷”（EF BF BD EF BF BD）

```
import os

a = input('请选择你的功能（1、加密 2、解密）：')
if a == "1":
    s = input('请输入你要加密的话：')
    utf = s.encode('utf')
    gbk = s.encode('utf').decode('gbk', errors='ignore')
    if len(s)%2 == 1:
        gbk = gbk + "�"
    print(gbk)
    os.system("pause")
if a == "2":
    s = input('请输入你要解密的话：')
    gbk = s.encode('gbk')
    utf = s.encode('gbk').decode('utf-8', errors='ignore')
    print(utf)
    os.system("pause")
```

### [](#%e9%94%ae%e7%9b%98%e5%9d%90%e6%a0%87%e5%af%86%e7%a0%81)键盘坐标密码

```
1 2 3 4 5 6 7 8 9 0
1 Q W E R T Y U I O P
2 A S D F G H J K L
3 Z X C V B N M
```

例题 - i 春秋 - misc3

```
flag{11 21 31 18 27 33 34}
flag{QAZIJCV}
```

### [](#%e6%a3%8b%e7%9b%98%e5%af%86%e7%a0%81adfgvxadfgxpolybius)棋盘密码 ((ADFGVX,ADFGX,Polybius)

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20241018145022295.png)

直接使用 CaptfEncoder 或者随波逐流等工具输入密文和密钥解密即可 ![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20241018145101804.png)

ADFGVX 密码 默认棋盘：ph0qg64mea1yl2nofdxkr3cvs5zw7bj9uti8 默认密钥：german ADFGX 密码 默认棋盘：phqgmeaynofdxkrcvszwbutil 默认密钥：german 波利比奥斯方阵密码 密钥：随机 默认密文字符：ABCDE

### [](#%e7%a6%8f%e5%b0%94%e6%91%a9%e6%96%af%e5%af%86%e7%a0%81)福尔摩斯密码

```
·-· ·-· ·-· ·-· ·-· ·-· ·
```

直接网上查找福尔摩斯密码对照表即可 flag{RRRRRRE}

### [](#%e6%89%8b%e6%9c%ba%e4%b9%9d%e5%ae%ab%e6%a0%bc%e9%94%ae%e7%9b%98%e5%af%86%e7%a0%81)手机九宫格键盘密码

参考链接：[https://blog.csdn.net/qq_55011640/article/details/123626280](https://blog.csdn.net/qq_55011640/article/details/123626280)

下面举个栗子就理解了： 82  73  42  31  22  31  33  41  32 U   R   H   D  B   D   F   G   E

### [](#%e5%88%a9%e7%94%a8%e7%bc%96%e7%a8%8b%e4%bb%a3%e7%a0%81%e7%94%bb%e5%9b%be)利用编程代码画图

1.  LOGO 编程语言【例题 -[RCTF2019]draw 】 在线编译器：https://www.calormen.com/jslogo/
2.  CFRS 编程语言【例题 - 2024 宁波市赛初赛 Misc2】 在线画图网站：https://susam.net/cfrs.html

[](#%e5%90%84%e7%a7%8d%e6%96%87%e4%bb%b6%e5%a4%b4%e5%b0%be)各种文件头 / 尾：
---------------------------------------------------------------------

这里要注意，出题人可能会把文件头的小写字母偷偷改成大写，例如：Rar -> RAR

```
zip 文件头：50 4B 03 04 14 00 08 00
rar 文件头：52 61 72 21 (Rar!)               文件尾：C4 3D 7B 00 40 07 00
7z  文件头：37 7A BC AF 27 1C
png 文件头：89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52   文件尾：49 45 4E 44 AE 42 60 82
jpg 文件头：FF D8 FF E0 00 10 4A 46 49 46 00 01
gif 文件头：47 49 46 38 39 61（GIF89A）或 47 49 46 38 37 61（GIF87A）    文件尾：00 3B
wav 文件头：57415645
gz 文件头：1F 8B 08 00
pyc的文件头：03 F3 0D 0A
psd的文件头：38 42 50 53
TIFF (tif)，文件头：49492A00
Windows [Bitmap](https://so.csdn.net/so/search?q=Bitmap&spm=1001.2101.3001.7020) (bmp)，文件头：424D
CAD (dwg)，文件头：41433130
Adobe Photoshop (psd)，文件头：38425053
Rich Text Format (rtf)，文件头：7B5C727466
XML (xml)，文件头：3C3F786D6C
HTML (html)，文件头：68746D6C3E
Email [thorough only] (eml)，文件头：44656C69766572792D646174653A
Outlook Express (dbx)，文件头：CFAD12FEC5FD746F
Outlook (pst)，文件头：2142444E
MS Word/Excel (xls.or.doc)，文件头：D0CF11E0
MS Access (mdb)，文件头：5374616E64617264204A
WordPerfect (wpd)，文件头：FF575043
Postscript (eps.or.ps)，文件头：252150532D41646F6265
Adobe Acrobat (pdf)，文件头：255044462D312E
Quicken (qdf)，文件头：AC9EBD8F
Windows Password (pwl)，文件头：E3828596
AVI (avi)，文件头：41564920
Real Audio (ram)，文件头：2E7261FD
Real Media (rm)，文件头：2E524D46
MPEG (mpg)，文件头：000001BA
MPEG (mpg)，文件头：000001B3
Quicktime (mov)，文件头：6D6F6F76
Windows Media (asf)，文件头：3026B2758E66CF11
MIDI (mid)，文件头：4D546864
M4a，文件头：00000018667479704D3441
```

[](#misc%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)Misc——流量分析
-------------------------------------------------------

详见作者博客中的 **Network Traffic Analysis** 这篇文章

[](#misc%e5%9b%be%e7%89%87%e9%a2%98%e6%80%9d%e8%b7%af)MIsc——图片题思路：
------------------------------------------------------------------

Tips：各种隐写可以先拉入一键梭哈网站解析一下: https://aperisolve.fr/

### [](#%e9%80%9a%e7%94%a8%e6%80%9d%e8%b7%af)通用思路

#### [](#1%e6%9f%a5%e7%9c%8b%e5%9b%be%e7%89%87%e5%b1%9e%e6%80%a7%e7%9a%84%e8%af%a6%e7%bb%86%e4%bf%a1%e6%81%af%e5%8f%af%e8%83%bd%e5%85%b3%e9%94%ae%e4%bf%a1%e6%81%af%e5%b0%b1%e5%9c%a8%e9%87%8c%e9%9d%a2)1、查看图片属性的详细信息 (可能关键信息就在里面)

#### [](#2%e6%8b%89%e5%85%a5010%e6%9f%a5%e7%9c%8b%e6%96%87%e4%bb%b6%e5%a4%b4%e5%b0%be%e5%8f%af%e8%83%bd%e4%bc%9a%e6%9c%89%e4%b8%8d%e5%90%8c%e7%b1%bb%e5%9e%8b%e6%96%87%e4%bb%b6%e6%96%87%e4%bb%b6%e5%a4%b4%e6%b7%b7%e7%94%a8)2、拉入 010，查看文件头尾，可能会有不同类型文件文件头混用

#### [](#3foremost-%e6%88%96%e8%80%85-binwalk)3、foremost 或者 binwalk

如果 foremost 没有提取出东西，可以用 binwalk 试一下，可能 binwalk 可以提取出东西

例题 - i 春秋 CTF Misc class10

#### [](#4%e7%9b%b2%e6%b0%b4%e5%8d%b0%e9%9a%90%e5%86%99%e5%8f%af%e8%83%bd%e6%98%af%e4%b8%80%e5%bc%a0%e5%9b%be%e7%89%87%e6%88%96%e8%80%85%e4%b8%a4%e5%bc%a0%e5%9b%be%e7%89%87)4、盲水印隐写 (可能是一张图片或者两张图片)

**一张图片的情况**

可以使用 隐形水印工具 V1.2 或者 WaterMark 来提取水印

![](https://goodlunatic.github.io/posts/1ad9200/imgs/bw1.png)

**两张图片的情况**

```
先把要处理的图片拉入BlindWaterMark-master文件夹，然后使用如下命令
py bwmforpy3.py decode day1.png day2.png flag.png --oldseed
Tips:这里还会出现FFT（傅里叶盲水印）:直接运行CTFD中的FFT.py
```

#### [](#5%e5%9b%be%e7%89%87%e7%9a%84%e5%88%86%e7%a6%bb%e5%92%8c%e6%8b%bc%e6%8e%a5)5、图片的分离和拼接

(1) 可以用 kali 的 convert 分离和 montage 拼接命令

```
分解GIF的命令：convert glance.gif flag.png
水平镜像翻转图片：convert -flop reverse.jpg reversed.jpg
垂直镜像翻转图片：convert -flip reverse.jpg reversed.jpg
合成图片的命令：montage flag*.png -tile x1 -geometry +0+0 flag.png
-tile是拼接时每行和每列的图片数，这里用x1，就是只一行
-geometry是首选每个图和边框尺寸，我们边框为0，图照原始尺寸即可
```

(2) 使用在线网站分解：https://tu.sioe.cn/gj/fenjie/

(3) 用 py 脚本跑

```
import os
from PIL import Image
im = Image.new('RGB', (2*201, 600))  # new(mode,size) size is long and width
PATH = 'E:/ctf/glance.gif'
FILE_NAME = [i for i in os.listdir(PATH)]
width = 0
for i in FILE_NAME:
    im.paste(Image.open(PATH+i), (width, 0, width+2, 600))  # box is 左，上，右,下
    width += 2
im.show()
```

#### [](#6%e5%83%8f%e7%b4%a0%e7%82%b9%e5%90%88%e6%88%90)6、像素点合成

注：Linux wc 命令用于计算字数。

-l 或–lines 显示行数。

-w 或–words 只显示字数。

-c 或–bytes 或–chars 只显示 Bytes 数。

可以改个标题后用在线网站将 txt 转换为 ppm 文件

#### [](#7image-conbiner%e4%b8%a4%e5%bc%a0%e5%9b%be%e7%89%87)7、Image conbiner(两张图片)

两张图片可能有部分残缺（可以互补）

给了两张图片时，用 Stegsolve.jar，打开其中一张，

然后再 Analyze-Image conbiner 打开另一张图片

还有可能是给了两张二维码，需要两个二维码每个像素亦或，直接用 CTFD 中的像素亦或脚本即可

#### [](#8oursecret%e9%9a%90%e5%86%99)8、OurSecret 隐写

拉入 OurSecret，输入密码解密，得到隐藏文件

#### [](#9%e6%8b%bc%e5%9b%be%e9%a2%98)9、拼图题

**碎图片合成一张图片**

```
#在Windows中使用imagemagick处理
magick.exe montage *.png -tile 18x10 -geometry 125x125+0+0 flag.jpg
magick montage *.png -tile 40x22 -geometry +0+0 flag-0.png
```

```
#在kali中处理
拉入kali里处理，如果是碎的图片，
先使用 montage *.PNG -tile 12x12 -geometry +0+0 out.png合成一张图片
*.png表示匹配所有图片
-tile表示图片的张数
-geometry +0+0表示每张图片的间距为0
合成后要先查看图片的宽高（宽高要相等，不相等要用PS调整）
```

**然后把上面合成好的图片使用 Puzzle-Merak 工具进行智能拼图**

![](https://goodlunatic.github.io/posts/1ad9200/imgs/puzzles1.png)

![](https://goodlunatic.github.io/posts/1ad9200/imgs/puzzles2.png)

**这里只需要输入 generation、population、size 并用分号分开即可开始自动拼图**

**也可以使用 gaps 智能拼图 (在 kali 和 wsl 里使用都可以)**

```
gaps --image=out.png --generation=30 --population=144 --size=30 --save 

--image 指向拼图的路径
--size 拼图块的像素尺寸
--generations 遗传算法的代的数量
--population 个体数量
--verbose 每一代训练结束后展示最佳结果
--save 将拼图还原为图像
```

```
gaps --image=flag.jpg --generations=50 --population=180 --size=125 --verbose

-generations 你要迭代多少次
-population 你有多少个小拼图
--size 每张小图，也就是拼图小块的大小
--verbose 实时显示
```

#### [](#10%e8%bf%91%e9%82%bb%e6%b3%95%e7%bc%a9%e6%94%be%e5%9b%be%e7%89%87)10、近邻法缩放图片

在 PS 中打开图片，然后在更改图像大小中，将宽高调成指定像素并将重新采样选项选为邻近（硬边缘）

#### [](#11pixeljihad%e6%9c%89%e5%af%86%e7%a0%81)11、pixeljihad（有密码）

直接使用在线网站解密即可：[PixelJihad (sekao.net)](https://sekao.net/pixeljihad/)

#### [](#12%e9%9a%90%e5%86%99%e6%96%87%e6%9c%ac%e5%8f%af%e8%83%bd%e8%97%8f%e5%9c%a8%e5%8e%9f%e5%9b%be%e7%89%87%e5%92%8c%e9%9a%90%e5%86%99%e6%96%87%e4%bb%b6%e7%9a%84%e4%b8%ad%e9%97%b4)12、隐写文本可能藏在原图片和隐写文件的中间

直接在 010 中搜索 IEND，然后查看后面有没有额外内容即可

#### [](#13%e6%8f%90%e5%8f%96%e5%9b%be%e7%89%87%e4%b8%ad%e7%ad%89%e8%b7%9d%e7%9a%84%e5%83%8f%e7%b4%a0%e7%82%b9%e5%be%97%e5%88%b0%e9%9a%90%e5%86%99%e7%9a%84%e5%9b%be%e7%89%87)13、提取图片中等距的像素点得到隐写的图片

在 windows 的终端 wt 中运行 CTFD 中的 Get_Pixels.py

```
py main.py -f arcaea.png -p 0x0+3828x2148 -n 12x12
py main.py -f 要解密的图片 -p 第一个像素点的XY坐标+最后一个像素点的XY坐标 -n 两个等距像素点的XY距离的差值
如果是等距离提取整张图片中所有像素点，要注意右下角那个点的位置XY都要减去一倍的距离
Tips:在PS中按F8就可以看到每个像素点的具体坐标了
```

#### [](#14silenteye%e9%9a%90%e5%86%99)14、silenteye 隐写

特征：放大图像后会有行列不对齐的小灰块

直接用 silenteye 打开输入密钥 decode 即可，默认密钥是 silenteye

#### [](#15%e5%9b%be%e7%89%87%e6%8a%a5%e9%94%99%e6%94%b9%e5%ae%bd%e9%ab%98%e5%90%8e%e5%9b%be%e7%89%87%e6%97%a0%e5%8f%98%e5%8c%96%e5%8f%af%e4%bb%a5%e5%86%8d-foremost-%e4%b8%80%e4%b8%8b)15、图片报错改宽高后图片无变化，可以再 foremost 一下

#### [](#16deegger-embedder%e9%9a%90%e5%86%99)16、DeEgger Embedder 隐写

可以直接使用 DeEgger Embedder 工具 extract files

#### [](#17flag%e5%8f%af%e8%83%bd%e8%97%8f%e5%9c%a8-exif-%e4%b8%ad)17、flag 可能藏在 exif 中

直接在 WSL 中输入以下命令查看即可，如果偷懒也可以直接使用 破空 flag 查找工具 进行查找

#### [](#18%e7%bb%99%e4%ba%86%e4%b8%a4%e5%bc%a0%e5%9b%be%e7%89%87flag%e8%97%8f%e5%9c%a8%e6%af%8f%e8%a1%8c%e4%b8%8d%e5%90%8c%e5%83%8f%e7%b4%a0%e7%9a%84%e4%b8%aa%e6%95%b0%e4%b8%ad)18、给了两张图片，flag 藏在每行不同像素的个数中

例题 1-2023 羊城杯初赛 - 两支老虎

```
from PIL import Image, ImageChops

img1 = Image.open("1.png")
width1,heigth1 = img1.size # 1134,720
img2 = Image.open("2.png") 
width2,heigth2 = img2.size # 1144,720
img2 = img2.crop((0,0,1134,720))
width2,heigth2 = img2.size
# img2.save("3.png")

diff_dit = {}
# 返回差异图像，表示 img1 和 img2 之间的像素差异。
diff = ImageChops.difference(img1,img2)
width3,heigth3 = diff.size
for x in range(width3):
    for y in range(heigth3):
        pixel3 = str(diff.getpixel((x,y)))
        # 统计一下差异像素
        if pixel3 not in diff_dit: 
            diff_dit[pixel3] = 0
        else:
            diff_dit[pixel3] += 1
print(diff_dit) 
# {'(0, 0, 0)': 813891, '(1, 1, 1)': 2533, '(1, 1, 0)': 53}

for y in range(heigth1):
    cnt = 0
    for x in range(width1):
        pixel1 = img1.getpixel((x,y))
        pixel2 = img2.getpixel((x,y))
        if pixel1 != pixel2:
            cnt += 1
    if cnt != 0:
        print(chr(cnt),end='')
# DASCTF{tWo_t1gers_rUn_f@st}
```

### [](#png%e6%80%9d%e8%b7%af)PNG 思路

#### [](#1crc%e9%94%99%e8%af%af%e4%b8%8d%e8%83%bd%e4%b9%b1%e6%94%b9%e6%94%b9%e5%ae%bd%e9%ab%981720%e6%98%af%e5%ae%bd2124%e6%98%af%e9%ab%98%e5%8f%af%e7%94%a8pictools%e8%84%9a%e6%9c%ac%e5%bf%ab%e9%80%9f%e7%88%86%e7%a0%b4)1、CRC 错误 (不能乱改)，改宽高，17~20 是宽，21~24 是高 (可用 Pictools 脚本快速爆破)

#### [](#2lsb%e6%9c%80%e4%bd%8e%e6%9c%89%e6%95%88%e4%bd%8d%e9%9a%90%e5%86%99)2、LSB(最低有效位) 隐写:

**没有密钥的情况**

```
# 用zsteg快速查看
zsteg -a (文件名)  #查看各个通道的lsb
-b的位数是从1开始的 zsteg zlib.bmp -b 1 -o xy -v
提取文件并导出 zsteg -e b1,r,lsb,xy 3.png > 123.jpg
```

信息藏在图片中有时候会看不出来，所以还是要用 stegsolve.jar 过一遍

**有密钥的情况（cloacked-pixel）**

lsb 隐写的可能是加密后的数据，i 春秋最喜欢的 **cloacked-pixel**

拉到 kali/WSL 里用 cloacked-pixel 命令解密出数据

```
python2 cloacked-pixel-master/lsb.py extract 0.png out.data f78dcd383f1b574b
```

0.png 是隐写后的图片；out.data 是隐写内容保存的位置；f78dcd383f1b574b 是密钥

#### [](#3lsb%e4%bd%8e%e4%bd%8d%e9%9a%90%e5%86%99)3、LSB 低位隐写

用 CTFD 中的脚本跑出隐藏的图片

#### [](#4idat%e5%9d%97%e9%9a%90%e5%86%99)4、IDAT 块隐写

**(1) 解压 zlib 获得原始数据**

然后用 010 提取数据扔进 zlib 脚本解压获得原始数据

将异常的 IDAT 数据块斩头去尾之后使用脚本解压，在 python2 代码如下：

```
import zlib
import binascii
IDAT = "789C5D91011280400802BF04FFFF5C75294B5537738A21A27D1E49CFD17DB3937A92E7E603880A6D485100901FB0410153350DE83112EA2D51C54CE2E585B15A2FC78E8872F51C6FC1881882F93D372DEF78E665B0C36C529622A0A45588138833A170A2071DDCD18219DB8C0D465D8B6989719645ED9C11C36AE3ABDAEFCFC0ACF023E77C17C7897667".decode('hex')
result = binascii.hexlify(zlib.decompress(IDAT))
print (result.decode('hex'))
print (len(result.decode('hex')))
```

**(2) 加上文件头爆破宽高得到新的图片**

一般出问题的 IDAT Chunk 大小都是比正常的小的，很可能在图片末尾

如果不确定是哪一个有问题，可以尝试都提取出来，一个一个分析

可以使用 tweakpng 辅助分析，但是一般用 010 的模板提取分析就够了

我们可用 WSL 中的 pngcheck -v 0.png 检查 IDAT

如下图，最后一个和倒数第二个 IDAT 明显有问题，因此可以对这两部分进行尝试

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240724171411362.png)

借助 010 的模板功能把 IDAT 块提取出来，加上文件头尾并爆破 CRC 即可得到另一张图片

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240724171723828.png)

Tips：这里有时候也可以不用补文件尾

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240724171731445.png)

把文件头尾补完整后直接 CRC 爆破一下即可

例题 1-2023 安洵杯 - dacong の secret

例题 2-DASCTF2024 暑期挑战赛 - png_master

#### [](#5png%e6%95%b0%e6%8d%ae%e6%9c%ab%e5%b0%be%e8%97%8fzip)5、png 数据末尾藏 zip

补上压缩包的文件头，然后提取出来，解压 (可用 stegpy 得到解压密码)。

或者直接 foremost 提取

#### [](#6apngdis_gui)6、apngdis_gui

一张 png 图片还可能是 apng，直接用 apngdis_gui 跑一下，可以分出两张相似的 png

#### [](#7cve-2023-28303-%e6%88%aa%e5%9b%be%e5%b7%a5%e5%85%b7%e6%bc%8f%e6%b4%9e)7、CVE-2023-28303 截图工具漏洞

可以使用 Github 上大佬写好的工具一把梭，前提是需要知道原图的分辨率

#### [](#8stegpy%e9%9a%90%e5%86%99)8、stegpy 隐写

[stegpy 开源地址](https://github.com/izcoser/stegpy) 下载好后直接用 WSL 输入以下命令并输入密码解密即可

也可以直接用 pip 安装： pip3 install stegpy

### [](#jpg%e6%80%9d%e8%b7%af)JPG 思路

#### [](#1%e5%8f%af%e4%bb%a5%e8%af%95%e8%af%95%e7%94%a8stegdectet%e7%9c%8b%e7%9c%8b%e6%98%af%e4%bb%80%e4%b9%88%e5%8a%a0%e5%af%86)1、可以试试用 stegdectet 看看是什么加密：

.\stegdetect.exe -t jopi -s 10.0 .\0.jpg

![](https://goodlunatic.github.io/posts/1ad9200/imgs/stegdectet-171427285283031.gif)

出现三颗星不一定就代表一定是这种加密方式

#### [](#2jphs%e9%9a%90%e5%86%99)2、JPHS 隐写

有可能会有密码

导出步骤 Select File –> seek –> demo.txt –> Save the file

#### [](#3steghide%e9%9a%90%e5%86%99)3、steghide 隐写

```
#如果密码已经知道了
steghide extract -sf filename -p passwd
```

在 WSL 或者 kali 里用 Stegseek 跑（字典在 wordlist 里）

```
#如果密码未知
可以用下面这个脚本爆破
#bruteStegHide.sh
#!/bin/bash

for line in `cat $2`;do
    steghide extract -sf $1 -p $line > /dev/null 2>&1
    if [[ $? -eq 0 ]];then
        echo 'password is: '$line
        exit
    fi
done
```

```
#或者在WSL或者kali里用Stegseek跑（字典在wordlist里）
stegseek filename rockyou.txt
```

#### [](#4outguess%e9%9a%90%e5%86%99)4、outguess 隐写

```
outguess -k "abc" -r mmm.jpg flag.txt
#-k 后面跟的是解密的密钥
#flag.txt是解密后数据保存的位置
```

#### [](#5f5-steganography-master)5、F5-steganography-master

把要解密的图片拉到 F5 文件夹中

```
#有密码的情况
java Extract beautiful.jpg -p passwd
#无密码的情况
java Extract beautiful.jpg
#解密出来的数据会放到F5文件夹下的output.txt中
```

#### [](#6jpg%e5%ae%bd%e9%ab%98%e9%9a%90%e5%86%99)6、JPG 宽高隐写

010 打开 JPG 图片，找到 struct SOF 块数据，手动调整宽高即可

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240911103611924.png)

### [](#bmp%e6%80%9d%e8%b7%af)BMP 思路

#### [](#1bmp%e5%ae%bd%e9%ab%98%e7%88%86%e7%a0%b4)1、bmp 宽高爆破：

删除文件头，并保存为文件名. data，然后用 GIMP 打开修改宽高（这个比较方便）

或者直接用 bmp 爆破脚本跑 python script.py -f filename.bmp

```
import os
import time
import math
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-f", type=str, default=None, required=True,
                    help="输入同级目录下图片的名称")
args = parser.parse_args()

SAVE_DIR = os.getcwd()


def save_img(data, width=None, height=None, sqrt_num=None):
    with open(os.path.join(SAVE_DIR, "fix_width.bmp"), "wb") as f:
        f.write(data[:0x12] + width.to_bytes(4,
                byteorder="little", signed=False) + data[0x16:])

    with open(os.path.join(SAVE_DIR, "fix_height.bmp"), "wb") as f:
        f.write(data[:0x16] + height.to_bytes(4,
                byteorder="little", signed=False) + data[0x1a:])

    with open(os.path.join(SAVE_DIR, "fix_sqrt.bmp"), "wb") as f:
        f.write(data[:0x12] + sqrt_num.to_bytes(4,
                byteorder="little", signed=False) * 2 + data[0x1a:])


def get_pixels_size(data):
    bfSize = int.from_bytes(data[0x2:0x2+4], byteorder="little", signed=False)
    bfOffBits = int.from_bytes(
        data[0xa:0xa+4], byteorder="little", signed=False)
    biBitCount = int.from_bytes(
        data[0x1c:0x1c+2], byteorder="little", signed=False)
    channel = biBitCount // 8
    # 由于宽高都会被修改，所以我计算出来的Padding_size也不是正确的，没有意义
    # padding_size = (4 - col * channel % 4) * row if col * channel % 4 != 0 else 0
    # pixels_size = (bfSize - bfOffBits - padding_size) // channel
    return (bfSize - bfOffBits) // channel


if __name__ == '__main__':
    file_path = os.path.abspath(args.f)
    if os.path.splitext(args.f)[-1] != ".bmp":
        print("您的文件后缀名不为BMP!")
        time.sleep(1)
        exit(-1)

    with open(file_path, "rb") as f:
        data = f.read()
    col = abs(int.from_bytes(data[0x12:0x12+4],
              byteorder="little", signed=True))
    row = abs(int.from_bytes(data[0x16:0x16+4],
              byteorder="little", signed=True))
    pixels_size = get_pixels_size(data)

    width, height = pixels_size // row, pixels_size // col
    sqrt_num = int(math.sqrt((pixels_size)))
    save_img(data, width=width, height=height, sqrt_num=sqrt_num)

    print("温馨提示：由于填充字节的问题，所以可能会偏差几个像素!")
    print(f"1.修复宽度: {width}")
    print(f"2.修复高度: {height}")
    print(f"3.修复宽度高度为: {sqrt_num}")
    time.sleep(1)
```

#### [](#2wbstego4open%e9%9a%90%e5%86%99)2、wbStego4open 隐写

用 wbStego4open 直接 decode

#### [](#3silenteye%e9%9a%90%e5%86%99)3、silenteye 隐写

直接拉入 silenteye 解密即可

### [](#gif%e6%80%9d%e8%b7%af)GIF 思路

#### [](#1gif%e5%9b%be%e7%89%87%e5%8f%af%e8%83%bd%e8%a6%81%e5%88%86%e5%b8%a7%e6%8f%90%e5%8f%96%e5%9c%a8%e7%ba%bf%e7%bd%91%e7%ab%99%e6%88%96%e8%80%85%e5%b7%a5%e5%85%b7)1、GIF 图片可能要分帧提取 (在线网站或者工具)

```
# 在Windows或者WSL中执行以下命令进行分离
ffmpeg -i filename.gif frame%04d.png
```

然后 GIF 可能会还有时间轴隐写 (每帧时间不同)，因此需要乘以倍数，当然也可能会有空间轴隐写

### [](#webp%e6%80%9d%e8%b7%af)Webp 思路

webp 文件用电脑自带的图片看可能会有点问题，建议用浏览器打开这种文件

webp 可能是动图，可以用下面这个脚本分离 webp 中的每帧图片

```
from PIL import Image

img = Image.open('killer.webp')
n_frame = img.n_frames
for i in range(n_frame):
    img.seek(i)
    img.save(f'img/{i}.png')
```

### [](#rawarw%e6%96%87%e4%bb%b6%e6%80%9d%e8%b7%af)RAW、ARW 文件思路

#### [](#1raw%e7%9a%84lsb%e9%9a%90%e5%86%99)1、RAW 的 LSB 隐写

ARW 文件是 Sony 相机的原始数据格式

可以使用 rawpy 模块读取图片的像素数据，查看是否存在 LSB 隐写【例：2024 L3HCTF RAWatermark】

示例脚本如下：

```
import rawpy
import numpy as np
import libnum

with rawpy.imread('image.ARW') as raw:
    # 从 raw 对象中获取可见的 Bayer 格式图像数据
    bayer_visible = raw.raw_image_visible
    # print(bayer_visible)
    # 用 bitwise_and() 函数将 bayer_visible 中的每个像素值与 1 进行按位与操作，以提取每个像素的最低有效位（LSB）
    lsb_array = np.bitwise_and(bayer_visible, 1)
    # print(lsb_array)
    # 使用 NumPy 数组的 flatten() 方法将 lsb_array 数组展平成一维数组
    lsb_array_flat = lsb_array.flatten()
    # print(lsb_array_flat)
    hidden_message = ''.join(map(str, lsb_array_flat))
    # 将隐写的数据转为十六进制，便于查看文件头
    hex_data = hex(int(hidden_message, 2))
    # print(hex_data[:10]) # 0x504b0304
    # 将二进制数据转换为byte类型数据
    data = libnum.b2s(hidden_message)

with open('flag.zip', 'wb') as f:
    f.write(data)
```

#### [](#2%e7%9b%b4%e6%8e%a5%e6%94%b9%e5%90%8e%e7%bc%80%e4%b8%badata%e7%84%b6%e5%90%8e%e6%8b%96%e5%85%a5gimp%e5%8d%b3%e5%8f%af)2、直接改后缀为. data，然后拖入 Gimp 即可

### [](#%e4%ba%8c%e7%bb%b4%e7%a0%81%e6%80%9d%e8%b7%af)二维码思路

#### [](#1bmp%e8%bd%ac%e4%ba%8c%e7%bb%b4%e7%a0%81)1、bmp 转二维码

#### [](#216%e8%bf%9b%e5%88%b6%e8%bd%acpyc)2、16 进制转 pyc

#### [](#3%e5%ad%97%e7%ac%a6%e4%b8%b2%e5%88%b6%e4%bd%9c%e4%ba%8c%e7%bb%b4%e7%a0%81)3、字符串制作二维码

```
直接右键使用B神的脚本制作二维码，制作前注意要把字符串的长度手动修正为平方数
1.0 1制作二维码
2.00 11制作二维码
```

#### [](#4%e5%9b%9b%e4%b8%aattl%e5%80%bc%e8%bd%ac%e6%8d%a2%e4%b8%80%e4%b8%aa%e5%ad%97%e8%8a%82%e7%9a%84%e4%ba%8c%e8%bf%9b%e5%88%b6%e6%95%b0)4、四个 TTL 值转换一个字节的二进制数

#### [](#5aztec-codedatamatrixgridmatrix%e6%b1%89%e4%bf%a1%e7%a0%81pdf417code%e7%ad%89)5、Aztec code、DataMatrix、GridMatrix、汉信码、PDF417code 等

我们平常见的最多的二维码就是 QRcode，但是实际上还有很多不同类型的二维码，这里就简单举几个例子：

![](https://goodlunatic.github.io/posts/1ad9200/imgs/azteccode.gif)

![](https://goodlunatic.github.io/posts/1ad9200/imgs/DataMatrix.png)

![](https://goodlunatic.github.io/posts/1ad9200/imgs/GridMatrix.png)

![](https://goodlunatic.github.io/posts/1ad9200/imgs/%E6%B1%89%E4%BF%A1%E7%A0%81.png)

![](https://goodlunatic.github.io/posts/1ad9200/imgs/PDF417code.png)

这里要注意的是，出题人可能会把图片反相导致无法直接扫描，因此我们可以先将图片拉入 PS 先进行反相处理

#### [](#%e4%ba%8c%e7%bb%b4%e7%a0%81%e7%9a%84%e7%ba%a0%e9%94%99%e7%ad%89%e7%ba%a7)二维码的纠错等级

参考链接：https://www.shangyexinzhi.com/article/4952046.html

以下面这张二维码为例子

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20241031211220251.png)

<table><thead><tr><th>1 位置的颜色</th><th>2 位置的颜色</th><th>纠错等级</th><th>容错率</th></tr></thead><tbody><tr><td>黑</td><td>黑</td><td>L(Low)</td><td>7%</td></tr><tr><td>黑</td><td>白</td><td>M(Medium)</td><td>15%</td></tr><tr><td>白</td><td>黑</td><td>Q(Quartil)</td><td>25%</td></tr><tr><td>白</td><td>白</td><td>H(High)</td><td>30%</td></tr></tbody></table>

[](#miscpdf%e9%a2%98%e6%80%9d%e8%b7%af)Misc——PDF 题思路：
-----------------------------------------------------

1、直接 binwalk 或者 foremost 解出隐藏文件

2、可能是 wbStego4open 隐写，用 wbStego4open 直接 decode

3、PDF 中可能携带了什么文件，可以在 Firefox 或者别的 PDF 软件中打开并提取

4、PDF 中可能有透明的文字，直接全选复制然后粘贴到记事本中查看即可

5、DeEgger Embedder 隐写

可以直接使用 DeEgger Embedder 工具 extract files

[](#miscms-office%e9%a2%98%e6%80%9d%e8%b7%af)Misc——MS-Office 题思路
----------------------------------------------------------------

### [](#excel%e6%96%87%e4%bb%b6xls-xlsx)Excel 文件：.xls .xlsx

1、拉入 010 或者记事本，查找 flag 2、取消隐藏先前隐藏的行和列 3、条件格式里设置突出显示某些单元格 (黑白后可能会有图案) 4、要先将数据按照行列排序后再进行处理

### [](#word%e6%96%87%e4%bb%b6doc-docx)Word 文件：.doc .docx

### [](#1%e7%9b%b4%e6%8e%a5foremost%e5%87%ba%e9%9a%90%e8%97%8f%e6%96%87%e4%bb%b6)1、直接 foremost 出隐藏文件

### [](#2%e4%b8%8e%e5%ae%8f%e6%9c%89%e5%85%b3%e7%b3%bb%e7%9a%84%e5%90%84%e7%a7%8d%e6%94%bb%e5%87%bb%e4%b8%8e%e9%9a%90%e5%86%99)2、与宏有关系的各种攻击与隐写

分析 word 中的宏需要用到这样一个工具：oletools

这个工具直接在 pip 中安装即可使用: pip3 install oletools

#### [](#doc%e6%a0%bc%e5%bc%8f%e5%8f%af%e4%bb%a5%e4%b8%8d%e9%9c%80%e8%a6%81%e6%96%87%e6%a1%a3%e5%af%86%e7%a0%81%e7%9b%b4%e6%8e%a5%e6%8f%90%e5%8f%96%e5%85%b6%e4%b8%ad%e7%9a%84vba%e5%ae%8f%e4%bb%a3%e7%a0%81)doc 格式可以不需要文档密码直接提取其中的 vba 宏代码

安装好 oletools 后直接运行以下代码提取即可，可能加密文档的加密算法就在期中

```
olevba .\attachment.doc > test.txt
```

### [](#3%e5%88%a9%e7%94%a8%e8%a1%8c%e8%b7%9d%e6%9d%a5%e9%9a%90%e5%86%99%e4%be%8biscc2023-%e6%b1%a4%e5%a7%86%e5%8e%86%e9%99%a9%e8%ae%b0)3、利用行距来隐写（例：ISCC2023 - 汤姆历险记）

word 中可能有一段是 1 倍行距，可能又有一段是 1.5 倍行距，需要根据不同行距敲出摩斯电码（单倍转为. 多倍转为 - 空行转为空格或者分隔符）

[](#misctxt%e9%a2%98%e6%80%9d%e8%b7%af)Misc——txt 题思路：
-----------------------------------------------------

### [](#1-%e6%9c%89%e5%8f%af%e8%83%bd%e6%98%afntfs%e7%9b%b4%e6%8e%a5%e7%94%a8ntfsstreamseditor2%e6%89%ab%e6%8f%8f%e6%89%80%e5%9c%a8%e6%96%87%e4%bb%b6%e5%a4%b9%e7%84%b6%e5%90%8e%e5%af%bc%e5%87%ba%e5%8f%af%e7%96%91%e6%96%87%e4%bb%b6%e5%a6%82%e6%9e%9c%e6%98%af%e5%8e%8b%e7%bc%a9%e5%8c%85%e4%b8%80%e5%ae%9a%e8%a6%81%e7%94%a8winrar%e8%a7%a3%e5%8e%8b)1、 有可能是 ntfs，直接用 NtfsStreamsEditor2 扫描所在文件夹，然后导出可疑文件【如果是压缩包，一定要用 winrar 解压】

### [](#2%e5%8f%af%e8%83%bd%e6%98%afwbstego4open%e9%9a%90%e5%86%99%e7%94%a8wbstego4open%e7%9b%b4%e6%8e%a5decode%e5%8f%af%e8%83%bd%e6%9c%89%e5%af%86%e9%92%a5)2、可能是 wbStego4open 隐写，用 wbStego4open 直接 decode(可能有密钥)

### [](#3%e5%a6%82%e6%9e%9c%e6%98%af%e9%82%a3%e7%a7%8d%e6%96%87%e4%bb%b6%e5%a4%b9%e5%a5%97%e6%96%87%e4%bb%b6%e5%a4%b9%e7%9a%84%e9%a2%98%e7%9b%ae%e5%8f%af%e4%bb%a5%e7%9b%b4%e6%8e%a5%e6%8a%8a%e8%b7%af%e5%be%84%e7%b2%98%e8%b4%b4%e5%88%b0everything%e4%b8%ad%e8%ae%a9everything%e4%b8%80%e6%8a%8a%e6%a2%ad)3、如果是那种文件夹套文件夹的题目，可以直接把路径粘贴到 everything 中，让 everything 一把梭

### [](#4%e6%97%a0%e5%ad%97%e5%a4%a9%e4%b9%a6whitespacesnow%e9%9a%90%e5%86%99)4、无字天书 (whitespace)&snow 隐写

一个文件打开都是空白字符 可以使用在线网站解密：https://vii5ard.github.io/whitespace/ 复制进去直接 run 即可 snow 隐写，到 snowdos32 工具目录下运行 SNOW.EXE -C -p password flag.txt 命令即可

### [](#5%e5%9e%83%e5%9c%be%e9%82%ae%e4%bb%b6%e9%9a%90%e5%86%99spammimic)5、垃圾邮件隐写 (spammimic)

例题 1-2024 强网拟态初赛 - PvZ

直接使用以下在线网站解密即可：

[https://www.spammimic.com/](https://www.spammimic.com/)

[](#mischtml%e9%a2%98%e6%80%9d%e8%b7%af)Misc——html 题思路：
-------------------------------------------------------

1、可能是 wbStego4open 隐写，用 wbStego4open 直接 decode

[](#misc%e5%8e%8b%e7%bc%a9%e5%8c%85%e6%80%9d%e8%b7%af)Misc——压缩包思路：
------------------------------------------------------------------

Tips：压缩包的密码可以是中英文字符和符号

​没有思路时可以直接纯数字 / 字母暴力爆破一下

### [](#zip%e6%96%87%e4%bb%b6%e7%bb%93%e6%9e%84)zip 文件结构

三部分：压缩文件源数据区 + 压缩源文件目录区 + 压缩源文件目录结束标志

**文件源数据区**

<table><thead><tr><th>HEX 数据</th><th>描述</th><th>010Editor 模板数据</th></tr></thead><tbody><tr><td>50 4B 03 04</td><td>zip 文件头标记，看文本的话就是 PK 开头</td><td>char frSignature[4]</td></tr><tr><td>0A 00</td><td>解压文件所需 pkware 版本</td><td>ushort frVersion</td></tr><tr><td>00 00</td><td>全局方式位标记（有无加密），头文件标记后 2bytes</td><td>ushort frFlags</td></tr><tr><td>00 00</td><td>压缩方式</td><td>enum COMPTYPE frCompression</td></tr><tr><td>E8 A6</td><td>最后修改文件时间</td><td>DOSTIME frFileTime</td></tr><tr><td>32 53</td><td>最后修改文件日期</td><td>DOSDATE frFileDate</td></tr><tr><td>0C 7E 7F D8</td><td>CRC-32 校验</td><td>uint frCrc</td></tr></tbody></table>

**文件目录区**

<table><thead><tr><th>HEX 数据</th><th>描述</th><th>010Editor 模板数据</th></tr></thead><tbody><tr><td>50 4B 01 02</td><td>目录中文件文件头标记</td><td>char deSignature[4]</td></tr><tr><td>3F 00</td><td>压缩使用的 pkware 版本</td><td>ushort deVersionMadeBy</td></tr><tr><td>0A 00</td><td>解压文件所需 pkware 版本</td><td>ushort deVersionToExtract</td></tr><tr><td>00 00</td><td>全局方式位标记（有无加密），目录文件标记后 4bytes</td><td>ushort frFlags</td></tr><tr><td>00 00</td><td>压缩方式</td><td>enum COMPTYPE frCompression</td></tr><tr><td>E8 A6</td><td>最后修改文件时间</td><td>DOSTIME frFileTime</td></tr><tr><td>32 53</td><td>最后修改文件日期</td><td>DOSDATE frFileDate</td></tr><tr><td>0C 7E 7F D8</td><td>CRC-32 校验</td><td>uint frCrc</td></tr></tbody></table>

**文件目录结束**

<table><thead><tr><th>50 4B 05 06</th><th>目录结束标记</th><th>char elSignature[4]</th></tr></thead><tbody><tr><td>00 00</td><td>当前磁盘编号</td><td>ushort elDiskNumber</td></tr><tr><td>00 00</td><td>目录区开始磁盘编号</td><td>ushort elStartDiskNumber</td></tr></tbody></table>

#### [](#%e5%b8%b8%e8%a7%81%e6%8a%a5%e9%94%99%e5%8f%8a%e5%af%b9%e5%ba%94%e8%a7%a3%e5%86%b3%e6%96%b9%e6%b3%95%e5%80%9f%e5%8a%a9010%e7%9a%84%e6%a8%a1%e6%9d%bf%e5%8a%9f%e8%83%bd)常见报错及对应解决方法（借助 010 的模板功能）

1.  该文件已损坏 - 源数据区和目录区的文件名长度被修改了

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240724172656435.png)

2.  CRC 校验错误 - 源数据区或目录区的压缩方法被修改了

![](https://goodlunatic.github.io/posts/1ad9200/imgs/image-20240724172708418.png)

### [](#rar%e6%96%87%e4%bb%b6%e7%bb%93%e6%9e%84)rar 文件结构

<table><thead><tr><th>HEX 数据</th><th>描述</th><th>010Editor 模板数据</th></tr></thead><tbody><tr><td>52 61 72 21 1A 07 00</td><td>rar 文件头标记，文本为 Rar!</td><td></td></tr></tbody></table>

**Main block**

<table><thead><tr><th>HEX 数据</th><th>描述</th><th>010Editor 模板数据</th></tr></thead><tbody><tr><td>33 92 B5 E5</td><td>全部块的 CRC32 值</td><td>uint32 HEAD_CRC</td></tr><tr><td>0A</td><td>块大小</td><td>struct uleb128 HeadSize</td></tr><tr><td>01</td><td>块类型</td><td>struct uleb128 HeadType</td></tr><tr><td>05</td><td>阻止标志</td><td>struct uleb128 HeadFlag</td></tr></tbody></table>

**File Header**

<table><thead><tr><th>HEX 数据</th><th>描述</th><th>010Editor 模板数据</th></tr></thead><tbody><tr><td>43 06 35 17</td><td>单独块的 CRC32 值</td><td>uint32 HEAD_CRC</td></tr><tr><td>55</td><td>块大小</td><td>struct uleb128 HeadSize</td></tr><tr><td>02</td><td>块类型</td><td>struct uleb128 HeadType</td></tr><tr><td>03</td><td>阻止标志</td><td>struct uleb128 HeadFlag</td></tr></tbody></table>

**Terminator**

<table><thead><tr><th>HEX 数据</th><th>描述</th><th>010Editor 模板数据</th></tr></thead><tbody><tr><td>1D 77 56 51</td><td>固定的 CRC32 值</td><td>uint32 HEAD_CRC</td></tr><tr><td>03</td><td>块大小</td><td>struct uleb128 HeadSize</td></tr><tr><td>05</td><td>块类型</td><td>struct uleb128 HeadType</td></tr><tr><td>04 00</td><td>阻止标志</td><td>struct uleb128 HeadFlag</td></tr></tbody></table>

### [](#1%e5%8e%8b%e7%bc%a9%e5%8c%85%e4%bc%aa%e5%8a%a0%e5%af%86)1、压缩包伪加密

### [](#zip%e6%96%87%e4%bb%b6)zip 文件：

可以直接用 ZipCenOp.jar 修复：

java -jar ZipCenOp.jar r screct.zip

WinRAR 打开、010 改标志位、binwalk 直接分离

如果压缩文件已损坏，则尝试用 winrar 打开，工具 - 修复压缩包

压缩源文件数据区：7-8 位表示有无加密

压缩源文件目录区：9-10 位表示是否是伪加密

一般这俩地方都是 09 00 的，大概率就是伪加密了 (直接把第二个 PK 后的 09 改了就行)

### [](#rar%e6%96%87%e4%bb%b6)rar 文件：

第 24 个字节尾数为 4 表示加密，0 表示无加密，将尾数改为 0 即可破解伪加密

### [](#2crc%e7%88%86%e7%a0%b4%e5%8e%8b%e7%bc%a9%e5%8c%85%e4%b8%ad%e6%96%87%e4%bb%b6%e6%af%94%e8%be%83%e5%b0%8f%e7%9a%84%e6%97%b6%e5%80%99)2、CRC 爆破（压缩包中文件比较小的时候）

使用 CRC 爆破需要文件大小小于等于 18 个字节

参考文章：https://blog.csdn.net/mochu7777777/article/details/110206427

可以使用 CTFD 中的两种脚本爆破一下 (速度不同)

### [](#3%e6%98%8e%e6%96%87%e6%94%bb%e5%87%bb)3、明文攻击

#### [](#%e5%b7%b2%e7%9f%a5%e6%89%80%e6%9c%89%e7%9a%84%e6%98%8e%e6%96%87%e6%88%96%e4%b8%89%e6%ae%b5%e5%af%86%e9%92%a5)**已知所有的明文或三段密钥**

**使用 Advanced Archive Password Recovery 破解**

有和压缩包中的一样 (CRC 值一样) 的文件时，压缩然后用 AAPR 进行明文攻击, 这个攻击的过程可能需要几分钟

有了完整的三段密钥也可以使用这个工具破解密码

**使用 pkcrack 破解**

```
#将pkcrack作为系统命令使用
cp pkcrack /usr/sbin/pkcrack
```

```
pkcrack -c "README.txt" -p README.txt -C flag.zip -P README.zip
```

```
-C:要破解的目标文件(含路径)
-c:破解文件中的明文文件的名字(其路径不包括系统路径,从zip文件一层开始)
-P:压缩后的明文文件
-p:压缩的明文文件中明文文件的名字(也就是readme.txt在readme.zip中的位置)
```

#### [](#%e5%b7%b2%e7%9f%a5%e9%83%a8%e5%88%86%e6%98%8e%e6%96%87)已知部分明文

**利用 bkcrack 进行攻击**

参考资料

```
https://www.freebuf.com/articles/network/255145.html
https://byxs20.github.io/posts/30731.html#%E6%80%BB%E7%BB%93
```

该利用方法的具体要求如下：

```
至少已知明文的12个字节及偏移，其中至少8字节需要连续。
明文对应的文件加密方式为ZipCrypto Store
Tips：进行明文攻击前要判断制作压缩包的压缩工具，然后对已知明文使用特定工具进行压缩，再进行明文攻击
例子：bkcrack -C \$R9EG7XR.zip -c flag.txt -k 958597ea b9f7740b 622aed5e -d flag.txt
```

如何判断压缩工具（参考自 B 神的博客）

<table><thead><tr><th>压缩攻击</th><th>VersionMadeBy(压缩所用版本)</th></tr></thead><tbody><tr><td>Bandzip 7.06</td><td>20</td></tr><tr><td>Windows 自带</td><td>20</td></tr><tr><td>WinRAR 4.20</td><td>31</td></tr><tr><td>WinRAR 5.70</td><td>31</td></tr><tr><td>7-Zip</td><td>63</td></tr></tbody></table>

**bkcrack 常用参数**

```
-c 要解密的文件
-P 已知明文所在的压缩包
-p 已知的明文部分
-x 压缩包内目标文件的偏移地址  部分已知明文值
-C 加密压缩包
-o offset  -p参数指定的明文在压缩包内目标文件的偏移量
-k 后面加破解出的三段密钥
-d 后面加解密后数据的保存位置
-U 修改压缩包密码并导出	bkcrack -C flag.zip -c hint.jpg -k afb9fee3 f8795353 f6de1d4e -U out.zip 114514
```

例题：

```
#Tips:
xxd // xxd 命令用于用二进制或十六进制显示文件的内容
-r // 把xxd的十六进制输出内容转换回原文件的二进制内容
-ps // 以 postscript的连续十六进制转储输出，这也叫做纯十六进制转储
```

##### [](#1%e7%ae%80%e5%8d%95%e7%9a%84%e5%8a%a0%e5%af%86%e6%96%87%e6%9c%ac%e5%8e%8b%e7%bc%a9%e5%8c%85%e7%a0%b4%e8%a7%a3)1) 简单的加密文本压缩包破解

```
flag{16e371fa-0555-47fc-b343-74f6754f6c01}
```

```
#攻击步骤如下：
#准备已知明文
echo -n "lag{16e3" > plain1.txt   #连续的8明文
echo -n "74f6" | xxd             #额外明文的十六进制格式，37346636
#攻击，-o是偏移量
bkcrack -C flag_360.zip -c flag.txt -p plain1.txt -o 1 -x 29 37346636
#由于时间较长，为防止终端终端导致破解中断，可以加点小技巧
bkcrack -C flag_360.zip -c flag.txt -p plain1.txt -o 1 -x 29 37346636 > 1.log& 
#后台运行，结果存入1.log
#加上time参数方便计算爆破时间
time bkcrack -C flag_360.zip -c flag.txt -p plain1.txt -o 1 -x 29 37346636 > 1.log&
#查看爆破进度
tail -f 1.log
#使用该秘钥进行解密：
bkcrack -C flag_360.zip -c flag.txt  -k b21e5df4 ab9a9430 8c336475 -d flag.txt
```

```
#-p 指定的明文不需要转换，-x 指定的明文需要转成十六进制
#提到的偏移都是指 “已知明文在加密前文件中的偏移”。
```

##### [](#2%e5%88%a9%e7%94%a8png%e5%9b%be%e7%89%87%e6%96%87%e4%bb%b6%e5%a4%b4%e7%a0%b4%e8%a7%a3)2) 利用 PNG 图片文件头破解

```
#准备已知明文
echo 89504E470D0A1A0A0000000D49484452 | xxd -r -ps > png_header
#攻击
time bkcrack -C png4.zip -c 2.png -p png_header -o 0 >1.log&
tail -f 1.log
time bkcrack -C png4.zip -c flag.txt -k e0be8d5d 70bb3140 7e983fff -d flag.txt
```

##### [](#3%e5%88%a9%e7%94%a8%e5%8e%8b%e7%bc%a9%e5%8c%85%e6%a0%bc%e5%bc%8f%e7%a0%b4%e8%a7%a3)3) 利用压缩包格式破解

```
将一个名为flag.txt的文件打包成ZIP压缩包后，发现文件名称会出现在压缩包文件头中，且偏移固定为30。且默认情况下，flag.zip也会作为该压缩包的名称。
已知的明文片段有：
“flag.txt”  8个字节，偏移30
ZIP本身文件头：50 4B 03 04 ，4字节
满足12字节的要求
```

```
echo -n "flag.txt" > plain1.txt #-n参数避免换行，不然文件中会出现换行符，导致攻击失效
time bkcrack -C test5.zip -c flag.zip -p plain1.txt -o 30  -x 0 504B0304 >1.log&
tail -f 1.log
bkcrack -C test5.zip -c flag.zip -k b21e5df4 ab9a9430 8c336475  -d flag.zip
#但若想解密2.png，由于是ZipCrypto deflate加密的
#使用deflate算法压缩的文件，解码出来的是Deflate的数据流
#所以解密后需要bkcrack/tool内的inflate.py脚本再次处理
bkcrack -C test5.zip -c 2.png -k b21e5df4 ab9a9430 8c336475  -d 2.png
python3 inflate.py < 2.png > 2_out.png
```

Tips：如果这里用 "XXXXX.txt" 作为 plaint1.txt 无法破解出密钥，可以试试直接去掉后缀再作为 plaint1.txt

例如：NKCTF2023——五年 Misc，三年模拟

```
#echo -n "handsome.txt" > plain1.txt 破解失败
echo -n "handsome" > plain1.txt
time bkcrack -C test5.zip -c handsome.zip -p plain1.txt -o 30  -x 0 504B0304 >1.log&
```

##### [](#4exe%e6%96%87%e4%bb%b6%e6%a0%bc%e5%bc%8f%e7%a0%b4%e8%a7%a3)4)EXE 文件格式破解

```
EXE文件默认加密情况下，不太会以store方式被加密，但它文件格式中的的明文及其明显，长度足够。如果加密ZIP压缩包出现以store算法存储的EXE格式文件，很容易进行破解。
大部分exe中都有这相同一段，且偏移固定为64：
```

![](https://image.3001.net/images/20201117/1605593956_5fb36b64db62588f96dcc.png!small)

```
echo -n "0E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000" | xxd -r -ps > mingwen
time bkcrack -C nc64.zip -c nc64.exe -p mingwen -o64  >1.log&
tail -f 1.log
bkcrack -C nc64.zip -c nc64.exe -k b21e5df4 ab9a9430 8c336475  -d nc64.exe
```

##### [](#5%e6%b5%81%e9%87%8f%e5%8c%85pcapng%e6%a0%bc%e5%bc%8f%e8%a7%a3%e5%af%86)5) 流量包 pcapng 格式解密

```
echo -n "00004D3C2B1A01000000FFFFFFFFFFFFFFFF" | xxd -r -ps > pcap_plain1
time bkcrack -C 3.zip -c capture.pcapng -p pcap_plain1 -o 6
bkcrack -C 3.zip -c capture.pcapng  -k e33a580c  c0c96a81 1246d892  -d out.pcapng
```

##### [](#6%e7%bd%91%e7%ab%99%e7%9b%b8%e5%85%b3%e6%96%87%e4%bb%b6%e7%a0%b4%e8%a7%a3)6) 网站相关文件破解

```
robots.txt的文件开头内容通常是User-agent: * 
html文件开头通常是 <!DOCTYPE html>
xml文件开头通常是<?xml version="1.0" encoding="UTF-8"?>
```

```
echo -n '<?xml version="1.0" encoding="UTF-8"?>' > xml_plain
time bkcrack -C xml.zip -c 123/web.xml -p xml_plain -o 0  //注意相对路径
bkcrack -C xml.zip -c 123/web.xml  -k e0be8d5d 70bb3140 7e983fff  -d web.xml
```

##### [](#7svg%e6%96%87%e4%bb%b6%e6%a0%bc%e5%bc%8f%e7%a0%b4%e8%a7%a3)7)SVG 文件格式破解

```
#SVG是一种基于XML的图像文件格式
echo -n '<?xml version="1.0" ' > plain.txt
bkcrack -C secrets.zip -c spiral.svg -p plain.txt -o 0
#解密 Store算法  直接解密即可
bkcrack -C secrets.zip -c spiral.svg -k c4038591 d5ff449d d3b0c696 -d spiral_deciphered.svg
#解密 deflate算法
bkcrack -C secrets.zip -c advice.jpg -k c4038591 d5ff449d d3b0c696 -d out.jpg
#该文件使用了deflate算法压缩的，解码出来的是Deflate的数据流,因此须将其解压缩。
python3 inflate.py < out.jpge > flag.jpg
```

##### [](#8vmdk%e6%96%87%e4%bb%b6%e6%a0%bc%e5%bc%8f%e7%a0%b4%e8%a7%a3)8)VMDK 文件格式破解

```
echo -n "4B444D560100000003000000" | xxd -r -ps > plain2
time bkcrack -C Easy_VMDK.zip -c flag.vmdk -p plain2 -o 0
time bkcrack -C Easy_VMDK.zip -c flag.vmdk -k xxx xxx xxx -d flag.vmdk
```

**有时候直接给你部分明文的情况（2023 DASCTFxCBCTF）**

直接在 bkcrack 中使用以下命令即可，key 是题目给的压缩包中被压缩文件的部分明文

```
bkcrack -C purezip.zip -c 'secret key.zip' -p key
```

**直接给了加密压缩包中部分文件的情况**

例题 1 - 2023 古剑山 - 幸运饼干

*   可以先把该文件用压缩软件压缩成一个压缩包，然后用 Advanced Archive Password Recovery 明文攻击试试看
    
*   用压缩软件把该文件压缩成一个压缩包，然后使用 bkcrack 进行明文攻击
    
    为什么需要压缩成压缩包呢？因为如果不带上压缩包进行明文攻击的话会报下面这个错误
    
    ```
    $ bkcrack -C flag.zip -c 'hint.jpg' -p hint.jpg
    bkcrack 1.5.0 - 2023-03-08
    Data error: ciphertext is smaller than plaintext.
    ```
    
    用 -P 参数带上压缩包后即可正确解密出密钥
    
    ```
    $ bkcrack -C flag.zip -c hint.jpg -p hint.jpg -P hint.zip
    bkcrack 1.5.0 - 2023-03-08
    [14:37:27] Z reduction using 25761 bytes of known plaintext
    100.0 % (25761 / 25761)
    [14:37:29] Attack on 289 Z values at index 21821
    Keys: afb9fee3 f8795353 f6de1d4e
    100.0 % (289 / 289)
    [14:37:29] Keys
    afb9fee3 f8795353 f6de1d4e
    ```
    
    因此这种情况一定要记得将已有的文件用适当的压缩方法压缩成压缩包，然后用 - P 参数带上这个压缩包
    

例题 1 - 2023 铁三决赛 - baby_jpg

我们先从部分伪加密的压缩包中分离出了 serect.pdf，然后从 PDF 中 foremost 出了加密压缩包中的 sha512.txt

将 sha512.txt 压缩成 sha512.zip，然后使用下面的命令进行明文攻击即可：

其中 -C 后是要破解的压缩包，-c 后是压缩包中我们要破解的文件，-P 后是我们压缩好的压缩包，-p 后是我们已得的文件

```
$ bkcrack -C 00000218.zip -c 'sha512.txt' -P sha512.zip -p sha512.txt
bkcrack 1.5.0 - 2023-03-08
[16:14:25] Z reduction using 78 bytes of known plaintext
100.0 % (78 / 78)
[16:14:25] Attack on 104916 Z values at index 6
Keys: ed3fb6a9 1c4a7211 c07461ed
59.9 % (62867 / 104916)
[16:14:52] Keys
ed3fb6a9 1c4a7211 c07461ed
```

破解出密钥后，用 -U 参数修改压缩包密码并导出

```
$ bkcrack -C 00000218.zip -k ed3fb6a9 1c4a7211 c07461ed -U out.zip 111
bkcrack 1.5.0 - 2023-03-08
[16:15:44] Writing unlocked archive out.zip with password "111"
100.0 % (3 / 3)
Wrote unlocked archive.
```

#### [](#%e5%9c%a8%e6%af%94%e8%b5%9b%e4%b8%ad%e7%9a%84%e4%bd%bf%e7%94%a8%e8%ae%b0%e5%bd%95)在比赛中的使用记录

**2022 西湖论剑 zipeasy**

```
bkcrack -C zipeasy.zip -c dasflow.zip -x 30 646173666c6f772e706361706e67 -x 0 504B0304 > 1.log &
```

**2023 DASCTFxCBCTF**

利用 bkcrack 反向爆破密钥

```
bkcrack -k e48d3828 5b7223cc 71851fb0 -r 3 \?b
#bkcrack 1.5.0 - 2023-03-08
#[17:47:50] Recovering password
#length 0-6...
#[17:47:50] Password
#as bytes: 8b e7 dc
#as text: ���
```

然后如果要对得到的密钥进行 MD5 加密，可以使用 CyberChef（From Hex + MD5）

![](https://goodlunatic.github.io/posts/1ad9200/imgs/MD5.png)

Tips：题目做不出来可以尝试多换几个压缩软件：Bandzip、Winrar、7zip、360 压缩、2345 压缩等

### [](#4%e6%9a%b4%e5%8a%9b%e7%a0%b4%e8%a7%a3%e7%88%86%e7%a0%b4%e6%97%b6%e6%b3%a8%e6%84%8f%e9%99%90%e5%88%b6%e9%95%bf%e5%ba%a6)4、暴力破解 (爆破时注意限制长度)

可以使用 Advanced Archive Password Recovery 进行爆破

(1) 如果知道部分的密码，可以使用掩码攻击，例如：????LiHua

(2) 没啥思路的时候可以直接用纯数字密码爆破看看，也可以用字典爆破

(3) 如果爆破的速度很慢，可以用 Passware Kit Forensic 2021 v1 (64-bit) 来爆破（也可以自定义字典）

### [](#5%e8%bf%9e%e7%8e%af%e5%a5%97%e5%8e%8b%e7%bc%a9%e5%8c%85)5、连环套压缩包

可以用 fcrackzip 进行爆破或者使用 CTFD 中的脚本爆破

```
import zipfile
import re
file_name = 'pic/' + 'f932f55b83fa493ab024390071020088.zip'
while True:
  try:
     zf = zipfile.ZipFile(file_name)
     re_result = re.search('[0-9]*', zf.namelist()[0])
     passwd = re_result.group()
     zf.extractall(path='pic/', pwd=re_result.group().encode('ascii'))
     file_name = 'pic/' + zf.namelist()[0]
  except:
     print("get the result")
```

### [](#6%e6%9c%aa%e7%9f%a5%e5%90%8e%e7%bc%80%e7%9a%84%e5%8e%8b%e7%bc%a9%e5%8c%85)6、未知后缀的压缩包

可以多用几个压缩软件试试，比如 Winrar 7z

### [](#7%e5%88%86%e5%8d%b7%e5%8e%8b%e7%bc%a9%e5%8c%85%e5%90%88%e5%b9%b6)7、分卷压缩包合并

```
copy /B topic.zip.001 + topic.zip.002+topic.zip.003+topic.zip.004+topic.zip.005+topic.zip.006 topic.zip
```

### [](#8%e5%8e%8b%e7%bc%a9%e5%8c%85%e7%82%b8%e5%bc%b9)8、压缩包炸弹

很小的压缩文件，解压出来会占据巨大的空间，甚至撑爆磁盘

处理方法：010 中直接编辑压缩包文件，看看是否藏有另一个压缩包

### [](#9%e6%a0%b9%e6%8d%ae010%e4%b8%ad%e7%9a%84%e6%a8%a1%e6%9d%bf%e4%bf%ae%e6%94%b9%e4%ba%86%e6%9f%90%e4%ba%9b%e5%8f%82%e6%95%b0)9、根据 010 中的模板修改了某些参数

有些题目可能会修改源数据中压缩包文件中被压缩文件的文件名的长度

源数据中被压缩文件名字的长度对不上也会导致解压后文件无法打开

所以… 010 的模板功能真的非常非常的好用！

![](https://goodlunatic.github.io/posts/1ad9200/imgs/010.png)

### [](#10%e5%8e%8b%e7%bc%a9%e5%8c%85%e5%af%86%e7%a0%81%e6%98%af%e4%b8%8d%e5%8f%af%e8%a7%81%e5%ad%97%e7%ac%a6)10、压缩包密码是不可见字符

#### [](#%e5%ad%97%e8%8a%82%e6%95%b0%e5%be%88%e7%9f%ad%e7%9a%84%e6%83%85%e5%86%b5)字节数很短的情况

直接写个 Python 脚本爆破即可

```
import zipfile
import libnum

def solve():
    # 在ASCII编码中，一个字符占用8位（1字节）
    for i in range(256):
        for j in range(256):
            fz = zipfile.ZipFile('secret key.zip', 'r')
            password = libnum.n2s(i) + libnum.n2s(j)
            print(f"[+]正在尝试密码{password}")
            try:
                fz.extractall(pwd=password)
                fz.close()
                return password
            except:
                fz.close()
                continue
    return None

if __name__ == "__main__":
    password = solve()
    if password:
        print(f"[+]压缩包解压成功,密码是{password}")
    else:
        print(f"[+]在该范围内找不到压缩包密码，压缩包解压失败")
```

#### [](#%e5%ad%97%e8%8a%82%e6%95%b0%e8%be%83%e9%95%bf%e7%9a%84%e6%83%85%e5%86%b5)字节数较长的情况

需要先把密码 base64 编码一下，然后再 base64 解码成 byte 类型作为密码

```
import base64
import pyzipper

target_zip = '1.zip'
outfile = './solved'

pwd = base64.b64decode(b'aEXigItjVOKAjEbigI8=')
# b'hE\xe2\x80\x8bcT\xe2\x80\x8cF\xe2\x80\x8f'
with pyzipper.AESZipFile(target_zip, 'r') as f:
    f.pwd = pwd
    f.extractall(outfile)
```

[](#misc%e8%a7%86%e9%a2%91%e9%a2%98%e6%80%9d%e8%b7%af)Misc——视频题思路：
------------------------------------------------------------------

1、可能有音频隐写，用 mkvtool 分离出音频，再拉入 Au 看频谱图

2、可能是视频中的每一帧图片都有 LSB 隐写（2023 WMCTF）

3、循环读取视频每一帧图像中指定列的指定像素（2023 极客大挑战）

```
import cv2
from PIL import Image

# 创建一个视频读取对象，读取名为'kira.mp4'的视频文件。
video = cv2.VideoCapture('kira.mp4')  # type: ignore

# # 设置要提取的帧数，如现在指定的是第100帧
# video.set(cv2.CAP_PROP_POS_FRAMES, 100)
# # 读取视频的指定帧
# ret, frame = video.read()
# # 保存提取的帧为图像文件
# cv2.imwrite('1.png', frame)
# # 释放视频对象
# video.release()

# 定义视频的尺寸为1920x1080
video_size = [1920, 1080]
# 设置起始像素为5
start_pixel = 5
# 设置每个像素块的大小为10
size = 10
# 创建一个新的图像对象，大小为视频尺寸除以像素块大小，即原视频的帧的抽样结果
out = Image.new('RGB', (video_size[0] // size, video_size[1]//size))
# 初始化帧率计数为0
fps_count = 0
# 循环读取每一帧图像中指定列的指定像素
while True:
    print(f"[+] 当前正在读取视频的第{fps_count}帧")
    # 从视频文件中读取一帧，success为是否成功读取帧的结果，frame为读取的帧
    success, frame = video.read()
    # 如果读取失败，跳出循环
    if not success:
        print(f"[X] 视频的第{fps_count}帧读取失败")
        break
    # 对每一行像素进行遍历，从视频的高度减去起始像素并除以像素块大小，得到需要遍历的行数
    for y in range((video_size[1]-start_pixel)//size):
        try:
            # 从当前行中获取一个像素，使用getpixel方法获取指定坐标处的像素，并将其转换为PIL图像格式
            pixel = Image.fromarray(frame).getpixel(
                (start_pixel+fps_count*size, start_pixel+y*size))
            # 将获取的像素值设置为抽样图像的对应像素位置的值
            out.putpixel((fps_count, y), pixel)
        except:
            pass
    # 帧率计数加1，准备下一帧的处理
    fps_count += 1

# 将抽样图像保存为'out.png'文件
out.save('out.png')
out.show()
```

4、DeEgger Embedder 隐写

可以直接使用 DeEgger Embedder 工具 extract files

例题 - 攻防世界 PyHaHa

[](#misc%e9%9f%b3%e9%a2%91%e9%a2%98%e6%80%9d%e8%b7%af)Misc——音频题思路：
------------------------------------------------------------------

### [](#1%e6%b3%a2%e5%bd%a2%e5%9b%be%e5%88%86%e6%9e%90%e6%91%a9%e6%96%af%e7%94%b5%e7%a0%81)1、波形图分析：摩斯电码

### [](#2%e9%a2%91%e8%b0%b1%e5%9b%be%e5%88%86%e6%9e%90%e6%9c%89%e6%97%b6%e8%a6%81%e8%b0%83%e9%ab%98%e6%9c%80%e9%ab%98%e9%a2%91%e7%8e%87)2、频谱图分析 (有时要调高最高频率)：

### [](#3lsb%e6%9c%80%e4%bd%8e%e6%9c%89%e6%95%88%e4%bd%8d%e9%9a%90%e5%86%99%e7%94%a8silenteye%e8%a7%a3%e5%af%86)3、LSB(最低有效位隐写)：用 silenteye 解密

### [](#4sstv%e6%85%a2%e6%89%ab%e6%8f%8f%e7%94%b5%e8%a7%86)4、SSTV 慢扫描电视：

**SSTV 识别可以直接用这个项目里的脚本：https://github.com/colaclanth/sstv**

#### [](#windows%e4%b8%ad%e4%bd%bf%e7%94%a8rx-sstv)Windows 中使用 RX-SSTV

使用前还要安装虚拟声卡 Virtual Audio Cable

```
#使用步骤:
1.点击Setup-Sound Control and Devices将默认输入设备和输出设备都设置为虚拟声卡line1
2.用VLC播放音频（最好不要用Au播放）
3.如果扫描出来的图片有错位，可以点击slant手动修改
4.退出RX-SSTV前要注意把默认的输入/输出设备改回原来的参数
```

#### [](#%e6%8b%89%e5%85%a5kali%e7%94%a8qsstv%e6%9c%89%e6%97%b6%e5%80%99%e8%a6%81%e7%94%a8%e5%88%b0%e5%8f%8d%e5%90%91%e5%92%8c%e5%8f%8d%e7%9b%b8)拉入 kali 用 qsstv（有时候要用到反向和反相）

### [](#5%e7%94%b5%e8%af%9d%e9%9f%b3%e5%88%86%e6%9e%90)5、电话音分析

用在线网站: http://www.dialabc.com/sound/detect/

或者在 dtmf2num.exe 里使用 dtmf2num -o C:\Desktop\1.wav 命令

### [](#6-wavriff%e7%9a%84%e9%9a%90%e5%86%99%e6%9c%89-deepsound-%e5%92%8c-silenteye-%e6%88%96%e8%80%85%e5%85%b6%e4%bb%96)6、 WAV[RIFF] 的隐写 (有 deepsound 和 silenteye 或者其他):

先用 deepsound 试一下，如果需要密码说明就是 deepsound 隐写

如果是 deepsound 隐写，就先用脚本获取 wav 文件的哈希值 (注释里有使用方法)，

然后拉入 kali 用 john 爆破 hash(如果编码有误，可以先用 notepad 另存为一下)

执行：john 1.txt

### [](#7wav%e5%8f%af%e8%83%bd%e6%98%af%e4%b8%9a%e4%bd%99%e6%97%a0%e7%ba%bf%e7%94%b5%e6%96%87%e4%bb%b6)7、wav 可能是业余无线电文件：

先用 sox 把 wav 转为 raw：

sox -t wav latlong.wav -esigned-integer -b16 -r 22050 -t raw latlong.raw

再用 multimon-ng 分析:

multimon-ng -t raw -a AFSK1200 latlong.raw

### [](#8steghide)8、steghide

```
#如果密码已经知道了
steghide extract -sf filename -p passwd
```

在 WSL 或者 kali 里用 Stegseek 跑（字典在 wordlist 里）

```
#如果密码未知
可以用下面这个脚本爆破
#bruteStegHide.sh
#!/bin/bash

for line in `cat $2`;do
    steghide extract -sf $1 -p $line > /dev/null 2>&1
    if [[ $? -eq 0 ]];then
        echo 'password is: '$line
        exit
    fi
done
```

```
#或者在WSL或者kali里用Stegseek跑（字典在wordlist里）
stegseek filename rockyou.txt
```

### [](#9mp3%e9%9f%b3%e9%a2%91%e9%9a%90%e5%86%99)9、MP3 音频隐写

#### [](#mp3stego)MP3stego

使用前需要先把要处理的文件放到 MP3stego 目录下

```
#Encode
encode -E data.txt -P pass sound.wav sound.mp3    
data.txt里面放要隐写的txt信息 pass是解密时需要的密码
#Decode
decode -X -P pass sound.mp3   
-X 是提取出隐写的文件
pass是解密时需要的密码 
sound.mp3是待处理的MP3文件
```

### [](#10wav%e8%bf%98%e5%8f%af%e8%83%bd%e6%98%afopenpuff%e9%9a%90%e5%86%99%e6%9c%89%e5%af%86%e7%a0%81)10、WAV 还可能是 OpenPuff 隐写（有密码）

直接用 OpenPuff.exe 解密即可

### [](#11%e6%8f%90%e5%8f%96%e5%b9%b6%e5%88%86%e6%9e%90%e5%b7%a6%e5%8f%b3%e5%a3%b0%e9%81%93%e7%9a%84%e5%b7%ae%e5%80%bc)11、提取并分析左右声道的差值

```
# 导入模块wavfile
import scipy.io.wavfile as wavfile
# 读取音频文件的采样率和数据
sample_rate, data = wavfile.read("1.wav")
# print(sample_rate, data)
# 创建两个列表来存储左右两声道的数据
left = []
right = []

for item in data:
    # print(item)
    # 第一列的数据是左声道，第二列是右声道
    left.append(item[0])
    right.append(item[1])

diff = [str(left-right) for left, right in zip(left, right)]
res = ''
for item in diff:
    if item == '2':
        res += '1'
    elif item == '1':
        res += '0'
    else:
        continue
with open('res.txt', 'w') as f:
    f.write(res)
```

### [](#12%e4%bd%bf%e7%94%a8%e8%84%9a%e6%9c%ac%e6%8f%90%e5%8f%96%e6%95%b0%e6%8d%ae%e8%bf%9b%e8%a1%8c%e5%88%86%e6%9e%90)12、使用脚本提取数据进行分析

```
# 2023 DASCTFxCBCTF
import numpy as np
import wave
import scipy.fftpack as fftpack

SAMPLE_RATE = 44100 # 表示采样率，即每秒钟有多少采样点
SAMPLE_TIME = 0.1 # 表示一个样本的时间，即0.1秒
SAMPLE_NUM = int(SAMPLE_RATE * SAMPLE_TIME) # 计算在SAMPLE_TIME时间内的采样点数
LIST = [800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700]   


def get_len():
    with wave.open('1.wav','rb') as f:
        # 使用numpy从音频文件中读取所有的帧并将其转换为int16数据类型的数组
        wav_data = np.frombuffer(f.readframes(-1),dtype=np.int16)
        N = len(wav_data)
        print(N)
    #这实际上计算了wav文件的总时长（以0.1秒为单位）
    a = (N/(44100*0.1)) / 189
    print(a)

# 傅立叶变换函数。给定时域数据，该函数返回其频域形式的前半部分
def fft(data):
    N = len(data)                                   #获取数据长度
    fft_data = fftpack.fft(data)                    #得到频域信号                      
    abs_fft = np.abs(fft_data)                      #计算幅值    
    abs_fft = abs_fft/(N/2)                             
    half_fft = abs_fft[range(N//2)]                 #取频域信号的前半部分

    return half_fft

# 此函数旨在解码100ms的音频数据。它首先对音频数据进行FFT变换，然后检查LIST中的每个频率，以确定哪些频率具有明显的活动（幅值大于0.8）  
def dec_100ms(wave_data_100_ms):
    fft_ret = fft(wave_data_100_ms)
    for index, freq in enumerate(LIST):
        if np.max(fft_ret[int(freq*SAMPLE_TIME) - 2 : int(freq*SAMPLE_TIME) + 2]) > 0.8:
            print(freq, 'Hz有值',end=" ")
            return index

# 解码整个音频文件中的句子。它首先确定音频中有多少个100ms的段，然后每次解码两个段来生成一个两位数的索引，该索引用于查找与之对应的字符
def dec_sentence(wav_data):
    _100ms_count = len(wav_data) // SAMPLE_NUM    
    # print(_100ms_count) 
    print('待解码音频包含', _100ms_count // 2, '个字')    
    ret = ''
    for i in range(0, _100ms_count, 2):              
        index = 0
        for k in range(2):
            index = index*10 + dec_100ms(wav_data[i*SAMPLE_NUM + k*SAMPLE_NUM : i*SAMPLE_NUM + (k+1)*SAMPLE_NUM])
        print('序号:', index)
        ret += string[index]
    return ret

if __name__ == '__main__':
    # get_len()
    # 题目给了一个字符串序列，所以就是从音频中提取出index，然后根据index找到对应的字符
    string ="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_}{-?!"
    with wave.open('1.wav', 'rb') as f:          #读取为数组
        wav_data = np.frombuffer(f.readframes(-1), dtype=np.int16)
    print(dec_sentence(wav_data))
    # DASCTF{Wh1stling_t0_Convey_informat1on!!!}
```

### [](#13stegpy%e9%9a%90%e5%86%99)13、stegpy 隐写

[stegpy 开源地址](https://github.com/izcoser/stegpy) 下载好后直接用 WSL 输入以下命令并输入密码解密即可

也可以直接用 pip 安装： pip3 install stegpy

### [](#14deegger-embedder%e9%9a%90%e5%86%99)14、DeEgger Embedder 隐写

可以直接使用 DeEgger Embedder 工具 extract files

### [](#15silenteye%e9%9a%90%e5%86%99)15、Silenteye 隐写

音频文件也可能是 silenteye 隐写，可以拿默认密码 silenteye 解密试试看

[](#misc%e5%8f%96%e8%af%81%e9%a2%98%e6%80%9d%e8%b7%af)Misc——取证题思路：
------------------------------------------------------------------

详解请查看我的另一篇 博客 Misc——取证类题目详解

[](#git%e6%96%87%e4%bb%b6%e6%b3%84%e9%9c%b2)Git 文件泄露：
-----------------------------------------------------

1、利用命令 git stash show 显示做了哪些改动

2、利用命令 git stash apply 导出改动之前的文件

[](#osint)OSINT
---------------

### [](#1%e7%94%a8yandex%e8%af%86%e5%9b%be)1. 用 yandex 识图

[](#others)Others：
------------------

### [](#%e5%ad%97%e8%8a%82%e5%ba%8f)字节序

**字节的排列方式有两个通用规则:**

```
大端序（Big-Endian）将数据的低位字节存放在内存的高位地址，高位字节存放在低位地址。这种排列方式与数据用字节表示时的书写顺序一致，符合人类的阅读习惯。
小端序（Little-Endian），将一个多位数的低位放在较小的地址处，高位放在较大的地址处，则称小端序。小端序与人类的阅读习惯相反，但更符合计算机读取内存的方式，因为CPU读取内存中的数据时，是从低地址向高地址方向进行读取的。
```

**例子：**

```
整型数值168496141 需要4个字节
对应的16进制表示是0X0A0B0C0D
大端序：
0x0A 0x0B 0x0C 0x0D
小端序：
0x0D 0x0C 0xB 0xA
```

### [](#%e4%b8%ba%e4%bd%95%e8%a6%81%e6%9c%89%e5%ad%97%e8%8a%82%e5%ba%8f)为何要有字节序

```
因为计算机电路先处理低位字节，效率比较高，因为计算都是从低位开始的。所以，计算机的内部处理都是小端字节序。在计算机内部，小端序被广泛应用于现代 CPU 内部存储数据；而在其他场景，比如网络传输和文件存储则使用大端序。
```

**使用 Python 中的 struct 模块来处理大小端序**

```
import struct

def display_binary(data):
    #将字节数据转化为十六进制表示形式
    # return ' '.join(['{:02x}'.format(byte) for byte in data])
    return ' '.join([f"{byte:02x}" for byte in data])

# 定义要打包的数据
int_data = 10240099
float_data = 123.456

# 使用默认端序（小端序）打包
packed_int_little = struct.pack('I', int_data)
packed_float_little = struct.pack('f', float_data)

# 使用大端序打包
packed_int_big = struct.pack('>I', int_data)
packed_float_big = struct.pack('>f', float_data)

# 打印打包的结果,display_binary()是以十六进制的形式显示
print("Packed data (Little Endian):")
print(packed_int_little)
print("Int:", display_binary(packed_int_little))
print(packed_float_little)
print("Float:", display_binary(packed_float_little))

print("\nPacked data (Big Endian):")
print(packed_int_big)
print("Int:", display_binary(packed_int_big))
print(packed_float_big)
print("Float:", display_binary(packed_float_big))

# 解包数据,由于返回的是一个元组，所以需要[0]
unpacked_int_little = struct.unpack('I', packed_int_little)[0]
unpacked_float_little = struct.unpack('f', packed_float_little)[0]

unpacked_int_big = struct.unpack('>I', packed_int_big)[0]
unpacked_float_big = struct.unpack('>f', packed_float_big)[0]

# 打印解包的结果
print("\nUnpacked data (Little Endian):")
print("Int:", unpacked_int_little)
print("Float:", unpacked_float_little)

print("\nUnpacked data (Big Endian):")
print("Int:", unpacked_int_big)
print("Float:", unpacked_float_big)

# 验证打包和解包是否保持数据的完整性(float类型的数据先打包再解包后可能会有误差)
assert int_data == unpacked_int_little
# assert float_data == unpacked_float_little

assert int_data == unpacked_int_big
# assert float_data == unpacked_float_big

print("\nData integrity maintained!")
```

**十六进制数据大小端序转换**

```
hex_data = """0x00006c66 0x00006761 0x0000617b 0x00006168 0x00005f21 0x00006f79 0x00005f75 0x00006f66 0x00006e75 0x00005f64 0x00007469 0x00007d21 0x00000000 """

def swap_endianness(hex_string):
    hex_bytes = bytes.fromhex(hex_string[2:])
    # 直接使用 bytes 类型的数据翻转即可
    swapped_bytes = hex_bytes[::-1]
    swapped_hex = swapped_bytes.hex()
    swapped_hex = '0x' + swapped_hex
    return swapped_hex


def solved():
    flag = ""
    # hex_data = input("请输入待转换的数据\n")
    hex_list = hex_data.split()
    for hex_num in hex_list:
        swapped_hex = swap_endianness(hex_num)
        print(swapped_hex)
        flag += bytes.fromhex(swapped_hex[2:]).decode()
    print(flag)


if __name__ == "__main__":
    solved()
```

### [](#linux-tar%e5%91%bd%e4%bb%a4)Linux tar 命令

### [](#%e6%89%93%e5%8c%85%e5%8e%8b%e7%bc%a9)打包压缩

```
#打包单独的文件
tar -cvf target.tar filename.txt
#打包整个目录
tar -cvf target.tar directory
#-c 表示创建新的tar包
#-v 表示显示详细信息
#-f 表示指定目标文件名
```

### [](#%e8%a7%a3%e5%8e%8b%e6%8f%90%e5%8f%96)解压提取

```
#把压缩包中的所有文件解压到当前目录
tar -xvf target.tar
#把压缩包解压到指定目录
tar -xvf target.tar -C path
```

### [](#%e4%b8%8d%e5%90%8c%e7%9a%84%e9%94%ae%e7%9b%98%e5%b8%83%e5%b1%80)不同的键盘布局

Qwerty、Qwertz、Azerty

Dvorak

Colemak

例题 - 2023 台州市赛初赛 Black Mamba
