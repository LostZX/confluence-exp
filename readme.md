# confluence

## 已定义的功能

* 暂时支持cve-2021-26085 和 cve-2022-26134,
* CVE_2023_22515，CVE-2023-22527 过年再看下

支持直接写入冰蝎、哥斯拉内存马

支持不写shell直接获取管理员cookie、添加管理员

支持执行自定义字节码

## 用法

例： java -jar confluence-exp.jar -u http://127.0.0.1:8090/ -a godzilla -c cve-2021-26085

-a 可选 behinder,godzilla,custom,addAdmin,getCookie

-c cve-2021-26085, cve-2022-26134, 2023(还没看，看完写)

自定义字节码指定 -i 字节码文件路径  -cl 字节码的class


![img_2.png](img/img_2.png)

增加cookie登录

![img_3.png](img/img_3.png)

新增管理员

![img_4.png](img/img_4.png)

adnim/admin@qax.com

![img_5.png](img/img_5.png)

打入哥斯拉

![img_6.png](img/img_6.png)

![img_7.png](img/img_7.png)

打入冰蝎

![img_9.png](img/img_9.png)

![img_8.png](img/img_8.png)


## 自定义字节码

注入一个suo，首先用jmg生成一个suo的filter字节码

![img.png](img/img.png)

-i 文件路径  -cl 指定 `注入器类名`

![img_1.png](img/img_1.png)

还可以有其他玩法，比如添加用户和获取cookie的实现就是先打入一个方法类到内存，在反射调用，可参考PostConfluence实现



