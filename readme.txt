简单的 RSA + MD5 数字签名测试程序

c 程序用到了 openssl 库，源代码在 msys2 环境下可以用 gcc 直接编译
编译方法：gcc rsatest.c -lcrypto

java 程序用到了 commons-codec-1.11.jar 这个库，编译和运行时需要加到 classpath 中去

