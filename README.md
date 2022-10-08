# leakfinder

1、新增响应包中手机号、身份证号码等敏感信息正则匹配

2、新增多级敏感目录扫描：springboot未授权、swagger未授权、druid未授权等

3、新增POST请求方式（Content-Type：application/json）

命令：python3 leakfinder.py -f url.txt -ol leakinfo.txt

![image](https://user-images.githubusercontent.com/47935274/194695677-13ebf502-99c1-48ba-a559-c527581e7e2e.png)



参考

https://github.com/p1g3/JSINFO-SCAN

https://github.com/Threezh1/JSFinder
