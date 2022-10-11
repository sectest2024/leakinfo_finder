# 批量扫描JS文件中接口的脚本

1、新增响应包中手机号、身份证号码等敏感信息正则匹配

2、新增多级敏感目录扫描：springboot未授权、swagger未授权、druid未授权等

3、新增POST请求方式（Content-Type：application/json）

命令：python3 leakinfo_finder.py -f url.txt -ol leakinfo.txt
![image](https://user-images.githubusercontent.com/47935274/194975640-4a1c8012-76f0-4319-8766-9df8497f7fc6.png)

![image](https://user-images.githubusercontent.com/47935274/194695775-4143c47a-0035-48fa-9550-503aae6271cd.png)



参考

https://github.com/p1g3/JSINFO-SCAN

https://github.com/Threezh1/JSFinder
