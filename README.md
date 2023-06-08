<!--
 * @Author: zhzhou33
 * @Date: 2023-06-08 18:42:24
 * @LastEditors: zhzhou33
 * @LastEditTime: 2023-06-08 18:42:25
-->
+ 该项目为CMAKE项目，使用前在build目录(若有)分别执行

  + cmake ..
  + cmake --build .

  生成二进制文件运行即可，需要注意的是，该代码原始环境是在linux+vscode+cmake插件下运行，因此需要修改main.cpp文件中的保存/加载文件路径，方可正常运行
  
  同时，该环签名算法基于Openssl库，因此运行前需要下载该第三方库**https://www.openssl.org**
  
  最后根据具体库路径配置CMakeLists.txt即可。
  
+ git项目开源地址https://github.com/zhzhou33/RSign