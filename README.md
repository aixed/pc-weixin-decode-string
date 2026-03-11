使用方法：
ida 加载 Weixin.dll 对应版本必须是 4.1.5.30
然后 ait+F7 执行python脚本
会自动重命名加密符号 此操作会修改 .rdata 区段内容


x64dbg 中加载：
手动在ida中导出 dif 文件 x64dbg 加载 dif  导出 .1337 补丁文件，
分析时重新打开 x64dbg直接 加载 .1337补丁文件 即可

