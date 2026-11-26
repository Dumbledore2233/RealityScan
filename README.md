# RealityScan
自用VPS扫描Reality域名脚本  
脚本需要python3，可以检测安装

## 一键安装
```shell
wget -O hy2.sh \
  https://raw.githubusercontent.com/Dumbledore2233/RealityScan/refs/heads/main/rs.sh \
  && sh rs.sh
```

## 参数说明
默认参数为 -port 443 -thread 100 -timeout 5，如需调整可直接传环境变量：
```shell
PORT=8443 THREAD=200 TIMEOUT=3 ./rs.sh
```

## 参考文章
https://www.aspchang.com/posts/reality-steal-domain/
