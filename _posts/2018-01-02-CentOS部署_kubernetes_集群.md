---
layout: post
title: CentOS部署 kubernetes 集群
date: 2018-01-02 
tag: kubernetes

---
## CentOS部署 kubernetes 集群
kubernetes部署有几种方式：kubeadm、minikube 和二进制包，前两者属于自动部署，简化部署操作，自动部署屏蔽了很多细节，使得对各个模块的感知很少，不利于新手学习。所以采用二进制方式安装部署 kubernetes 集群。通过二进制部署集群群，你将理解系统各组件的交互原理，进而能快速解决实际问题。
### 1. 基础环境
- OS：CentOS Linux release 7.3.1611 (Core)  Linux 3.10.0-514.el7.x86_64
- Kubernetes：1.8.3
- Docker：Docker version 17.12.0-ce-rc3
- Etcd：3.1.5
- Flannel：0.7.1
- TLS 认证通信（所有组件，如 etcd、kubernetes master 和 node）
- RBAC 授权
- kubelet TLS BootStrapping
- kubedns、dashboard、heapster(influxdb、grafana)、EFK(elasticsearch、fluentd、kibana) 集群插件

本次搭建使用三台服务器做实验，角色分配如下：
**Master**：192.168.5.78
**Node**：192.168.5.78、192.168.5.79、192.168.5.80
>**192.168.5.78 这台主机 master 和 node 复用。所有生成证书、执行 kubectl 命令的操作都在这台节点上执行。一旦 node 加入到 kubernetes 集群之后就不需要再登陆 node 节点了。**</font>

### 2. 安装过程
#### 2.1 创建 TLS 证书和秘钥
Kubernetes 系统的各个组件需要使用TLS证书对通信进行加密，本文档使用 CloudFlare 的 PKI 工具集 cfssl 来生成 Certificate Authority（CA）和其他证书；
**生成的 CA 证书和秘钥文件如下：**
- ca-key.pem
- ca.pem
- kubernetes-key.pem
- kubernetes.pem
- kube-proxy.pem
- kube-proxy-key.pem
- admin.pem
- admin-key.pem
**使用证书的组件如下：**
- etcd：使用 ca.pem、kubernetes-key.pem、kubernetes.pem
- kube-apiserver：使用 ca.pem、kubernetes-key.pem、kubernetes.pem
- kubelet：使用 ca.pem
- kube-proxy：使用 ca.pem、kube-proxy-key.pem、kube-proxy.pem
- kubectl：使用 ca.pem、admin-key.pem、admin.pem
- kube-controller-manager：使用 ca-key.pem、ca.pem

>**注意：以下操作都在 master 节点及 192.168.5.78 这台主机上执行，证书只需要创建一次即可，以后再向集群中添加节点时只要将 /etc/kubernetes/ 目录下的证书拷贝到新节点上即可。**</font>
##### 2.1.1 安装 CFSSL
```shell
# mkdir /usr/local/bin && cd /usr/local/bin
# wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -O cfssljson
# wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -O cfssl
# wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64 -O cfssl-certinfo
# chmod +x *
# echo "export PATH=/usr/local/bin:$PATH" >> /etc/profile
```
##### 2.1.2 创建 CA（Certificate Authority）
**创建 CA 配置文件**
```shell
# mkdir /root/ssl && cd /root/ssl
# cfssl print-defaults config > config.json
# cfssl print-defaults csr > csr.json
# 根据config.json文件的格式创建如下的ca-config.json文件
# 过期时间设置成了87600h
# vim ca-config.json 
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "87600h"
      }
    }
  }
}

```
**字段说明**
- ca-config.json：可以定义多个 profiles，分别制定不同的过期时间、使用场景等参数；后续签名证书是使用某个 profile；
- signing：表示改正数可用于签名其他证书；生成的 ca.pem 证书中 CA=TRUE；
- server auth：表示 client 可以使用该 CA 对 server 提供的证书进行验证；
- client auth：表示 server 可以使用该 CA 对 client 提供的证书进行验证；

**创建 CA 证书签名请求**
创建 ca-csr.json 文件，内容如下：
```shell
# vim  ca-csr.json
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
```
- "host"：值是证书有效的域名列表，
- "CN"：值是一些 ca 用来确定哪些域生成证书，如果提供 "www" 域名，这些 CA 将经常为 "www（例如 www.example.net）" 和 "bare"（例如 example.net）域名提供证书。kube-apiserver 从证书中提取该字段作为请求的用户名（User name ）；浏览器使用该字段验证网站是否合法；
- "key"：示例中的值是大多数 CA 支持的默认值。（在这种情况下甚至可以省略；这里显示是为了完整性）
- "C": country。国家。
- "L": locality or municipality (such as city or town name)。地点或城市（例如城市或城镇名字）
- "O": organisation。组织、机构、团体、安排。kube-apiserver 从证书中提取该字段作为请求用户所属的组（Group）
- "OU": organisational unit, such as the department responsible for owning the key; it can also be used for a "Doing Business As" (DBS) name。组织单位，例如部门负责所属的 key；它也可以用于 “Doing Business As”（DBS）名称。
- "ST": the state or province。州或省

**生成 CA 证书和私钥**
```shell
# cfssl gencert -initca ca-csr.json |cfssljson -bare ca -
# ls ca*
ca-config.json  ca.csr  ca-csr.json  ca-key.pem  ca.pem
```
##### 2.1.3 创建 kubernetes 证书
创建 kubernetes 证书签名请求文件 kubernetes-csr.json
```shell
# vim kubernetes-csr.json
{
    "CN": "kubernetes",
    "hosts": [
      "127.0.0.1",
      "192.168.5.78",
      "192.168.5.79",
      "192.168.5.80",
      "10.254.0.1",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "BeiJing",
            "L": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
```
如果 hosts 字段不为空则需要指定授权使用该证书的 **IP 或域名列表**，由于该证书后续被 etcd 集群和 kubernetes master 集群使用，所以上面分别指定了 etcd 集群、kubernetes master集群的主机 IP 和 kubernetes**服务的服务IP**（一般是 kube-apiserver 指定的 service-cluster-ip-range 网段的第一个IP，如10.254.0.1。）
hosts 中的内容可以为空，即使按照上面的配置，向集群中增加新节点后也不需要重新生成证书。

**生成 kubernetes 证书和私钥**
```shell
# cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes
# ls kubernetes*
kubernetes.csr  kubernetes-csr.json  kubernetes-key.pem  kubernetes.pem
```
##### 2.1.4 创建 admin 证书
创建 admin 证书签名请求文件 admin-csr.json
```shell
# vim admin-csr.json
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
```
后续 kube-apiserver 使用 RBAC 对客户端（如 kubelet、kube-proxy、Pod）请求进行授权；kube-apiserver 预定义了一些 RBAC 使用的 RoleBindings，如 cluster-admin 将 Group system:master 与 Role cluster-admin 绑定，该 Role 授予了调用 kube-apiserver 的**所有 API** 的权限；
OU 指定该证书的 Group 为 system:master，kubelet 使用该证书访问 kube-apiserver 时，由于证书被CA签名，所以认证通过，同事由于证书组为经过预授权的 system:master，所以被授权予访问所有API的权限；

**生成 admin 证书和私钥**
```shell
# cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
# ls admin*
admin.csr  admin-csr.json  admin-key.pem  admin.pem
```
##### 2.1.5 创建kube-proxy证书
创建 kube-proxy 证书签名请求文件 kube-proxy-csr.json：
```shell
# vim kube-proxy-csr.json
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
```
CN 指定该证书的 User 为 system:kube-proxy；kube-apiserver 预定义的 RoleBinding cluster-admin 将 User system:kube-proxy 与 Role system:node-proxy 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；

**生成 kube-proxy 客户端证书和私钥**
```shell
# cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes  kube-proxy-csr.json | cfssljson -bare kube-proxy
# ls kube-proxy*
kube-proxy.csr  kube-proxy-csr.json  kube-proxy-key.pem  kube-proxy.pem
```
##### 2.1.6 校验证书
以 kubernetes 证书为例
**使用 openssl 命令**
```shell
# openssl x509  -noout -text -in  kubernetes.pem
...
  Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=CN, ST=BeiJing, L=BeiJing, O=k8s, OU=System, CN=kubernetes
        Validity
            Not Before: Dec 19 06:07:00 2017 GMT
            Not After : Dec 17 06:07:00 2027 GMT
        Subject: C=CN, ST=BeiJing, L=BeiJing, O=k8s, OU=System, CN=kubernetes
        Subject Public Key Info:
...
    X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                18:94:FF:F5:CA:F9:17:8B:FF:D3:DC:74:F4:5E:F5:2A:4E:6A:4D:A2
            X509v3 Authority Key Identifier: 
                keyid:37:3A:28:3D:04:4E:2E:05:E5:B8:72:AA:E5:CF:66:99:88:E6:29:32

            X509v3 Subject Alternative Name: 
                DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:192.168.5.78, IP Address:192.168.5.79, IP Address:192.168.5.80, IP Address:10.254.0.1
...
```
确认 Issuer 字段的内容和 ca-csr.json一致；
确认 Subject 字段的内容和 kubernetes-csr.json一致；
确认 X509v3 Subject Alternative Name 字段的内容和 kubernetes-csr.jaon一致；
确认 X509v3 Key Usage、Extended Key Usage 字段内容和 ca-config.json 中 kubernetes profile 一致；
**使用 cfsslinfo 命令**
```sehll
# cfssl-certinfo -cert kubernetes.pem
{
  "subject": {
    "common_name": "kubernetes",
    "country": "CN",
    "organization": "k8s",
    "organizational_unit": "System",
    "locality": "BeiJing",
    "province": "BeiJing",
    "names": [
      "CN",
      "BeiJing",
      "BeiJing",
      "k8s",
      "System",
      "kubernetes"
    ]
  },
  "issuer": {
    "common_name": "kubernetes",
    "country": "CN",
    "organization": "k8s",
    "organizational_unit": "System",
    "locality": "BeiJing",
    "province": "BeiJing",
    "names": [
      "CN",
      "BeiJing",
      "BeiJing",
      "k8s",
      "System",
      "kubernetes"
    ]
  },
  "serial_number": "638164930512996746561192862141892498684937602690",
  "sans": [
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local",
    "127.0.0.1",
    "192.168.5.78",
    "192.168.5.79",
    "192.168.5.80",
    "10.254.0.1"
  ],
  "not_before": "2017-12-19T06:07:00Z",
  "not_after": "2027-12-17T06:07:00Z",
  "sigalg": "SHA256WithRSA"
...
```
##### 2.1.7 分发证书
将生成的证书和秘钥文件（后缀名为.pem）拷贝到所有机器的 /etc/kubernetes/ssl 目录下备用；
```shell
# mkdir -p /etc/kubernetes/ssl
# cp *.pem /etc/kubernetes/ssl
```

#### 2.2 创建 kubeconfig 文件
先在 master 节点上安装 kubectl 然后再进行后面的操作。kubelet、kube-proxy 等 Node 机器上的进程与 Master 机器的 kube-apiserver 进程通信时需要认证和授权；kubernetes1.4 开始支持由 kube-apiserver 为客户端生成 TLS 证书的 TLS Bootstrapping 功能，这样就不需要为每个客户端生成证书了；该功能**当前仅支持为** kubelet 生成证书。安装 kubectl 后，后面的操作只需要在 master 节点上执行，生成的*.kubeconfig 文件可以直接拷贝到 Node 节点的 /etc/kubernetes 目录下。
##### 2.2.1 创建TLS Bootstrapping Token
Token 可以是任意的包涵 128bit 的字符串，使用安全的随机数发生器生成。
```shell
# export BOOTSTRAP_TOKEN=$(head -c 16 /dev/urandom | od -An -t x | tr -d ' ')
# cat > token.csv <<EOF
${BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF
```
><font color=red>**注意：在进行后续操作前检查 token.csv 文件，确认 ${BOOTSTRAP_TOKEN} 环境变量已经被真实的值替换。**</font>

**BOOTSTRAP_TOKEN** 将被写入到 kube-apiserver 使用的 token.csv 文件和 kubelet 使用的 bootstrap.kubeconfig 文件，如果后续重新生成了 BOOTSTRAP_TOKEN，则需要：更新 token.csv 文件，分发到所有机器 (master 和 node）的 /etc/kubernetes/ 目录下，分发到 Node 节点上非必需；重新生成 bootstrap.kubeconfig 文件，分发到所有 Node 机器的 /etc/kubernetes/ 目录下；重启 kube-apiserver 和 kubelet 进程；重新 approve kubelet 的 csr 请求；
```shell
# cp token.csv /etc/kubernetes/
```
##### 2.2.2 创建 kubelet bootstrapping kubeconfig 文件
执行下面的命令时需要先安装 kubectl 命令：
```shell
# cd /etc/kubernetes
# export KUBE_APISERVER="https://192.168.5.78:6443"
# 设置集群参数
# kubectl config set-cluster kubernetes  --certificate-authority=/etc/kubernetes/ssl/ca.pem  --embed-certs=true  --server=${KUBE_APISERVER}  --kubeconfig=bootstrap.kubeconfig
# kubectl config set-credentials kubelet-bootstrap  --token=${BOOTSTRAP_TOKEN}  --kubeconfig=bootstrap.kubeconfig
# kubectl config set-context default  --cluster=kubernetes  --user=kubelet-bootstrap  --kubeconfig=bootstrap.kubeconfig
# kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
```
参数说明：
- --embed-certs 为 true 时表示将 certificate-autority 证书写入到生成的 bootrap.kubeconfig 文件中。

设置客户端认证参数时没有指定秘钥和证书，后续由 kube-apiserver 自动生成；
##### 2.2.3 创建 kub-proxy kubeconfig 文件
```shell
# kubectl config set-cluster kubernetes  --certificate-authority=/etc/kubernetes/ssl/ca.pem  --embed-certs=true  --server=${KUBE_APISERVER}  --kubeconfig=kube-proxy.kubeconfig
# kubectl config set-credentials kube-proxy  --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem  --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem  --embed-certs=true  --kubeconfig=kube-proxy.kubeconfig
# kubectl config set-context default  --cluster=kubernetes  --user=kube-proxy  --kubeconfig=kube-proxy.kubeconfig
# kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```
设置集群参数和客户端认证参数时 --embed-certs 都为 true，这会将 certificate-authority、client-certificate 和 client-key 指向的证书文件内容写入到生成的 kube-proxy.kubeconfig 文件中；
kube-proxy.pem 证书中 CN 为 system:kube-proxy，kube-apiserver 预定义的 RoleBinding cluster-admin 将 User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；
##### 2.2.4 分发 kubeconfig 文件
将两个 kubeconfig 文件分发到所有 Node 机器的 /etc/kubernetes/ 目录
```shell
# cp bootstrap.kubeconfig kube-proxy.kubeconfig /etc/kubernetes/
```
#### 2.3 创建高可用etcd集群
kubernetes 系统使用 etcd 存储集群所有数据，本文档介绍部署一个三节点高可用 etcd 集群的步骤，这三个节点复用 kubernetes master 机器。
##### 2.3.1 TLS 认证文件
需要 etcd 集群创建加密通信的 TLS 证书，这里复用以前创建的 kubernetes 证书。
```shell
# cp ca.pem kubernetes-key.pem kubernetes.pem /etc/kubernetes/ssl
```
**下载二进制文件**
到 https://github.com/coreos/etcd/releases 页面下载最新版本的二进制文件
```shell
# wget https://github.com/coreos/etcd/releases/download/v3.2.11/etcd-v3.2.11-linux-amd64.tar.gz
# tar xf etcd-v3.2.11-linux-amd64.tar.gz
# mv etcd-v3.2.11-linux-amd64/etcd* /usr/local/bin
```
##### 2.3.2 创建 etcd 的 systemd unit 文件
注意替换 IP 地址为你自己的 etcd 集群的主机 IP。
```shell
# vim /lib/systemd/system/etcd.service
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
Type=notify
WorkingDirectory=/var/lib/etcd/
EnvironmentFile=-/etc/etcd/etcd.conf
ExecStart=/usr/bin/etcd \
  --name=infra1 \
  --cert-file=/etc/kubernetes/ssl/kubernetes.pem \
  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem \
  --peer-cert-file=/etc/kubernetes/ssl/kubernetes.pem \
  --peer-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \
  --trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --peer-trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --initial-advertise-peer-urls=https://192.168.5.78:2380 \
  --listen-peer-urls=https://192.168.5.78:2380 \
  --listen-client-urls=https://192.168.5.78:2379,http://127.0.0.1:2379 \
  --advertise-client-urls=https://192.168.5.78:2379 \
  --initial-cluster-token=etcd-cluster \
  --initial-cluster=infra1=https://192.168.5.78:2380,infra2=https://192.168.5.79:2380,infra3=https://192.168.5.80:2380 \
  --initial-cluster-state=new \
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
指定 etcd 的工作目录为 /var/lib/etcd，数据目录为 /var/lib/etcd，需要启动服务前创建这个目录，否则启动服务的时候会报错 “Failed at step CHDIR spawning /usr/bin/etcd: No such file or directory”；
为了保证通信安全，需要指定 etcd 的公私钥（cert-file和key-file）、Peers 通信的公私钥和 CA 证书（peer-cert-file、peer-key-file、peer-trusted-ca-file）、客户端的 CA 证书（trusted-ca-file）；
创建 kubernetes.pem 证书时使用的 kubernetes-csr.json 文件的 hosts 字段**包含所有 etcd 节点的 IP，**否则证书校验会出错；
- --initial-cluster-state 值为 new 时，--name 的参数值必须位于 --initial-cluster 列表中；

**环境变量配置文件 /etc/etcd/etcd.conf**
```shell
# vim /etc/etcd/etcd.conf
# [member]
ETCD_NAME=infra1
ETCD_DATA_DIR="/var/lib/etcd"
ETCD_LISTEN_PEER_URLS="https://192.168.5.78:2380"
ETCD_LISTEN_CLIENT_URLS="https://192.168.5.78:2379"

#[cluster]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://192.168.5.78:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_ADVERTISE_CLIENT_URLS="https://192.168.5.78:2379"
```
这是 192.168.5.78 节点的配置，其他两个 etcd 节点只要将上面的 IP 地址改成相应节点的 IP 地址即可。ETCD_NAME 换成对应节点的 infra1/2/3。
##### 2.3.3 启动 etcd 服务
```shell
# systemctl daemon-reload
# systemctl start etcd
# systemctl enable etcd
```
在所有的 etcd master 节点重复上面的步骤，直到所有机器的 etcd 服务都已启动。
##### 2.3.4 验证服务
在任一 etcd master 机器上执行如下命令：
```shell
# etcdctl  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem  cluster-health
member a3c852add53cbc12 is healthy: got healthy result from https://192.168.5.78:2379
member c993f1bbd44bad6a is healthy: got healthy result from https://192.168.5.79:2379
member f24bb405f1810f35 is healthy: got healthy result from https://192.168.5.80:2379
cluster is healthy
```
结果最后一行为 cluster is healthy 时表示集群服务正常。
#### 2.4 安装 kubectl 命令行工具
##### 2.4.1 下载 kubectl 
```shell
# cd /software
# wget https://dl.k8s.io/v1.8.4/kubernetes-server-linux-amd64.tar.gz
# tar -xf kubernetes-server-linux-amd64.tar.gz
# cp kubernetes/server/bin/kube* /usr/bin/
```
##### 2.4.2 创建 kubelet config 文件
```shell
# export KUBE_APISERVER="https://192.168.5.78:6443"
# kubectl config set-cluster kubernetes  --certificate-authority=/etc/kubernetes/ssl/ca.pem  --embed-certs=true  --server=${KUBE_APISERVER}
# kubectl config set-credentials admin  --client-certificate=/etc/kubernetes/ssl/admin.pem  --embed-certs=true  --client-key=/etc/kubernetes/ssl/admin-key.pem
# kubectl config set-context kubernetes  --cluster=kubernetes  --user=admin
# kubectl config use-context kubernetes
```
admin.pem 证书 OU 字段值为 system:master，kube-apiserver 预定义的 RolieBinding cluster-admin 将 Group system:master 与 Role cluster-admin 绑定，该 Role 授予了调用 kube-apiserver 相关 API 的权限；生成的 kubeconfig 被保存到 ~/.kube/config 文件；
><font color=red>**~/.kube/config 文件拥有对该集群的最高权限，请妥善保管。**</font>
#### 2.5 部署master节点
kubernetes master 节点包含的组件：
- kube-apiserver
- kube-scheduler
- kube-controller-manager

kube-scheduler、kube-controller-manager 和 kube-apiserver 三者的功能紧密相关；同时只能有一个 kube-secheduler、kube-controller-manager 进程处于工作状态，如果运行多个，则需要通过选举产生一个 leader。

##### 2.5.1 下载二进制文件 
安装 kubectl 时所有的二进制包已经都下载好了，也已经复制到相应路径，在这里直接使用就好。
##### 2.5.2 配置和启动 kube-apiserver 
**创建 kube-apiserver 的 service 配置文件**
```shell
# vim /lib/systemd/system/kube-apiserver.service 
[Unit]
Description=Kubernetes API Service
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
After=etcd.service

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/apiserver
ExecStart=/usr/local/bin/kube-apiserver \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBE_ETCD_SERVERS \
        $KUBE_API_ADDRESS \
        $KUBE_API_PORT \
        $KUBELET_PORT \
        $KUBE_ALLOW_PRIV \
        $KUBE_SERVICE_ADDRESSES \
        $KUBE_ADMISSION_CONTROL \
        $KUBE_API_ARGS
Restart=on-failure
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
**/etc/kubernetes/config**
```shell
# vim /etc/kubernetes/config
###
# kubernetes system config
#
# The following values are used to configure various aspects of all
# kubernetes services, including
#
#  kube-apiserver.service
#  kube-controller-manager.service
#  kube-scheduler.service
#  kubelet.service
#  kube-proxy.service
# logging to stderr means we get it in the systemd journal
KUBE_LOGTOSTDERR="--logtostderr=true"

# journal message level, 0 is debug
KUBE_LOG_LEVEL="--v=0"

# Should this cluster be allowed to run privileged docker containers
KUBE_ALLOW_PRIV="--allow-privileged=true"

# How the controller-manager, scheduler, and proxy find the apiserver
#KUBE_MASTER="--master=http://sz-pg-oam-docker-test-001.tendcloud.com:8080"
KUBE_MASTER="--master=http://192.168.5.78:8080"
```
该配置文件同时被 kube-apiserver、kube-controller-manager、kube-scheduler、kubelet、kube-proxy 使用。
apiserver 配置文件 /etc/kubernetes/apiserver 内容为：
```shell
# vim /etc/kubernetes/apiserver
###
## kubernetes system config
##
## The following values are used to configure the kube-apiserver
##
#
## The address on the local server to listen to.
#KUBE_API_ADDRESS="--insecure-bind-address=sz-pg-oam-docker-test-001.tendcloud.com"
KUBE_API_ADDRESS="--advertise-address=192.168.5.78 --bind-address=192.168.5.78 --insecure-bind-address=192.168.5.78"
#
## The port on the local server to listen on.
#KUBE_API_PORT="--port=8080"
#
## Port minions listen on
#KUBELET_PORT="--kubelet-port=10250"
#
## Comma separated list of nodes in the etcd cluster
KUBE_ETCD_SERVERS="--etcd-servers=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379"
#
## Address range to use for services
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=10.254.0.0/16"
#
## default admission control policies
#KUBE_ADMISSION_CONTROL="--admission-control=ServiceAccount,NamespaceLifecycle,NamespaceExists,LimitRanger,ResourceQuota"
KUBE_ADMISSION_CONTROL="--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota,DefaultTolerationSeconds,NodeRestriction"
#
## Add your own!
KUBE_API_ARGS="--authorization-mode=Node,RBAC --runtime-config=rbac.authorization.k8s.io/v1beta1 --kubelet-https=true --experimental-bootstrap-token-auth --token-auth-file=/etc/kubernetes/token.csv --service-node-port-range=30000-32767 --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem --client-ca-file=/etc/kubernetes/ssl/ca.pem --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem --etcd-cafile=/etc/kubernetes/ssl/ca.pem --etcd-certfile=/etc/kubernetes/ssl/kubernetes.pem --etcd-keyfile=/etc/kubernetes/ssl/kubernetes-key.pem --enable-swagger-ui=true --apiserver-count=3 --audit-log-maxage=30 --audit-log-maxbackup=3 --audit-log-maxsize=100 --audit-log-path=/var/lib/audit.log --event-ttl=1h"
```
--authorization-mode=RBAC 指定在安全端口使用 RBAC 授权模式，拒绝未通过授权的请求；kube-scheduler、kube-controller-manager 一般和 kube-apiserver 部署在同一台机器上，他们使用非安全端口和 kube-apiserver 通信；
kubelet、kube-proxy、kubelet 部署在其他 Node 节点上，如果通过安全端口访问 kube-apiserver，则必须先通过 TLS 证书认证，再通过 RBAC 授权；
kube-proxy、kubelet 通过在使用的证书里指定相关的 User、Group 来达到通过 RBAC 授权的目的；如果使用了 kubelet TLS Boostrap 机制，则不能再指定 --kubelet-certificate-authority、--kubelet-client-certificate 和 --kubelet-client-key 选项，否则后续 kube-apiserver 校验 kubelet 证书时出现 “x509：certificate signed by unknown authority” 错误；
- --adminssion-control 值必须包含 ServiceAccount；
- --bind-address 不能为 127.0.0.1；
- runtime-config 配置 为rbac.authorization.k8s.io/v1beta1，表示运行时的 apiVersion；
- --service-cluster-ip-range 指定 Service Cluster IP 地址段，该地址段路由不可达；

缺省情况 下kubernetes 对象保存在 etcd /registry 路径下，可以通过 --etcd-prefix 参数进行调整；
**启动kube-apiserver**
```shell
# systemctl daemon-reload
# systemctl enable kube-apiserver
# systemctl start kube-apiserver
```
##### 2.5.3 配置和启动 kube-controller-manager
**创建 kube-controller-manager 的 service 配置文件**
```shell
# vim /lib/systemd/system/kube-controller-manager.service
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/controller-manager
ExecStart=/usr/local/bin/kube-controller-manager \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBE_MASTER \
        $KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
配置文件 /etc/kubernetes/controller-manager
```shell 
# vim /etc/kubernetes/controller-manager
###
# The following values are used to configure the kubernetes controller-manager

# defaults from config and apiserver should be adequate

# Add your own!
KUBE_CONTROLLER_MANAGER_ARGS="--address=127.0.0.1 --service-cluster-ip-range=10.254.0.0/16 --cluster-name=kubernetes --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem --root-ca-file=/etc/kubernetes/ssl/ca.pem --leader-elect=true"
```
- --service-cluster-ip-range 参数指定 Cluster 中 Service 的 CIDR 范围，该网络在各 Node 间必须路由不可达，必须和 kube-apiserver 中的参数一直；
- --cluster-signing-* 指定的证书和私钥文件用来签名为 TLS BootStrap 创建的证书和私钥
- --root-ca-file 用来对 kube-apiserver 证书进行校验，**指定该参数后，才会在 Pod 容器的 ServiceAccount 中放置该 CA 证书文件**
- --address 值必须为 127.0.0.1，因为当前 kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器，否则：

```shell
# kubectl get componentstatuses
NAME                STATUS      MESSAGE                                                                                        ERROR
scheduler            Unhealthy  Get http://127.0.0.1:10251/healthz: dial tcp 127.0.0.1:10251: getsockopt: connection refused  
controller-manager  Healthy    ok                                                                                            
etcd-2              Healthy    {"health": "true"} 
etcd-0              Healthy    {"health": "true"}                                                                            
etcd-1              Healthy    {"health": "true"}
```
**启动 kube-controller-manager**
```shell
# systemctl daemon-reload
# systemctl enable kube-controller-manager
# systemctl start kube-controller-manager
```
##### 2.5.4 配置和启动 kube-scheduler
**创建 kube-scheduler 的 service 配置文件**
```shell
# vim /usr/lib/systemd/system/kube-scheduler.service
[Unit]
Description=Kubernetes Scheduler Plugin
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/scheduler
ExecStart=/usr/local/bin/kube-scheduler \
            $KUBE_LOGTOSTDERR \
            $KUBE_LOG_LEVEL \
            $KUBE_MASTER \
            $KUBE_SCHEDULER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
配置文件 /etc/kubernetes/scheduler
```shell
# vim /etc/kubernetes/scheduler
###
# kubernetes scheduler config

# default config should be adequate

# Add your own!
KUBE_SCHEDULER_ARGS="--leader-elect=true --address=127.0.0.1"
```
- --address 值必须为 127.0.0.1，因为当前 kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器；

**启动 kube-scheduler**
```shell
# systemctl daemon-reload
# systemctl enable kube-scheduler
# systemctl start kube-scheduler
```
**验证 master 节点功能**
```shell
# kubectl get componentstatuses
NAME                STATUS    MESSAGE              ERROR
controller-manager  Healthy  ok                  
scheduler            Healthy  ok                  
etcd-2              Healthy  {"health": "true"}  
etcd-0              Healthy  {"health": "true"}  
etcd-1              Healthy  {"health": "true"}
```
#### 2.6 安装 flannel 网络插件
所有的 Node 节点都需要安装网络插件才能让所有的 Pod 加入到同一个局域网中，建议直接使用 yum 安装 flanneld，除非对版本有特殊需求，默认安装的是 0.7.1 版本的 flannel。
```shell
# yum install -y flannel
```
service 配置文件 /lib/systemd/system/flanneld.service
```shell
#vim /lib/systemd/system/flanneld.service
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/flanneld
EnvironmentFile=-/etc/sysconfig/docker-network
ExecStart=/usr/bin/flanneld-start \
  -etcd-endpoints=${ETCD_ENDPOINTS} \
  -etcd-prefix=${ETCD_PREFIX} \
  $FLANNEL_OPTIONS
ExecStartPost=/usr/libexec/flannel/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=on-failure

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
```
/etc/sysconfig/flanneld 配置文件：
```shell
# cat /etc/sysconfig/flanneld
# Flanneld configuration options  

# etcd url location.  Point this to the server where etcd runs
#FLANNEL_ETCD_ENDPOINTS="http://127.0.0.1:2379"
# For address range assignment
ETCD_ENDPOINTS="https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379"
ETCD_PREFIX="/kube-centos/network"
# etcd config key.  This is the configuration key that flannel queries
# Any additional options that you want to pass
FLANNEL_OPTIONS="-etcd-cafile=/etc/kubernetes/ssl/ca.pem -etcd-certfile=/etc/kubernetes/ssl/kubernetes.pem -etcd-keyfile=/etc/kubernetes/ssl/kubernetes-key.pem"
```
在 etcd 中创建网络配置
执行下面的命令为 docker 分配 IP 地址段。
```shell
# etcdctl --endpoints=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem mkdir /kube-centos/network
# etcdctl --endpoints=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem mk /kube-centos/network/config '{"Network":"172.30.0.0/16","SubnetLen":24,"Backend":{"Type":"host-gw"}}'
```
如果你要是用 vxlan 模式，可以直接将 host-gw 改成 vxlan 即可。

启动 flannel
```shell
# systemctl daemon-reload
# systemctl start flanneld
```
现在查询 etcd 中的内容可以看到：
```shell
# etcdctl --endpoints=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem  ls /kube-centos/network/subnets
/kube-centos/network/subnets/172.30.60.0-24
/kube-centos/network/subnets/172.30.61.0-24
/kube-centos/network/subnets/172.30.17.0-24
# etcdctl --endpoints=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem  get /kube-centos/network/config
{"Network":"172.30.0.0/16","SubnetLen":24,"Backend":{"Type":"vxlan"}}

#  etcdctl --endpoints=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem  get /kube-centos/network/subnets/172.30.17.0-24
{"PublicIP":"192.168.5.79","BackendType":"vxlan","BackendData":{"VtepMAC":"a2:61:de:2d:11:fd"}}

# etcdctl --endpoints=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem  get /kube-centos/network/subnets/172.30.60.0-24
{"PublicIP":"192.168.5.80","BackendType":"vxlan","BackendData":{"VtepMAC":"1a:47:b3:f2:19:0c"}}

# etcdctl --endpoints=https://192.168.5.78:2379,https://192.168.5.79:2379,https://192.168.5.80:2379  --ca-file=/etc/kubernetes/ssl/ca.pem  --cert-file=/etc/kubernetes/ssl/kubernetes.pem  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem  get /kube-centos/network/subnets/172.30.61.0-24
{"PublicIP":"192.168.5.78","BackendType":"vxlan","BackendData":{"VtepMAC":"8e:9c:93:8e:d9:2d"}}
```
能够查看到以上内容证明搭建完成。

#### 2.7 部署node节点
Kubernetes node 节点包含如下组件：
- Flanneld：配置带有 TLS 的 flannel
- Docker
- kubelet：直接二进制文件安装
- kube-proxy：直接用二进制文件安装
##### 2.7.1 配置 Docker 
如果使用 yum 的方式安装 flannel 则不需要执行 mk-docker-opt.sh 文件这一步，如果不是使用的 yum 安装的 flannel，那么需要下载 flannel github release 中的 tar 包，解压后会获得一个 mk-docker-opt.sh 文件。这个文件是用来 Generate Docker daemon options based on flannel env file。
使用 systemctl 命令启动 flanneld 后，会自动执行 ./mk-docker-opts.sh -i 生成如下的文件环境变量文件：
- /run/flannel/subnet.env
```shell
FLANNEL_NETWORK=172.30.0.0/16
FLANNEL_SUBNET=172.30.60.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=false
```
Docker 将会读取这个环境变量文件作为容器的启动参数。
><font color=red>**注意：不论使用哪种方式安装 flanneld，下面的步骤是必不可少的**</font>

修改 docker 的配置文件 /lib/systemd/system/docker.service，增加一条环境变量配置：
```shell
EnvironmentFile=-/run/flannel/docker
```
/run/flannel/docker 文件是 flannel 启动后自动生成的，其中包含了 docker 启动时需要的参数如下：
```shell
# cat /run/flannel/docker
DOCKER_OPT_BIP="--bip=172.30.61.1/24"
DOCKER_OPT_IPMASQ="--ip-masq=true"
DOCKER_OPT_MTU="--mtu=1450"
DOCKER_NETWORK_OPTIONS=" --bip=172.30.61.1/24 --ip-masq=true --mtu=1450"
```
我安装的时候遇到一个问题就是，启动 docker 后这个文件中的变量没有被引用，docker 启动后，docker0不能加入到flannel网络中。至今不知道什么原因，我就把 docker.service 的配置文件更改了，添加如下内容：
```shell
ExecStart=/usr/bin/dockerd $DOCKER_NETWORK_OPTIONS
```
重启 docker 后，docker0 加入 flanneld 网络中
```shell
# ifconfig |egrep  -A 2 "docker0|flannel"
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1450
        inet 172.30.61.1  netmask 255.255.255.0  broadcast 172.30.61.255
        inet6 fe80::42:bdff:fe64:27a0  prefixlen 64  scopeid 0x20<link>
--
flannel.1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1450
        inet 172.30.61.0  netmask 255.255.255.255  broadcast 0.0.0.0
        ether 8e:9c:93:8e:d9:2d  txqueuelen 0  (Ethernet)
```


**二进制方式安装的 flannel**
修改 docker 的配置文件 /lib/systemd/system/docker.service，增加如下环境变量配置：
```shell
EnvironmentFile=-/run/docker_opts.env
EnvironmentFile=-/run/flannel/subnet.env
```
这两个文件是 mk-docker-opts.sh 脚本生成环境变量文件默认的保存位置，docker启动的时候需要加载这几个配置文件才可以加入到 flannel 创建的虚拟网络里。

**启动 docker**
重启 docker 后还要重启 kubelet，这时又遇到问题，kubelet 启动失败。报错：
```shell
error: failed to run Kubelet: failed to create kubelet: misconfiguration: kubelet cgroup driver: "cgroupfs" is different from docker cgroup driver: "systemd"
```
这是 kubelet 与 docker 的 cgroup driver 不一致导致的，kubelet 启动的时候有两个 -cgroup-driver 参数，可以指定为 “cgroups” 或者 “systemd”。
```shell
--cgroup-driver string                                    Driver that the kubelet uses to manipulate cgroups on the host.  Possible values: 'cgroupfs', 'systemd' (default "cgroupfs")
```
修改 docker 的 service 配置文件 /lib/systemd/system/docker.service，在 ExecStart 行添加 --exec-opt native.cgroupdriver=systemd。
##### 2.7.2 安装和配置 kubelet
kubernetes1.8 相对于 kubernetes1.6 集群必须进行的配置有：必须关闭 swap，否则 kubelet 启动将失败。修改 /etc/fstab，将 swap 系统注释掉。
kubelet 启动时向 kube-apiserver 发送 TLS bootstrapping 请求，需要先将 bootstrap token 文件中的 kubel-bootstrap 用户赋予 system:node-bootstrapper cluster 角色（role），然后 kubelet 才能有权限创建认证请求（certificate signing requests）：
```shell
# cd /etc/kubernetes
# kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap
```
- --user=kubelet-bootstrap 是在 /etc/kubernetes/token.csv 文件中指定的用户名，同时也写入了 /etc/kubernetes/bootstrap.kubeconfig 文件。

前面已经下载过 server 的二进制包了，将各个文件也都拷贝到相应目录了，接下来只需创建相应的配置文件即可。

**创建 kubelet 的 service 配置文件**
```shell
# vim /lib/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/kubelet
ExecStart=/usr/local/bin/kubelet \
            $KUBE_LOGTOSTDERR \
            $KUBE_LOG_LEVEL \
            $KUBELET_ADDRESS \
            $KUBELET_PORT \
            $KUBELET_HOSTNAME \
            $KUBE_ALLOW_PRIV \
            $KUBELET_ARGS
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
**kubelet 的配置文件 /etc/kubernetes/kubelet**
kubernetes1.8 相对于 kubernetes1.6 的配置有变动：
- 对于 kubernetes1.8 集群中的 kubelet 配置，取消了 KUBELET_API_SERVER 的配置，而改用 kubeconfig 文件来定义 master 地址。
```shell
# vim /etc/kubernetes/kubelet
###
## kubernetes kubelet (minion) config
## The address for the info server to serve on (set to 0.0.0.0 or "" for all interfaces)
KUBELET_ADDRESS="--address=192.168.5.78"
## The port for the info server to serve on
#KUBELET_PORT="--port=10250"
## You may leave this blank to use the actual hostname
KUBELET_HOSTNAME="--hostname-override=192.168.5.78"
## Add your own!
KUBELET_ARGS="--cgroup-driver=systemd --cluster-dns=10.254.0.2 --experimental-bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig --kubeconfig=/etc/kubernetes/kubelet.kubeconfig --require-kubeconfig --cert-dir=/etc/kubernetes/ssl--cluster-domain=cluster.local --hairpin-mode=promiscuous-bridge --serialize-image-pulls=false"
```
- --address 不能设置为 127.0.0.1，否则后续 Pods 访问 kubelet 的 API 接口时会失败，因为Pods访问的 127.0.0.1 指向自己而不是 kubelet；
- --如果设置了--hostname-override 选项，则 kube-proxy 也需要设置该选项，否则会出现在好不到 Node 的情况；
- --cgroup-driver 配置成 systemd，不要使用 cgroup，否则在 CentOS 系统中 kubelet 将启动失败（保持 docker 和 kubelet 中的 cgroup driver 配置一致即可，不一定非使用 systemd）
- --experimental-bootstrap-kubeconfig 指向 bootstrap kubeconfig 文件，kubelet 使用该文件中的用户名和 token 向 kube-apiserver 发送 TLS bootstrapping 请求；
- 管理员通过了 CSR 请求后，kubelet 自动在 --cert-dir 目录创建证书和私钥文件(kubelet-client.crt 和 kubelet-client.key)，然后写入 --kubeconfig 文件；
- 建议在 --kubeconfig 配置文件中指定 kube-apiserver 地址，如果未指定 --api-servers 选项，则必须指定 --require-kubeconfig 选项后才能从配置文件中读取 kube-apiserver 的地址，否则 kubelet 启动后将找不到 kube-apiserver (日志中提示未找到 API Server），kubectl get nodes 不会返回对应的 Node 信息;
- --cluster-dns 指定 kubedns 的 Service IP(可以先分配，后续创建 kubedns 服务时指定该 IP)，--cluster-domain 指定域名后缀，这两个参数同时指定后才会生效；
- --cluster-domain 指定 pod 启动时 /etc/resolve.conf 文件中的 search domain ，起初我们将其配置成了 cluster.local.，这样在解析 service 的 DNS 名称时是正常的，可是在解析 headless service 中的 FQDN pod name 的时候却错误，因此我们将其修改为 cluster.local，去掉最后面的 ”点号“ 就可以解决该问题
- --kubeconfig=/etc/kubernetes/kubelet.kubeconfig 中指定的 kubelet.kubeconfig 文件在第一次启动 kubelet 之前并不存在，请看下文，当通过CSR请求后会自动生成kubelet.kubeconfig 文件，如果你的节点上已经生成了~/.kube/config文件，你可以将该文件拷贝到该路径下，并重命名为kubelet.kubeconfig，所有 Node 节点可以共用同一个 kubelet.kubeconfig 文件，这样新添加的节点就不需要再创建 CSR 请求就能自动添加到 kubernetes 集群中。同样，在任意能够访问到 kubernetes 集群的主机上使用 kubectl --kubeconfig 命令操作集群时，只要使用 ~/.kube/config 文件就可以通过权限认证，因为这里面已经有认证信息并认为你是admin用户，对集群拥有所有权限
- KUBELET_POD_INFRA_CONTAINER 是基础镜像容器，根据自己环境修改为自己的镜像
通过 kubelet 的 TLS 证书请求，kubelet 首次启动时向 kube-apiserver 发送证书签名请求，必须通过后 kubernetes 系统才会将该 Node 加入到集群。

**查看未授权的 CSR 请求**
```shell
# kubectl get csr
NAME                                                  AGE      REQUESTOR          CONDITION
node-csr-6AxPZt8lbnp3NYilsrCycs-nJMsKax0fYtpNZ9Ph_C4  42m      kubelet-bootstrap  Approved,Issued
node-csr-PDB1d5vHj1ghqH2pMv7-T5yj2iZr2Mn_jnavzwB-wY0  1h        kubelet-bootstrap  Approved,Issued
node-csr-rH9skkK3WTRMd4MFM9Z7PpaxM0SoOK74xAJVwqMHEh8  27s      kubelet-bootstrap  Pending
# kubectl get nodes
No resources found.
```
**通过 CSR 请求**
```shell
# kubectl certificate approve node-csr-rH9skkK3WTRMd4MFM9Z7PpaxM0SoOK74xAJVwqMHEh8
certificatesigningrequest "node-csr-rH9skkK3WTRMd4MFM9Z7PpaxM0SoOK74xAJVwqMHEh8" approved
# kubectl get csr
NAME                                                  AGE      REQUESTOR          CONDITION
node-csr-6AxPZt8lbnp3NYilsrCycs-nJMsKax0fYtpNZ9Ph_C4  2d        kubelet-bootstrap  Approved,Issued
node-csr-PDB1d5vHj1ghqH2pMv7-T5yj2iZr2Mn_jnavzwB-wY0  2d        kubelet-bootstrap  Approved,Issued
node-csr-rH9skkK3WTRMd4MFM9Z7PpaxM0SoOK74xAJVwqMHEh8  1d        kubelet-bootstrap  Approved,Issued
# kubectl get nodes
NAME          STATUS    ROLES    AGE      VERSION
192.168.5.78  Ready    <none>    1d        v1.8.4
192.168.5.79  Ready    <none>    2d        v1.8.4
192.168.5.80  Ready    <none>    2d        v1.8.4
```
**自动生成了 kubelet kubeconfig 文件和公私钥**
```shell
# ls -l /etc/kubernetes/kubelet.kubeconfig
-rw------- 1 root root 2279 Dec 19 22:06 /etc/kubernetes/kubelet.kubeconfig
# ls -l /etc/kubernetes/ssl/kubelet*
-rw-r--r-- 1 root root 1046 Dec 19 22:06 /etc/kubernetes/ssl/kubelet-client.crt
-rw------- 1 root root  227 Dec 19 22:05 /etc/kubernetes/ssl/kubelet-client.key
-rw-r--r-- 1 root root 1111 Dec 19 22:05 /etc/kubernetes/ssl/kubelet.crt
-rw------- 1 root root 1675 Dec 19 22:05 /etc/kubernetes/ssl/kubelet.key
```
假如更新 kubernetes 的证书，只要没有更新 token.csv，当重启 kubelet 后，该 node 就会自动加入到 kuberentes 集群中，而不会重新发送 certificaterequest，也不需要在 master 节点上执行 kubectl certificate approve 操作。前提是不要删除 node 节点上的 /etc/kubernetes/ssl/kubelet* 和 /etc/kubernetes/kubelet.kubeconfig 文件。否则 kubelet 启动时会提示找不到证书而失败。

><font color=red>**注意：如果启动 kubelet 的时候见到证书相关的报错，有个 trick 可以解决这个问题，可以将 master 节点上的 ~/.kube/config 文件（该文件在安装 kubectl 命令行工具这一步中将会自动生成）拷贝到 node 节点的 /etc/kubernetes/kubelet.kubeconfig 位置，这样就不需要通过 CSR，当 kubelet 启动后就会自动加入的集群中。**</font>

##### 2.7.3 安装和配置 kube-proxy
安装 contrack
```shell
# yum install contrack -y
```
**创建 kube-proxy 的 service 配置文件**
文件路径 /lib/systemd/system/kube-proxy.service
```shell
# vim /lib/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/proxy
ExecStart=/usr/local/bin/kube-proxy \
        $KUBE_LOGTOSTDERR \
        $KUBE_LOG_LEVEL \
        $KUBE_MASTER \
        $KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
kube-proxy 配置文件 /etc/kubernetes/proxy
```shell
# vim /etc/kubernetes/proxy
###
# kubernetes proxy config
# default config should be adequate
# Add your own!
KUBE_PROXY_ARGS="--bind-address=192.168.5.79 --hostname-override=192.168.5.79 --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig --cluster-cidr=10.254.0.0/16"
```
- --hostname-override 参数值必须与 kubelet 的值一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 iptables 规则；
- kube-proxy 根据 --cluster-cidr 判断集群内部和外部流量，指定 --cluster-cidr 或 --masquerade-all 选项后 kube-proxy 才会对访问 Service IP 的请求做 SNAT；
- --kubeconfig 指定的配置文件嵌入了 kube-apiserver 的地址、用户名、证书、秘钥等请求和认证信息；
- 预定义的 RoleBinding cluster-admin 将User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；
启动 kubeconfig-proxy
```shell
# systemctl daemon-reload
# systemctl start kube-proxy
```
**验证测试**
创建一个 nginx 的 service 试一下集群是否可用：
```shell
# kubectl run nginx --replicas=2 --labels="run=load-balancer-example" --image=nginx:1.8  --port=80
deployment "nginx" created
# kubectl expose deployment nginx --type=NodePort --name=nginx-test-service
service "nginx-test-service" exposed
# kubectl describe svc nginx-test-service
Name:                    nginx-test-service
Namespace:                default
Labels:                  run=load-balancer-example
Annotations:              <none>
Selector:                run=load-balancer-example
Type:                    NodePort
IP:                      10.254.110.82
Port:                    <unset>  80/TCP
TargetPort:              80/TCP
NodePort:                <unset>  30014/TCP
Endpoints:                <none>
Session Affinity:        None
External Traffic Policy:  Cluster
Events:                  <none>
# curl -I 10.254.110.82:80
HTTP/1.1 200 OK
Server: nginx/1.8.1
Date: Thu, 21 Dec 2017 14:58:56 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 26 Jan 2016 15:24:47 GMT
Connection: keep-alive
ETag: "56a78fbf-264"
Accept-Ranges: bytes
```
在浏览器访问三个节点 IP+ 容器端口号：
 ![此处输入图片的描述][1]

><font color=red>**需要特别注意的是，防火墙需要打开转发功能，iptables -P FORWARD ACCEPT   iptables -I FORWARD -s 172.30.0.0/16  -j ACCEPT**</font>。


  [1]: C:%5CUsers%5Ccbsy%5CDesktop