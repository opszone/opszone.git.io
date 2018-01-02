---
layout: post
title:  CentOS7.2部署 kubernetes1.8.x 集群
categories: jekyll update
tag: kubernetes
description: kubernetes 
keywords: kubernetes
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
- server auth：表示 client 可以
