var data = {
  初始访问: {
    description:
      "初始访问战术指所有用于获得资源访问权限的技术。在云原生环境里，这些技术可以实现对容器、集群的初始访问。",
    children: {
      "利用对外开放的（部署到容器/云环境）应用程序": {
        description:
          "容器或云的基础设施内部署带有漏洞的应用程序，通常是一些web服务，比如RCE漏洞、Redis未授权访问、SSH服务等。",
      },
      外部远程服务: {
        description: "",
        children: {
          "Docker Remote API 未授权访问":
            "docker 守护进程监听在 0.0.0.0，默认端口为2375，可以调用API来执行docker 命令进行未授权访问和逃逸。",
          "K8s Api Server 未授权访问":
            "K8s API Server 默认HTTP服务端口为 8080（insecure-port，非安全端口），HTTPS端口为和 6443（secure-port，安全端口）。\n8080端口的请求没有认证和授权检查，如果该端口暴露在互联网上，即可以直接与K8s API Server交互，从而控制整个集群。1.20版本后该选项已无效。\n不带任何凭证访问6443端口，会被服务器标记为 system:anonymous 用户, 一般 system:anonymous 用户权限是很低的，但是如果运维人员管理失当，将 system:anonymous 用户绑定到了 cluster-admin 用户组，那么就意味着 secure-port 允许匿名用户以管理员权限向集群下达命令。",
          "Kubelet 未授权访问":
            "Kubelet的HTTPS服务端口为10250，把 authentication-anonymous-enabled 改为 true，authorization-mode 改为 AlwaysAllow重启kubelet就存在未授权访问，可以在pod中执行命令。",
          "K8s etcd 未授权访问":
            "etcd是K8s集群的数据库组件，监听端口为2379，如果存在未授权就可以利用etcdctl工具查询数据库获取敏感文件（比如clusterrole的token，云产品的AKSK）[1][2]，利用这个token就可以访问k8s api server控制集群。",
          私有镜像仓库暴露:
            "公司企业在业务中往往使用私有的镜像库，暴露的私有镜像库可能遭受到攻击者劫持，造成供应链攻击。比如Harbor，2019披露的CVE-2019-16097允许攻击者发送恶意请求以管理员权限创建用户，接管Harbor，从而上传恶意镜像等行为。",
        },
      },
      有效账户: {
        description: "",
        children: {
          本地账户: {
            利用泄露的kubeconfig文件:
              "kubeconfig文件中有k8s集群、用户、命名空间和身份认证的详细信息，包括API Server地站和登录凭证。如果攻击者可以访问kubeconfig文件，则可以通过API Server接管集群。",
            "利用泄露的Master SSH登录凭证":
              "如果攻击者可以拿到Master节点的SSH登录凭证，则可以进入Master节点从而控制集群。",
          },
          "云账户/云凭证": {
            ServiceAccount:
              "ServiceAccount是在 Kubernetes 中一种用于非人类用户的账号，在 Kubernetes 集群中提供不同的身份标识。常见的使用ServiceAccount来提供身份标识的场景有Pod 与 Kubernetes API 服务器通信、Pod 与外部服务进行通信、使用 imagePullSecret 完成在私有镜像仓库上的身份认证、外部服务与 Kubernetes API 服务器通信。",
            "Access Keys":
              "Access Keys（通常由 Access Key ID 和 Secret Access Key 组成）允许用户和应用程序访问云服务。通过这些密钥，云服务可以验证用户的身份并授予相应权限。",
            "云厂商API key（云厂商Cloudshell）":
              "API 密钥是用于授权应用程序访问云服务的一串字符。它通常嵌入应用程序代码或传递给第三方服务以验证应用的身份。应用程序调用云服务的 API 接口时，使用 API 密钥进行认证。例如，调用 AWS、Google Cloud 或 Azure 的 API。",
            "IAM Role":
              "IAM 角色允许云资源临时获取访问其他资源的权限，而无需长时间暴露静态密钥。角色通过临时的安全令牌授予权限，并且有时间限制。",
            "OAuth 令牌":
              "OAuth 令牌是用于授权第三方应用访问用户云服务资源的一种凭证，通常有时间限制。OAuth 令牌不需要共享用户密码，仅授权特定的权限。用户通过 OAuth 授权第三方应用访问 Google Cloud、Microsoft Azure、GitHub 等服务，常见于 SaaS 应用场景。",
          },
        },
      },
      用户执行: {
        description:
          "用户可能使用公开的镜像源（如docker hub）或私有的镜像源（如harbor）下载镜像，但这些镜像可能是恶意镜像，用户在自己的业务环境中部署这些恶意镜像并执行，导致供应链攻击。",
      },
      暴露的敏感信息接口: {
        description:
          "Openshift api、Rancher api、VMware Tanzu这些私有化部署的容器编排平台都提供了敏感信息接口。",
      },
    },
  },
  执行: {
    description: "执行战术是指攻击者在云原生环境中执行其代码的技术。",
    children: {
      容器管理命令: {
        description:
          "具备相应权限的攻击者可以在云原生环境用Kubectl exec和docker exec等命令执行恶意代码。",
      },
      部署容器: {
        description: "",
        children: {
          注入Sidercar容器:
            "SiderCar 容器是一种与主应用容器共同运行在同一个 Pod 中的辅助容器。它通常用于增强主应用的功能，比如日志收集、监控、代理等。近年来随着服务网格的流行（例如Envoy SiderCar模式），Sidercar容器也常被作为一种攻击技术，攻击者可以在master节点通过kubectl patch在现有Pod基础上注入SiderCar容器，接着在Sidercar容器执行其恶意代码。",
          "利用 k8s 控制器部署后门容器（ReplicaSet/DaemonSet/Deployment）":
            "如果攻击者拥有controllers权限时可以通过ReplicaSet/DaemonSet/Deployment来创建后门容器，从而在容器中执行其恶意代码。",
        },
      },
      "计划任务/作业": {
        description:
          "容器编排任务，Kubernetes CronJob 是用于定时调度任务的 Kubernetes 资源。CronJob 允许你基于指定的时间调度周期性任务，任务可以是攻击者的恶意代码。",
      },
      用户执行: {
        description: "",
        children: {
          恶意镜像:
            "用户可能从公开的镜像源（如docker hub）或私有的镜像源（如harbor）下载恶意镜像并部署，攻击者则可以通过这个恶意镜像执行命令。",
          "利用Service Account连接API Server执行命令":
            '攻击者拥有高权限的Service Account则可以直接向k8s下发命令，比如获取集群中所有的 Pods 信息：curl -k -X GET https://<api-server-url>/api/v1/pods  --header "Authorization: Bearer <service-account-token>"',
        },
      },
      "利用对外开放的（部署到容器/云环境）应用程序": {
        description:
          "容器含有SSH服务，攻击者通过暴力破解或凭证泄露进入容器执行其代码。或者是容器中的应用程序存在RCE漏洞，则攻击者也可以执行任意代码。",
      },
      外部远程服务: {
        description: "",
        children: {
          "Docker Remote API未授权访问":
            "docker 守护进程监听在 0.0.0.0，默认端口为2375，可以调用API来执行docker 命令进行未授权访问和逃逸。",
          "K8s ApI未授权访问":
            "K8s API Server 默认HTTP服务端口为 8080（insecure-port，非安全端口），HTTPS端口为和 6443（secure-port，安全端口）。\n8080端口的请求没有认证和授权检查，如果该端口暴露在互联网上，即可以直接与K8s API Server交互，从而控制整个集群。1.20版本后该选项已无效。\n不带任何凭证访问6443端口，会被服务器标记为 system:anonymous 用户, 一般 system:anonymous 用户权限是很低的，但是如果运维人员管理失当，将 system:anonymous 用户绑定到了 cluster-admin 用户组，那么就意味着 secure-port 允许匿名用户以管理员权限向集群下达命令。",
          Kubelet未授权访问:
            "Kubelet的HTTPS服务端口为10250，把 authentication-anonymous-enabled 改为 true，authorization-mode 改为 AlwaysAllow重启kubelet就存在未授权访问，，可以在pod中执行命令。",
          "K8s etcd未授权访问":
            "etcd是K8s集群的数据库组件，监听端口为2379，如果存在未授权就可以利用etcdctl工具查询数据库获取敏感文件（比如clusterrole的token，云产品的AKSK）[1][2]，利用这个token就可以访问k8s api server控制集群。",
          私有镜像仓库暴露:
            "公司企业在业务中往往使用私有的镜像库，暴露的私有镜像库可能遭受到攻击者劫持，造成供应链攻击。比如Harbor，2019披露的CVE-2019-16097允许攻击者发送恶意请求以管理员权限创建用户，接管Harbor，从而上传恶意镜像等行为。在恶意镜像中，攻击者可以执行其恶意命令。",
        },
      },
      利用云厂商CloudShell下发命令: {
        description:
          "云账户凭证（云厂商API key）泄露，攻击者可以通过云厂商提供的API控制集群，执行其代码。",
      },
    },
  },
  持久化: {
    description: "持久化战术是指攻击者用来维持对集群访问的技术。",
    children: {
      外部远程服务: {
        description: "",
        children: {
          "Docker Remote API未授权访问":
            "docker 守护进程监听在 0.0.0.0，默认端口为2375，可以调用API来执行docker 命令进行未授权访问和逃逸。",
          "K8s ApI未授权访问":
            "K8s API Server 默认HTTP服务端口为 8080（insecure-port，非安全端口），HTTPS端口为和 6443（secure-port，安全端口）。\n8080端口的请求没有认证和授权检查，如果该端口暴露在互联网上，即可以直接与K8s API Server交互，从而控制整个集群。1.20版本后该选项已无效。\n不带任何凭证访问6443端口，会被服务器标记为 system:anonymous 用户, 一般 system:anonymous 用户权限是很低的，但是如果运维人员管理失当，将 system:anonymous 用户绑定到了 cluster-admin 用户组，那么就意味着 secure-port 允许匿名用户以管理员权限向集群下达命令。",
          Kubelet未授权访问:
            "Kubelet的HTTPS服务端口为10250，把 authentication-anonymous-enabled 改为 true，authorization-mode 改为 AlwaysAllow重启kubelet就存在未授权访问，，可以在pod中执行命令。",
          "K8s etcd未授权访问":
            "etcd是K8s集群的数据库组件，监听端口为2379，如果存在未授权就可以利用etcdctl工具查询数据库获取敏感文件（比如clusterrole的token，云产品的AKSK）[1][2]，利用这个token就可以访问k8s api server控制集群。",
          私有镜像仓库暴露:
            "公司企业在业务中往往使用私有的镜像库，暴露的私有镜像库可能遭受到攻击者劫持，造成供应链攻击。比如Harbor，2019披露的CVE-2019-16097允许攻击者发送恶意请求以管理员权限创建用户，接管Harbor，从而上传恶意镜像等行为。在恶意镜像中，攻击者可以执行其恶意命令。",
        },
      },
      部署容器: {
        description: "",
        children: {
          注入Sidercar容器:
            "SiderCar 容器是一种与主应用容器共同运行在同一个 Pod 中的辅助容器。它通常用于增强主应用的功能，比如日志收集、监控、代理等。近年来随着服务网格的流行（例如Envoy SiderCar模式），Sidercar容器也常被作为一种攻击技术，攻击者可以在master节点通过kubectl patch在现有Pod基础上注入SiderCar容器，接着在Sidercar容器执行其恶意代码。",
          "利用k8s控制器部署后门容器（ReplicaSet/DaemonSet/Deployment）":
            "如果攻击者拥有controllers权限时可以通过ReplicaSet/DaemonSet/Deployment来创建后门容器，从而在容器中执行其恶意代码。",
        },
      },
      "计划任务/作业": {
        description: "参考章节执行:计划任务/作业。",
      },
      有效账户: {
        description: "",
        children: {
          本地账户: {
            利用泄露的kubeconfig文件:
              "kubeconfig文件中有k8s集群、用户、命名空间和身份认证的详细信息，包括API Server地站和登录凭证。如果攻击者可以访问kubeconfig文件，则可以通过API Server接管集群。",
            "利用泄露的Master SSH登录凭证":
              "如果攻击者可以拿到Master节点的SSH登录凭证，则可以进入Master节点从而控制集群。",
          },
          "云账户/云凭证": {
            ServiceAccount:
              "ServiceAccount是在 Kubernetes 中一种用于非人类用户的账号，在 Kubernetes 集群中提供不同的身份标识。常见的使用ServiceAccount来提供身份标识的场景有Pod 与 Kubernetes API 服务器通信、Pod 与外部服务进行通信、使用 imagePullSecret 完成在私有镜像仓库上的身份认证、外部服务与 Kubernetes API 服务器通信。",
            "Access Keys":
              "Access Keys（通常由 Access Key ID 和 Secret Access Key 组成）允许用户和应用程序访问云服务。通过这些密钥，云服务可以验证用户的身份并授予相应权限。",
            "云厂商API key（云厂商Cloudshell）":
              "API 密钥是用于授权应用程序访问云服务的一串字符。它通常嵌入应用程序代码或传递给第三方服务以验证应用的身份。应用程序调用云服务的 API 接口时，使用 API 密钥进行认证。例如，调用 AWS、Google Cloud 或 Azure 的 API。",
            "IAM Role":
              "IAM 角色允许云资源临时获取访问其他资源的权限，而无需长时间暴露静态密钥。角色通过临时的安全令牌授予权限，并且有时间限制。",
            "OAuth 令牌":
              "OAuth 令牌是用于授权第三方应用访问用户云服务资源的一种凭证，通常有时间限制。OAuth 令牌不需要共享用户密码，仅授权特定的权限。用户通过 OAuth 授权第三方应用访问 Google Cloud、Microsoft Azure、GitHub 等服务，常见于 SaaS 应用场景。",
          },
        },
      },
      容器逃逸: {
        description:
          "无论是通过特权容器、危险挂载、组件漏洞还是内核漏洞，攻击者可以通过容器逃逸修改宿主机上的敏感目录或文件，例如/root/.ssh/、cron，从而到达持久化控制的目的。",
        children: {
          危险配置: "利用特权容器、notify_on_release机制逃逸等等。",
          危险挂载:
            "挂载docker.sock，挂载procfs，挂载LXCFS，挂载/var/log等等。",
          "容器生态中客户端、服务端程序自身漏洞":
            "常见的有利用runc漏洞逃逸，比如cve-2019-5736、cve-2024-21626等等。",
          操作系统漏洞: "利用操作系统内核漏洞逃逸，比如cve-2022-0847等等。",
        },
      },
      写入Webshell: {
        description:
          "容器内运行的Web服务存在一些远程命令执行（RCE）漏洞或文件上传漏洞，攻击者可能利用该类漏洞写入WebShell。",
      },
      "添加恶意admission controller": {
        description:
          "Admission 控制器是 Kubernetes 内部用来拦截和验证 API 请求的机制，用于增强集群的安全性，紧接着Authentication和Authorization之后的就是Admission controller。恶意的 Admission 控制器可以在验证过程中注入恶意代码或绕过安全检查，比如通过创建Admission Controller拦截正常用户部署的工作负载请求，并在请求所属业务yaml配置文件中注入边车容器配置，从而进行持久化操作。",
      },
      "创建Shadow API server": {
        description:
          "攻击者在集群中创建一个伪装成合法 API Server 的组件，但修改了API Server的相关配置，比如常见的有允许容器请求特权模式，暴露了insecure-port为9443，监听地址绑定为0.0.0.0，允许了匿名访问，允许所有请求。",
      },
    },
  },
  权限提升: {
    description:
      "权限提升是指在当前环境中，攻击者获得更高权限的技术。在云原生环境中，包括获得节点的访问权限，集群中的高权限，访问云资源的权限。",
    children: {
      容器逃逸: {
        description: "",
        children: {
          危险配置: "利用特权容器、notify_on_release机制逃逸等等。",
          危险挂载:
            "挂载docker.sock，挂载procfs，挂载LXCFS，挂载/var/log等等。",
          "容器生态中客户端、服务端程序自身漏洞":
            "常见的有利用runc漏洞逃逸，比如cve-2019-5736、cve-2024-21626等等。",
          操作系统漏洞: "利用操作系统内核漏洞逃逸，比如cve-2022-0847等等。",
        },
      },
      有效账户: {
        description: "参考章节初始访问:有效账户。",
      },
      利用集群环境自身漏洞: {
        description:
          "比如利用CVE-2018-1002105、CVE-2020-14386、CVE-2023-25173等等实现集群内提权。",
      },
      "计划任务/作业": {
        description: "参考章节执行:计划任务/作业。",
      },
      "创建高权限的binding roles": {
        description:
          "K8s中采用基于角色的访问控制（RBAC）来允许集群管理员为不同的用户或服务账户指定细粒度的权限，cluster-admin是k8s集群中的一个高权限角色，它赋予了用户对整个集群的完全控制权限。攻击者可以通过访问某些配置不当的资源来查看哪些角色具有高权限。除此之外，如果攻击者有权限绑定的能力，攻击者可以创建一个 RoleBinding 或 ClusterRoleBinding，将自己或其他用户绑定到高权限的角色上，从而获得更多权限",
      },
    },
  },
  防御绕过: {
    description: "防御绕过战术是指攻击者用来隐藏其攻击行为躲避检测的技术。",
    children: {
      在主机上构建镜像: {
        description:
          "攻击者可以直接在主机上构建容器镜像，以绕过监控从公共注册表检索恶意镜像的防御措施。攻击者build可以向 Docker API 发送远程请求，其中包含一个 Dockerfile，该 Dockerfile 从公共或本地注册表中提取原始基础镜像（例如 alpine），然后在其上构建自定义镜像。由于基础映像是从公共注册表中提取的，防御系统可能不会将该映像检测为恶意映像。",
      },
      部署容器: {
        description:
          "攻击者可能会部署新容器来执行与特定映像或部署相关的进程，例如执行或下载恶意软件，或者部署特权容器等等。",
      },
      清除入侵痕迹: {
        description: "",
        children: {
          "清除容器、宿主机日志":
            "在获得一定权限的前提条件下，清除容器以及宿主机的系统日志和服务日志。",
          清除K8s事件:
            "Kubernetes 会记录集群中资源对象（如 Pods、Nodes、Deployments 等）在其生命周期中发生的重要状态变化。攻击者可以通过删除关联的资源对象；访问etcd数据库删除与事件相关的键值；或者通过修改 Kubernetes 控制平面组件的参数，缩短事件的保留时间，使事件尽快被清理；或者直接删除事件资源。",
          "清除K8s audit日志":
            "Audit logs是对 Kubernetes 集群中的 API 请求进行详细记录。它包含了谁（用户、服务账户等）在何时进行了什么操作（创建、删除、更新、读取等），以及这些操作的结果如何。审计日志是 Kubernetes 提供的一种强大的安全监控工具，通常用于审计和合规性检查。攻击者可以通过直接删除审计日志文件、篡改审计策略、修改API server启动参数来禁用审计来清除audit日志。",
        },
      },
      损害防御: {
        description: "",
        children: {
          禁用或修改工具:
            "攻击者可能会恶意修改受害环境的组件或关闭一些安全产品的功能，以阻碍或禁用防御机制。",
        },
      },
      伪装: {
        description: "",
        children: {
          利用系统pod伪装:
            "Deployment或DaemonSet这类控制器创建的pod名称带有随机后缀，攻击者可以将其创建的恶意pod和现有pod命名一致。或者是将恶意pod命名为coredns+随机后缀来迷惑用户。",
        },
      },
      有效账户: {
        description:
          "攻击者可以利用窃取的凭证绕过对网络内系统上各种资源的访问控制。",
      },
      "通过代理访问API Server": {
        description: "通过代理或匿名网络执行攻击，避免被日志记录源ip。",
      },
      "创建shadow api server": {
        description:
          "攻击者可以部署一个shadow api server，该api server具有和集群中现存的api server一致的功能，同时开启了全部K8s管理权限，接受匿名请求且不保存审计日志。便于攻击者无痕迹的管理整个集群以及下发后续渗透行动。",
      },
      "创建超长annotations使K8s Audit解析失败": {
        description: "过长的annotations可能导致审计日志过大，解析异常。",
      },
    },
  },
  获取凭证: {
    description:
      "获取凭证包括窃取帐户名和密码等凭据的技术，在云原生中，包括窃取k8s secret、敏感配置文件等等。",
    children: {
      暴力破解: {
        description:
          "当密码未知时，攻击者可能会使用暴力破解的方式（比如字典爆破）访问账户、镜像仓库等等，获取敏感凭证。",
      },
      文件中的凭据: {
        description: "",
        children: {
          "获取K8s config文件":
            "Kubernetes 的配置文件通常位于用户主目录下的 .kube/config，这个文件包含了 Kubernetes 集群的连接信息、用户凭证和上下文配置。",
        },
      },
      "云账户/服务凭证泄露": {
        description: "",
        children: {
          "K8s Secret":
            "Kubernetes Secrets 用于存储敏感信息，如密码、OAuth 令牌和 SSH 密钥。一旦泄露，攻击者可以利用其做未授权访问、执行恶意操作等等。可以通过kubectl列出Kubernetes的Secrets资源信息。",
          "K8s Service Account":
            "Service Accounts 为 Pod 提供身份验证。如果Service Accounts 泄露，攻击者可以访问API server，窃取其它secrets。",
          云实例元数据API:
            "云实例元数据 API 提供关于云实例的敏感信息。云服务提供商（如 AWS、GCP、Azure）将实例元数据存储在特定的内部 URL 中。例如，AWS 实例元数据可以通过 http://169.254.169.254/latest/meta-data/ 访问。这些元数据只能在运行该实例的虚拟机内部访问，通常通过特定的 HTTP 请求来获取。",
          "获取AKS service principal":
            "在 AKS 中，服务主体用于身份验证和授权，服务主体信息存储在 Azure Active Directory（AAD）中，凭证（如客户端密钥）通常由用户在创建服务主体时提供。",
        },
      },
      应用层API凭证: {
        description:
          "在一些复杂的业务场景和微服务架构中，Kubernetes 各个服务之间、容器与虚拟机之间通常通过 API 进行通信，比如RESTful API ，并且它们使用了 API 密钥进行身份验证。攻击者有可能通过未授权的访问或代码审计，在配置错误的环境变量中发现该用户服务的 API 密钥。",
      },
      "添加恶意k8s准入控制器（admission controller）": {
        description:
          "“恶意准入控制器”，它实际上是一段代码，在用户请求通过认证授权之后，Kubernetes资源对象持久化之前进行拦截。集群管理员可以通过在kube-apiserver配置文件中指定“--enable-admission-plugins”参数项的值来启用准入控制器。Kubernetes包含许多准入控制器，其中常见的有MutatingAdmissionWebhook和ValidatingAdmissionWebhook准入控制器。它们分别用于拦截并修改Kubernetes API Server请求的对象以及对其对象格式进行校验。近年来，利用准入控制器修改YAML以向业务Pod中添加恶意容器的攻击面变得尤为突出。",
      },
    },
  },
  探测发现: {
    description: "探测发现战术是攻击者发现目标环境是否具有访问权限的技术。",
    children: {
      容器和资源发现: {
        description: "",
        children: {
          "K8s API Server、Docker Remote API、Kubelet":
            "攻击者可以探测访问K8s API Server、Docker Remote API、Kubelet看是否存在未授权访问，具体可参考章节初始访问:外部远程服务。",
          通过NodePort访问Service:
            "NodePort 访问 Kubernetes 中的 Service 是一种常见的方式，可以让外部流量访问集群内部的服务。微服务架构中，各个服务之间往往有信任关系。如果攻击者通过一个被暴露的 NodePort 访问了某个服务，他们可能会利用这个服务与其他服务之间的信任关系进行横向移动。",
        },
      },
      网络服务扫描: {
        description: "容器内端口扫描等等。",
      },
      权限组发现: {
        description: "比如Siloscape检查 Kubernetes 节点权限",
      },
      镜像仓库发现: {
        description:
          "私有镜像仓库可能会暴露，见章节初始访问:外部远程服务。攻击者可以在一些配置文件中找到私有镜像仓库的连接方式，进而访问。",
      },
      访问云厂商服务接口: {
        description:
          "部署到容器中应用程序往往会和多种内外API交互，参考章节初始访问:利用对外开放的（部署到容器/云环境）应用程序，攻击者可以通过这些API做未授权测试。",
      },
    },
  },
  横向移动: {
    description:
      "横向移动战术是指攻击者在目标环境中移动的技术，在云原生环境中，这包括节点间的移动、容器间的移动等等扩大影响范围的行为。",
    children: {
      逃逸到宿主机: {
        description: "参考章节权限提升:容器逃逸。",
      },
      窃取凭证移动: {
        description: "参考章节获取凭证。",
      },
      访问云资源: {
        description: "攻击者可能会从受感染的容器转移到云环境。",
      },
      集群中的网络和服务: {
        description: "",
        children: {
          集群内部网络:
            "攻击者获得集群内某容器访问权限后，可以利用其访问集群内的另外一个容器。",
          CoreDNS投毒:
            "CoreDNS 是一个用 Go 编写的模块化域名系统 (DNS) 服务器，由云原生计算基金会 (CNCF) 托管。CoreDNS 是 Kubernetes 中使用的主要 DNS 服务。CoreDNS 的配置可以通过名为 corefile 的文件进行修改。在 Kubernetes 中，此文件存储在位于 kube-system 命名空间的 ConfigMap 对象中。如果攻击者有权修改 ConfigMap（例如通过使用容器的服务帐户），他们可以更改集群 DNS 的行为、毒害它并窃取其他服务的网络身份。",
          ARP投毒和IP欺骗:
            "Kubernetes 有许多可在集群中使用的网络插件（容器网络接口或 CNI）。Kubenet 是基本的网络插件，在许多情况下是默认的。在此配置中，在每个节点 (cbr0) 上创建一个网桥，各个 Pod 使用 veth 对连接到该网桥。跨 Pod 流量通过网桥（二级组件）传输，这意味着可以在集群中执行 ARP 投毒。因此，如果攻击者可以访问集群中的 Pod，他们就可以执行 ARP 投毒，并欺骗其他 Pod 的流量。通过使用这种技术，攻击者可以在网络级别执行多种攻击，从而导致横向移动，例如 DNS 欺骗或窃取其他 Pod 的云身份 (CVE-2021-1677)。",
        },
      },
      攻击第三方K8s组件: {
        description: "第三方K8s组件可能会引入新的攻击面，进而控制集群。",
      },
    },
  },
  收集: {
    description:
      "收集战术包括攻击者可能用来收集信息的技术以及收集与实现攻击者目标相关的信息来源。\n收集私有仓库中的镜像。集群中运行的镜像可以存储在私有注册表中。为了提取这些镜像，容器运行时引擎（例如 Docker 或 containerd）需要拥有这些注册表的有效凭据。如果注册表由云提供商托管，在 Azure 容器注册表 (ACR) 或 Amazon Elastic Container Registry (ECR) 等服务中，云凭据用于向注册表进行身份验证。如果攻击者获得集群的访问权限，在某些情况下，他们可以访问私有注册表并提取其镜像。例如，攻击者可以使用“访问托管身份凭据”技术中所述的托管身份令牌。同样，在 EKS 中，攻击者可以使用默认绑定到节点 IAM 角色的 AmazonEC2ContainerRegistryReadOnly 策略。",
  },
  危害: {
    description: "危害战术包括攻击者用来破坏、干扰受害者环境的技术。",
    children: {
      资源劫持: {
        description: "攻击者可以利用受害者集群的容器进行挖矿等恶意行为。",
      },
      破坏系统及数据: {
        description: "攻击者可以破坏集群中的数据和资源。",
      },
      拒绝服务: {
        description:
          "攻击者可以通过破坏容器、node、API Server的可用性使正常用户无法使用。",
      },
    },
  },
};
