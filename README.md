# 🚀 epeius
这是一个基于 CF Worker 平台的脚本，在原版的基础上修改了显示 Trojan 配置信息转换为订阅内容。使用该脚本，你可以方便地将 Trojan 配置信息使用在线配置转换到 Clash 或 Singbox 等工具中。

- **一步到位**部署视频教程：https://youtu.be/MBlAqYajVSY ***小白必看 一步到胃 最佳推荐!!!***
- **自制优选**订阅视频教程：https://youtu.be/jOhq3QpXG_I *折腾自己的专属订阅*
- **进阶使用**技巧视频教程：https://youtu.be/0Cd8uTNJj1Q *然后成为折腾的王*

Telegram交流群：[@CMLiussss](https://t.me/CMLiussss)

## ⚠️ 免责声明

本免责声明适用于 GitHub 上的 “epeius” 项目（以下简称“本项目”），项目链接为：https://github.com/cmliu/epeius 。

### 用途
本项目仅供教育、研究和安全测试目的而设计和开发。旨在为安全研究人员、学术界人士及技术爱好者提供一个探索和实践网络通信技术的工具。

### 合法性
在下载和使用本项目代码时，必须遵守使用者所适用的法律和规定。使用者有责任确保其行为符合所在地区的法律框架、规章制度及其他相关规定。

### 免责
1. 作为本项目的 **二次开发作者**（以下简称“作者”），我 **cmliu** 强调本项目仅应用于合法、道德和教育目的。
2. 作者不认可、不支持亦不鼓励任何形式的非法使用。如果发现本项目被用于任何非法或不道德的活动，作者将对此强烈谴责。
3. 作者对任何人或组织利用本项目代码从事的任何非法活动不承担责任。使用本项目代码所产生的任何后果，均由使用者自行承担。
4. 作者不对使用本项目代码可能引起的任何直接或间接损害负责。
5. 为避免任何意外后果或法律风险，使用者应在使用本项目代码后的 24 小时内删除代码。

通过使用本项目代码，使用者即表示理解并同意本免责声明的所有条款。如使用者不同意这些条款，应立即停止使用本项目。

作者保留随时更新本免责声明的权利，且不另行通知。最新版本的免责声明将发布在本项目的 GitHub 页面上。

## 🔥 风险提示
- 通过提交虚假的节点配置给订阅服务，避免节点配置信息泄露。
- 另外，您也可以选择自行部署 [WorkerVless2sub 订阅生成服务](https://github.com/cmliu/WorkerVless2sub)，这样既可以利用订阅生成器的便利。

## 💡 如何使用?
### ⚙️ Workers 部署方法 [视频教程](https://www.youtube.com/watch?v=MBlAqYajVSY&t=169s)

<details>
<summary><code><strong>「 Workers 部署文字教程 」</strong></code></summary>

1. 部署 CF Worker：
   - 在 CF Worker 控制台中创建一个新的 Worker。
   - 将 [worker.js](https://github.com/cmliu/epeius/blob/main/_worker.js) 的内容粘贴到 Worker 编辑器中。
   - 将第 3 行 `password` 修改成你自己的 **密码**

2. 添加优选线路:
   - 给 `addresses` 按格式添加优选域名/优选IP，若不带端口号 TLS默认端口为443，#号后为备注别名，例如：
     ```js
     let addresses = [
     	//当sub为空时启用本地优选域名/优选IP
     	'www.visa.com.sg#官方优选域名',
     	'www.wto.org:8443#官方优选域名',
     	'visa.cn:2087',
     	'icook.hk',
     ];
     ```
   - 或 给 `sub` 添加 **Trojan优选订阅生成器** 地址，例如：
     ```js
     let sub = 'Trojan.cmliussss.net';
     ```

3. 访问订阅内容：
   - 访问 `https://[YOUR-WORKERS-URL]/[PASSWORD]` 即可获取订阅内容。
   - 例如 `https://trojan.google.workers.dev/auto` 就是你的通用自适应订阅地址。
   - 例如 `https://trojan.google.workers.dev/auto?sub` Base64订阅格式，适用PassWall,SSR+等。
   - 例如 `https://trojan.google.workers.dev/auto?clash` Clash订阅格式，适用OpenClash等。
   - 例如 `https://trojan.google.workers.dev/auto?sb` singbox订阅格式，适用singbox等。

4. 给 workers绑定 自定义域： 
   - 在 workers控制台的 `触发器`选项卡，下方点击 `添加自定义域`。
   - 填入你已转入 CF 域名解析服务的次级域名，例如:`trojan.google.com`后 点击`添加自定义域`，等待证书生效即可。

</details>

### 🛠 Pages 上传 部署方法

<details>
<summary><code><strong>「 Pages 上传文件部署文字教程 」</strong></code></summary>

1. 部署 CF Pages：
   - 下载 [main.zip](https://github.com/cmliu/epeius/archive/refs/heads/main.zip) 文件，并点上 Star !!!
   - 在 CF Pages 控制台中选择 `上传资产`后，为你的项目取名后点击 `创建项目`，然后上传你下载好的 [main.zip](https://github.com/cmliu/epeius/archive/refs/heads/main.zip) 文件后点击 `部署站点`。
   - 部署完成后点击 `继续处理站点` 后，选择 `设置` > `环境变量` > **制作**为生产环境定义变量 > `添加变量`。
     变量名称填写**PASSWORD**，值则为你的密码，后点击 `保存`即可。
   - 返回 `部署` 选项卡，在右下角点击 `创建新部署` 后，重新上传 [main.zip](https://github.com/cmliu/epeius/archive/refs/heads/main.zip) 文件后点击 `保存并部署` 即可。

2. 添加优选线路:
 - 添加变量 `ADD` 本地静态的优选线路，若不带端口号 TLS默认端口为443，#号后为备注别名，例如：
   ```
   12315.cf.090227.xyz:443#加入我的频道t.me/CMLiussss解锁更多优选节点
   visa.cn#你可以只放域名 如下
   www.visa.com.sg
   time.is#也可以放域名带端口 如下
   www.wto.org:8443
   chatgpt.com:2087#节点名放在井号之后即可
   icook.hk#若不带端口号默认端口为443
   104.17.152.41#IP也可以
   [2606:4700:e7:25:4b9:f8f8:9bfb:774a]#IPv6也OK
   ```

3. 访问订阅内容：
   - 访问 `https://[YOUR-PAGES-URL]/[PASSWORD]` 即可获取订阅内容。
   - 例如 `https://epeius.pages.dev/auto` 就是你的通用自适应订阅地址。
   - 例如 `https://epeius.pages.dev/auto?sub` Base64订阅格式，适用PassWall,SSR+等。
   - 例如 `https://epeius.pages.dev/auto?clash` Clash订阅格式，适用OpenClash等。
   - 例如 `https://epeius.pages.dev/auto?sb` singbox订阅格式，适用singbox等。
   - 例如 `https://epeius.pages.dev/auto?surge` surge订阅格式，适用surge 4/5。

4. 给 Pages绑定 CNAME自定义域：
   - 在 Pages控制台的 `自定义域`选项卡，下方点击 `设置自定义域`。
   - 填入你的自定义次级域名，注意不要使用你的根域名，例如：
     您分配到的域名是 `fuck.cloudns.biz`，则添加自定义域填入 `lizi.fuck.cloudns.biz`即可；
   - 按照 CF 的要求将返回你的域名DNS服务商，添加 该自定义域 `lizi`的 CNAME记录 `epeius.pages.dev` 后，点击 `激活域`即可。

</details>

### 🛠 Pages GitHub 部署方法 [视频教程](https://www.youtube.com/watch?v=0Cd8uTNJj1Q&t=96s)

<details>
<summary><code><strong>「 Pages GitHub 部署文字教程 」</strong></code></summary>

1. 部署 CF Pages：
   - 在 Github 上先 Fork 本项目，并点上 Star !!!
   - 在 CF Pages 控制台中选择 `连接到 Git`后，选中 `epeius`项目后点击 `开始设置`。
   - 在 `设置构建和部署`页面下方，选择 `环境变量（高级）`后并 `添加变量`，
     变量名称填写**PASSWORD**，值则为你的密码，后点击 `保存并部署`即可。

2. 添加优选线路:
 - 添加变量 `ADD` 本地静态的优选线路，若不带端口号 TLS默认端口为443，#号后为备注别名，例如：
   ```
   12315.cf.090227.xyz:443#加入我的频道t.me/CMLiussss解锁更多优选节点
   visa.cn#你可以只放域名 如下
   www.visa.com.sg
   time.is#也可以放域名带端口 如下
   www.wto.org:8443
   chatgpt.com:2087#节点名放在井号之后即可
   icook.hk#若不带端口号默认端口为443
   104.17.152.41#IP也可以
   [2606:4700:e7:25:4b9:f8f8:9bfb:774a]#IPv6也OK
   ```

3. 访问订阅内容：
   - 访问 `https://[YOUR-PAGES-URL]/[PASSWORD]` 即可获取订阅内容。
   - 例如 `https://epeius.pages.dev/auto` 就是你的通用自适应订阅地址。
   - 例如 `https://epeius.pages.dev/auto?sub` Base64订阅格式，适用PassWall,SSR+等。
   - 例如 `https://epeius.pages.dev/auto?clash` Clash订阅格式，适用OpenClash等。
   - 例如 `https://epeius.pages.dev/auto?sb` singbox订阅格式，适用singbox等。
   - 例如 `https://epeius.pages.dev/auto?surge` surge订阅格式，适用surge 4/5。

4. 给 Pages绑定 CNAME自定义域：
   - 在 Pages控制台的 `自定义域`选项卡，下方点击 `设置自定义域`。
   - 填入你的自定义次级域名，注意不要使用你的根域名，例如：
     您分配到的域名是 `fuck.cloudns.biz`，则添加自定义域填入 `lizi.fuck.cloudns.biz`即可；
   - 按照 CF 的要求将返回你的域名DNS服务商，添加 该自定义域 `lizi`的 CNAME记录 `epeius.pages.dev` 后，点击 `激活域`即可。
   
</details>

## 🔑 变量说明
| 变量名 | 示例 | 备注 |
|--------|---------|-----|
| PASSWORD | `auto` | 可以取任意值 |
| SCV | `false`或`0` | 是否跳过TLS证书验证(默认`true`开启跳过证书验证) |
| PROXYIP | `proxyip.cmliussss.net:443` | 备选作为访问CFCDN站点的代理节点(支持多ProxyIP, ProxyIP之间使用`,`或`换行`作间隔) |
| HTTP  | `user:password@127.0.0.1:8080`或`127.0.0.1:8080` | 优先作为访问CFCDN站点的HTTP代理(支持多HTTP代理之间使用`,`或`换行`作间隔) |
| SOCKS5  | `user:password@127.0.0.1:1080`或`127.0.0.1:1080` | 优先作为访问CFCDN站点的SOCKS5代理(支持多socks5, socks5之间使用`,`或`换行`作间隔) |
| GO2SOCKS5  | `blog.cmliussss.com`,`*.ip111.cn`,`*google.com` | 设置`SOCKS5`或`HTTP`变量之后，可设置强制使用socks5访问名单(设置为`*`可作为全局代理) |
| NAT64 | `dns64.cmi.ztvi.org`或`2001:67c:2960:6464::/96` | 作为PROXYIP失效后的应急兜底，自行查询[nat64.xyz](https://nat64.xyz/)的`DNS64 Server`或`NAT64 Prefix` |
| ADD | `www.csgo.com:2087`,`icook.hk` | 本地优选域名/优选IP(支持多元素之间`,`或`换行`作间隔) |
| ADDAPI | [https://raw.github.../addressesapi.txt](https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt) | 不解释, 懂得都懂 |
| ADDCSV | [https://raw.github.../addressescsv.csv](https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressescsv.csv) | 不解释, 懂得都懂 |
| DLS | `8` | `ADDCSV`测速结果满足速度下限 | 
| CSVREMARK | `1` | CSV备注所在列偏移量 |
| TGTOKEN | `6894123456:XXXXXXXXXX0qExVsBPUhHDAbXXXXXqWXgBA` | 发送TG通知的机器人token | 
| TGID | `6946912345` | 接收TG通知的账户数字ID | 
| SUB | `Trojan.cmliussss.net` | 优选订阅生成器域名(使用订阅器将放弃`ADD`内的本地优选订阅内容) |
| SUBAPI | `SUBAPI.cmliussss.net` | clash、singbox等 订阅转换后端 |
| SUBCONFIG | [https://raw.github.../ACL4SSR_Online_Mini.ini](https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini.ini) | clash、singbox等 订阅转换配置文件 |
| SUBEMOJI | `false` | 订阅转换是否启用Emoji(默认`true`) |
| SUBNAME | `epeius` | 订阅名称 | 
| RPROXYIP | `false` | 设为 true 即可强制获取订阅器分配的ProxyIP(需订阅器支持)|
| URL302 | `https://t.me/CMLiussss` | 主页302跳转(支持多url, url之间使用`,`或`换行`作间隔, 小白别用) |
| URL | `https://blog.cmliussss.com` | 主页反代伪装(支持多url, url之间使用`,`或`换行`作间隔, 乱设容易触发反诈) |
| CFPORTS | `2053`,`2096`,`8443` | CF账户标准端口列表 |
| CF_EMAIL | `admin@google.com` | CF账户的邮箱，用于获取 Workers/Pages 请求数 |
| CF_APIKEY | `1234567890abcdef1234567890abcdef` | CF账户的`Global API Key`，用于获取 Workers/Pages 请求数 |

> **注意：** 只有 `CF_EMAIL` 和 `CF_APIKEY` 变量同时存在时，订阅时才会返回 CF Workers/Pages 的请求数用量信息。

## ❗ 注意事项

### 开启在线编辑优选列表
- 绑定名为`KV`的KV空间，即可在无`SUB`的前提下，在配置页实现在线编辑`ADD`与`ADDAPI`优选列表；

### **关于`SOCKS5`与`PROXYIP`：**
- 填入`SOCKS5`后，将停用`PROXYIP`。请确保**二者选其一使用**！

### **关于`SUB`与`ADD*`变量：**
- 填入`SUB`后，将停用由`ADD*`类变量生成的订阅内容。请确保**二者选其一使用**！

### **当`SUB`和`ADD*`均为空时：**
- 脚本将自动生成基于CF随机IP的线路，每次更新订阅时会生成不同的随机IP，确保您的订阅不会失联！

## 🔧 实用技巧
本项目提供灵活的订阅配置方案，支持通过URL参数快速自定义订阅内容。
- 示例订阅地址： `https://epeius.pages.dev/auto` 

1. 更换**订阅生成器**的订阅地址

   快速切换订阅生成器至 `Trojan.cmliussss.net`：
   ```url
   https://epeius.pages.dev/auto?sub=Trojan.cmliussss.net
   ```

2. 更换**PROXYIP**的订阅地址

   快速更换PROXYIP为 `proxyip.cmliussss.net`：
   ```url
   https://epeius.pages.dev/auto?proxyip=proxyip.cmliussss.net
   ```

3. 更换**SOCKS5**的订阅地址

   快速设置SOCKS5代理为 `user:password@127.0.0.1:1080`：
   ```url
   https://epeius.pages.dev/auto?socks5=user:password@127.0.0.1:1080
   ```

- 通过提交多个参数快速修改的订阅地址

   例如同时修改**订阅生成器**和**PROXYIP**：
   ```url
   https://epeius.pages.dev/auto?sub=Trojan.cmliussss.net&proxyip=proxyip.cmliussss.net
   ```

4. 该项目部署的节点可通过节点PATH(路径)的方式，使用指定的`PROXYIP`或`SOCKS5`！！！**

- 指定 `PROXYIP` 案例
   ```url
   /proxyip=proxyip.cmliussss.net
   /?proxyip=proxyip.cmliussss.net
   /proxyip.cmliussss.net (仅限于域名开头为'proxyip.'的域名)
   ```

- 指定 `SOCKS5` 案例
   ```url
   /socks5=user:password@127.0.0.1:1080
   /?socks5=user:password@127.0.0.1:1080
   /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (默认激活全局SOCKS5)
   /socks5://user:password@127.0.0.1:1080 (默认激活全局SOCKS5)
   ```

- 指定 `HTTP代理` 案例
   ```url
   /http://user:password@127.0.0.1:8080 (默认激活全局SOCKS5)
   ```

5. **当你的`ADDAPI`可作为`PROXYIP`时，可在`ADDAPI`变量末位添加`?proxyip=true`，即可在生成节点时使用优选IP自身作为`PROXYIP`**
- 指定 `ADDAPI` 作为 `PROXYIP` 案例
   ```url
   https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt?proxyip=true
   ```

## ⭐ Star 星星走起
[![Stargazers over time](https://starchart.cc/cmliu/epeius.svg?variant=adaptive)](https://starchart.cc/cmliu/epeius)

## 💻 已适配客户端
### Windows
   - [v2rayN](https://github.com/2dust/v2rayN)
   - clash.meta（[FlClash](https://github.com/chen08209/FlClash)，[mihomo-party](https://github.com/mihomo-party-org/mihomo-party)，[clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev)，[Clash Nyanpasu](https://github.com/keiko233/clash-nyanpasu)）
### IOS
   - Surge，小火箭
   - sing-box（[SFI](https://sing-box.sagernet.org/zh/clients/apple/)）
### 安卓
   - clash.meta（[ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid)，[FlClash](https://github.com/chen08209/FlClash)）
   - sing-box（[SFA](https://github.com/SagerNet/sing-box)）
### MacOS
   - clash.meta（[FlClash](https://github.com/chen08209/FlClash)，[mihomo-party](https://github.com/mihomo-party-org/mihomo-party)）


# 🙏 特别鸣谢
### 💖 赞助支持 - 提供云服务器维持[订阅转换服务](https://sub.cmliussss.net/)
- [Alice Networks LTD](https://url.cmliussss.com/alice)
- [VTEXS Enterprise Cloud](https://console.vtexs.com/?affid=1532)
### 🛠 开源代码引用
- [ca110us](https://github.com/ca110us/epeius)
- [xream](https://github.com/xream)
- [zizifn](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP](https://github.com/6Kmfi6HP/EDtunnel)
- [emn178](https://github.com/emn178/js-sha256)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [SHIJS1999](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [股神](https://t.me/CF_NAT/38889)
- [Workers/Pages Metrics](https://t.me/zhetengsha/3382)
- [白嫖哥](https://t.me/bestcfipas)