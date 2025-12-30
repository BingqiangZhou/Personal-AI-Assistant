# 使用 Docker 临时生成 Android `release.keystore`（JDK 容器）

目标：不在本机安装 JDK，只用一个临时 JDK Docker 容器生成 `release.keystore`，导出到本机后删除容器（可选也删除镜像）。

> **安全提醒**：`release.keystore` 是发布签名私钥容器文件，请妥善保管，**不要提交到公开仓库**。建议用 GitHub Secrets 保存（后文有示例）。

---

## 前置条件

- 已安装并可用 `docker`
- 在 Windows：建议在 **PowerShell** 或 **Git Bash** 中执行（下文同时给出要点）

---

## 方案 A（推荐）：一次性 `docker run` + 挂载目录（生成完自动删容器）

在你希望保存 `release.keystore` 的目录下执行：

### 1) 生成 keystore 到本机当前目录

```bash
docker run --rm -it   -v "$PWD:/out"   eclipse-temurin:17-jdk   keytool -genkeypair -v     -keystore /out/release.keystore     -alias release     -keyalg RSA -keysize 2048     -validity 10000     -storetype JKS
```

执行过程中会交互提示你输入：

- **Keystore 密码**（对应 `storePassword`）
- **Key 密码**（对应 `keyPassword`，直接回车可与 keystore 密码相同）
- 证书信息（姓名/组织/城市等，可按需填写）

完成后，你会在当前目录看到：

- `release.keystore`

### 2) 验证 keystore（可选）

```bash
docker run --rm -it   -v "$PWD:/out"   eclipse-temurin:17-jdk   keytool -list -v -keystore /out/release.keystore -alias release
```

---

## 方案 B：先开容器，里面生成，再 `docker cp` 拷出来（更啰嗦）

### 1) 启动容器

```bash
docker run -it --name jdk-tmp eclipse-temurin:17-jdk bash
```

### 2) 容器内生成

```bash
keytool -genkeypair -v   -keystore /tmp/release.keystore   -alias release   -keyalg RSA -keysize 2048   -validity 10000   -storetype JKS
exit
```

### 3) 拷贝到本机

```bash
docker cp jdk-tmp:/tmp/release.keystore ./release.keystore
```

### 4) 删除容器

```bash
docker rm jdk-tmp
```

---

## 可选：删除 JDK Docker 镜像（省空间）

如果你不再需要该镜像：

```bash
docker rmi eclipse-temurin:17-jdk
```

---

## 后续（推荐）：用于 GitHub Actions 固定签名

你的 `key.properties` 中通常会配置：

```properties
storeFile=../release.keystore
keyAlias=release
```

这意味着 CI 里需要把 `release.keystore` 放在 **项目根目录**（相对 `android/key.properties` 的 `../`）。

### Windows：把 keystore 转 base64（准备写入 GitHub Secrets）

在 `release.keystore` 所在目录打开 PowerShell：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("release.keystore")) | Set-Content -NoNewline "release.keystore.b64"
```

然后把 `release.keystore.b64` 的内容复制到 GitHub Secrets：

- `ANDROID_KEYSTORE_B64`
- `KEYSTORE_PASSWORD`
- `KEY_PASSWORD`
- `KEY_ALIAS`

### Actions：解码成 `release.keystore`（放在项目根目录）

```yaml
- name: Restore keystore
  shell: bash
  run: |
    echo "${{ secrets.ANDROID_KEYSTORE_B64 }}" | base64 --decode > release.keystore

- name: Write key.properties
  shell: bash
  run: |
    cat > android/key.properties <<EOF
    storeFile=../release.keystore
    storePassword=${{ secrets.KEYSTORE_PASSWORD }}
    keyAlias=${{ secrets.KEY_ALIAS }}
    keyPassword=${{ secrets.KEY_PASSWORD }}
    EOF
```

---

## 常见问题排查

- **Gradle 找不到 keystore**：确认 `storeFile=../release.keystore` 对应的实际路径是项目根目录的 `release.keystore`。
- **安装报签名冲突（package conflicts）**：通常是手机上已有同包名但不同签名的安装包。确保每次构建都使用同一 keystore 签名，或卸载旧包/使用不同 flavor 包名。
