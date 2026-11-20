# OCI Image Unpacker

离线排查容器文件缺失时，从交付镜像还原最终根文件系统的服务。
上传仅含单个 manifest 的 OCI Image Layout tar，当次请求返回还原后的 `rootfs.tar`。

同时提供**差分层接口** `POST /diff`：隔离网内已存在旧镜像时，只送入一份可追加到
旧镜像之上的未压缩 OCI 层 tar，即可把旧镜像的文件系统更新为目标镜像，无需重传整镜像。

## 快速开始（docker compose）

```bash
docker compose up --build
```

服务监听 <http://localhost:8000>，打开 <http://localhost:8000/docs>：

1. 先调 `GET /sample-image` 下载样例镜像 `sample-image.tar`（Swagger 里点 "Download file"）；
2. 再在 `POST /unpack` 里上传该 tar，响应即为 `rootfs.tar`；
3. 在 `POST /diff` 里分别上传**同平台**的旧镜像（`old_image`）与目标镜像
   （`new_image`），响应即为可追加的未压缩差分层 `diff-layer.tar`。

命令行等价操作：

```bash
curl -OJ http://localhost:8000/sample-image          # 下载样例镜像
curl -F "file=@sample-image.tar" -OJ \
     http://localhost:8000/unpack                    # 得到 rootfs.tar
tar -tf rootfs.tar                                   # 查看还原结果

# 差分层：old.tar 与 new.tar 均为单 manifest OCI Image Layout tar，且同平台
curl -F "old_image=@old.tar" -F "new_image=@new.tar" -OJ \
     http://localhost:8000/diff                      # 得到 diff-layer.tar
tar -tvf diff-layer.tar                              # 查看差分层内容
```

本地开发（不用 Docker）：

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
pytest                 # 运行测试
```

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/unpack` | 上传 OCI Image Layout tar（单 manifest），返回 `rootfs.tar`；任何校验/解包失败返回 400，不返回残缺文件系统 |
| `POST` | `/diff` | 上传同平台的旧镜像与目标镜像（均为单 manifest OCI Image Layout tar），返回可追加到旧镜像的**未压缩** OCI 层 `diff-layer.tar`；校验、生成或试叠失败只返回 400 错误 |
| `GET` | `/sample-image` | 下载样例镜像（含删除、opaque、硬链接覆盖） |
| `GET` | `/healthz` | 健康检查 |

## 差分层（`/diff`）语义

- **输入复用 `/unpack` 校验**：两份镜像都按单 manifest OCI Image Layout 校验
  blob 存在性、字节大小、SHA-256 与 config `rootfs.diff_ids`（gzip 层先解压）；
  并比对 `os` / `architecture` / `variant`，平台不一致直接报错。
- **仅支持四类条目**：普通文件、目录、符号链接，以及指向普通文件的硬链接；
  出现 FIFO、设备节点等其它类型整次请求失败。
- **删除用 whiteout 表达**：删除路径生成 `.wh.<name>`；目录被整体替换时只对
  该目录发一个 whiteout（下层整棵子树一并消失），不产生冗余子项 whiteout。
- **目录与文件互换**：先 whiteout 旧条目再写入新条目；whiteout 只作用于下层
  状态，因此同层新增内容必定保留。
- **未变内容沿用旧层**：字节与元数据完全未变的普通文件、成员集合与内容完全
  未变的硬链接组，差分层里不产生任何条目。
- **硬链接可拆可合，与字节是否相同无关**：硬链接分组独立于内容比较。即使
  字节完全相同，也能把一个硬链接组拆成独立文件，或把多个独立文件合并/重组成
  新的硬链接组。能复用下层同字节同元数据的独立文件作锚点时，不重复发送内容。
- **按块处理**：文件内容以 1 MiB 为块流式哈希与读写，不把整个文件载入内存。
- **试叠通过才返回**：服务先把生成的层叠到旧镜像上，做两道核对——
  1. 与权限无关的内存逻辑叠层，逐项核对路径集合、条目类型、文件字节、普通文件
     与目录的权限位、数字 UID/GID、秒级 mtime、符号链接文本以及硬链接分组；
  2. 用与 `/unpack` 相同的代码路径在磁盘上真实试叠，核对路径、类型、权限、
     文件字节与符号链接。
  两者全部一致才返回层 tar；任何校验、生成或试叠失败都只返回错误，不返回层。
- **未压缩输出**：差分层为未压缩 PAX tar（mediaType 对应
  `application/vnd.oci.image.layer.v1.tar`），可直接作为新层追加进镜像 manifest。

## 校验与还原语义

- **完整性校验**：index.json 引用的 manifest blob、manifest 引用的 config 与
  各 layer blob 都会核对**存在性、字节大小、SHA-256**；每个 layer 解压后
  （gzip 层先解压）再与 config 中 `rootfs.diff_ids` 逐一核对。层数与
  diff_ids 数量不一致、摘要不符、缺块、损坏，整次请求报错。
- **层格式**：支持未压缩层（`...layer.v1.tar`）与 gzip 层
  （`...layer.v1.tar+gzip`，含 docker 对应 mediaType）。
- **按清单层序还原**：普通文件、目录、符号链接、硬链接与权限位（含
  setuid/sgid/sticky）；目录权限与 mtime 在全部层应用完后统一设置，避免
  只读目录阻断同层/上层写入。
- **whiteout / opaque**：每层先扫描全部条目，把 `.wh.<name>` 与
  `.wh..wh..opq` 的删除动作**只作用于下层文件系统**，然后再写入本层新
  内容。因此删除标记在层内的位置（文件前/后）不会影响同层新增文件。
- **硬链接覆盖安全**：新文件先写临时文件再 `rename` 替换，绝不原地截断，
  所以覆盖硬链接的一端时，另一端保留原字节。输出 tar 中仍共享 inode 的
  硬链接会以硬链接条目保留。
- **路径安全**：条目路径拒绝绝对路径与 `..`；符号链接目标（绝对目标按
  rootfs 内解释）与硬链接目标经解析后必须落在隔离目录内，写入前再随
  符号链接逐层解析校验，任何逃逸都会让整次请求失败。
- **请求隔离**：每个请求使用独立临时目录，失败即清理，成功响应发送后
  清理；请求之间互不影响。

## 样例镜像内容

两层（第一层 gzip，第二层未压缩），用于验证上述语义：

- 下层文件 `app/config.txt`、`app/data/remove.txt` 被 whiteout 删除；
- `secret/` 被标记 opaque：下层的 `secret/token.txt` 消失，同层新增的
  `secret/public.txt` 保留；
- `app/data/rebuilt.txt` 在同层先写新内容、后出现其 whiteout —— 新内容
  必须保留；
- `bin/tool` 与 `bin/tool-link` 在下层是同一硬链接，上层只覆盖
  `bin/tool`（`tool-v2`），`bin/tool-link` 必须仍是 `tool-v1`；
- 相对符号链接 `bin/tool-alias -> tool` 与绝对符号链接
  `etc/motd-link -> /etc/motd`；
- 权限位：`bin/tool` 0755、`secret/` 0700。

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `UNPACK_WORKDIR` | `$TMPDIR/oci-unpacker` | 请求临时目录与样例镜像存放位置 |
