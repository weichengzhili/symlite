# SymLite

> 面向嵌入式 Linux 的可移植、非阻塞 eBPF 符号解析与栈聚合引擎

[![CI](https://img.shields.io/badge/ci-passing-green)]()
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)]()
[![BPF: GPL-2.0](https://img.shields.io/badge/bpf--progs-GPL--2.0-orange)]()
[![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow)]()

## 1. 概述

SymLite 是一个运行在嵌入式 Linux 目标设备上的轻量级 eBPF 可观测性基础设施组件。
它不提供完整的可观测平台，而是提供**可观测数据的"内核态预处理层"**：在数据离开
内核之前完成符号归一化、栈聚合与去重；在探针加载之前完成符号解析的离线化与缓存化；
在 BTF 不可用时提供经过工程验证的降级路径。

**设计目标**：让 eBPF 可观测能力在 ARM64/RISC-V、资源受限、内核碎片化的嵌入式环境中，
从"能跑通"变为"敢长期开着"。

## 2. 背景与量化痛点

| 编号 | 痛点 | 量化证据 | 影响 |
|---|---|---|---|
| P1 | attach 时符号解析阻塞 | 50 个精确名称 kprobe 在未优化内核上 attach 耗时 7488 ms；仅 libbpf 侧补丁后仍需 858 ms，`kallsyms` 路径占 25% CPU | 嵌入式节点动态加载探针时造成保护窗口缺失或控制周期错过 |
| P2 | 符号化与栈展开开销被反复支付 | 逐样本用户态符号化成本随采样频率线性增长 | 高频采样下 CPU/内存开销失控，被迫降低采样率而失去可观测性 |
| P3 | 内核碎片化导致静默失效 | 大量嵌入式内核无 `CONFIG_DEBUG_INFO_BTF`；`isra.*` 后缀、内联行为、hook 可用性差异大 | 探针换 BSP 后静默不产出数据，无告警 |
| P4 | 资源约束下开销无自适应 | 嵌入式设备内存/CPU 预算紧张，工具自身可能成为扰动源 | 运维需手工调参，难以规模化 |

## 3. 目标与非目标

### 3.1 目标

- **G1** 将 50 符号批量 attach 端到端耗时降至 **≤ 50 ms**（P1）
- **G2** 稳态下 BPF 程序自身 CPU 开销 **≤ 1.5%**（P2，ARM64 单板，1k syscall/s 负载）
- **G3** 在无 BTF 内核上，同一 eBPF 对象无需重编译即可部署，符号化失败以显式指标暴露而非静默丢弃（P3）
- **G4** 提供开销感知的自适应采样控制器，超预算时自动降级并可审计（P4）
- **G5** 核心 BPF 侧改动保持最小，解析/聚合/回退复杂度留在用户态，阶段一优化可上游化

### 3.2 非目标

- 不做全栈可观测平台（不与 Beyla/Pixie/Tetragon 竞争上层功能）
- 不提供安全策略阻断能力（不属于 Tetragon/Falco 的运行时安全范畴）
- 不替代 bpftrace 的交互式一次性诊断场景
- 阶段一不追求支持 32 位内核

## 4. 架构

SymLite 采用四层架构，每层对应一组被验证的痛点。
### 4.1 Layer 1 — 离线符号解析与缓存层

- **职责**：在部署准备阶段从 `/proc/kallsyms` 或 `System.map` 一次性提取所需符号，
  构建 mmap 友好的紧凑二进制索引（`symlite-symidx`），运行时 attach 直接读取地址。
- **关键设计**：
    - 索引格式带版本号与 build-ID 绑定，缓存与内核不匹配时拒绝使用并回退
    - 对必须走内核解析的批量场景，复用并封装 `ftrace_lookup_symbols()` 的 `cnt == 1`
      快速路径（O(log N) 二分），避免 O(N) 全量扫描
    - 缓存文件带完整性校验（BLAKE3 摘要），防止损坏索引导致错误 attach

### 4.2 Layer 2 — 可移植符号与栈信息回退层

- **职责**：按内核 build-ID 索引外部符号/栈元数据；无 BTF 时提供可复现的回退路径。
- **关键设计**：
    - 元数据仓库按 `(arch, build_id, kernel_version)` 三元组索引
    - 栈展开不假设 frame pointer：采集侧记录栈地址序列，用户态基于 `.eh_frame`/ORC
      unwind tables 回溯
    - 无法符号化的帧标记为 `[unknown:0xADDR]`，并计入 `unsymbolized_frames_total`
      指标；**禁止静默丢弃**
    - 若元数据缺失，启动阶段输出显式 `DEGRADED` 状态并通过指标暴露

### 4.3 Layer 3 — 内核态最小化采集与聚合层

- **职责**：热路径只做最小必要工作；聚合下沉到 BPF map。
- **关键设计**：
    - 聚合键 = `hash(stack_addrs) XOR symbol_cache_id`，用户态仅对**唯一栈**符号化一次
    - per-CPU map 暂存，用户态批量 drain，减少 ring buffer 压力
    - map 内存上限硬约束（默认 16 MB，可配置），超限触发丢弃计数并告警
    - 延迟直方图采用对数分桶，固定内存占用

### 4.4 Layer 4 — 嵌入式自适应控制层

- **职责**：将"工具自身扰动"纳入预算管理。
- **关键设计**：
    - 监测项：BPF 程序执行时间聚合、map 占用、用户态符号化队列积压
    - 三态状态机：`NORMAL → THROTTLED → AGGREGATE_ONLY`，每态有明确进入/退出条件
    - 所有状态跃迁写入结构化审计日志（含触发指标值与时间戳）
    - 控制器参数有硬上限，禁止配置成"永不降级"

## 5. 关键设计决策（ADR 摘要）

| ADR | 决策 | 权衡 |
|---|---|---|
| ADR-001 | 用户态选用 Rust，BPF 侧选用 C + libbpf CO-RE | 静态链接、无 GC、交叉编译成熟；libbpf-rs 提供工业级 API。代价：团队需 Rust 能力 |
| ADR-002 | 双许可证：用户态 Apache-2.0，BPF 程序 GPL-2.0 | BPF 程序使用 GPL-only helper 需 GPL 兼容声明；用户态保持宽松许可便于集成 |
| ADR-003 | 符号索引采用自定义二进制格式而非直接复用 BTF | BTF 在嵌入式中普遍缺失；自定义格式可 mmap、可校验、可版本化 |
| ADR-004 | 聚合下沉到内核 map，而非用户态聚合 | 减少上下文切换与拷贝；代价是 map 内存需硬约束与淘汰策略 |
| ADR-005 | 不支持"永不降级"配置 | 防止工具自身成为生产事故源；可观测性必须让位于业务可用性 |
| ADR-006 | 阶段一内核改动以独立补丁提交 bpf-next，不进主仓 | 保持上游友好，降低下游维护负担 |

## 6. 兼容性矩阵

| 维度 | 支持范围 | 验证方式 |
|---|---|---|
| 架构 | aarch64, riscv64（阶段三起） | QEMU + 实体板卡 |
| 内核版本 | 5.15 LTS, 6.1 LTS, 6.6 LTS, 6.12 LTS | 每版本 CI 矩阵 |
| BTF | 有 BTF / 无 BTF 两种路径 | 专项 e2e |
| libc | glibc, musl（静态链接） | 交叉编译产物测试 |
| 构建系统宿主 | Debian/Ubuntu, Yocto kirkstone+ | CI + Yocto 层集成测试 |
| eBPF 加载器 | libbpf ≥ 1.4 | 版本探测与明确报错 |

> 兼容性矩阵是发布门禁：任何 PR 导致矩阵中任一格从 pass 变 fail，CI 阻断合并。

## 7. 性能预算（发布门禁）

| 指标 | 目标 | 测量方法 |
|---|---|---|
| 50 符号 attach 端到端 | ≤ 50 ms | `bench/attach_latency` |
| 稳态 CPU（1k syscall/s） | ≤ 1.5% | `bench/steady_state` on RPi5 |
| 常驻内存 | ≤ 20 MB | RSS 采样 |
| 符号化队列 P99 延迟 | ≤ 100 ms | 内部指标 |
| 符号索引加载时间 | ≤ 5 ms | 启动计时 |

性能回归超过预算 10% 即阻断发布。

## 8. 安全与合规

- **SBOM**：每次发布生成 SPDX JSON，随制品归档
- **CVE 响应**：依赖树纳入 `cargo-audit` + 内核 CVE 跟踪；`SECURITY.md` 定义 72h 响应 SLA
- **签名**：发布制品 GPG 签名，校验和随 `SHA256SUMS` 发布
- **最小权限**：默认以专用非 root 用户运行，能力集最小化（CAP_BPF/CAP_PERFMON 按需）
- **数据面**：默认不采集进程参数、路径等敏感字段；提供字段级开关
- **审计**：控制器状态跃迁与配置变更全量审计日志

## 9. 构建与部署

- **构建**：`cargo` workspace + `bpf/` 独立 Makefile；统一入口 `just build` / `make build`
- **交叉编译**：`cross` 或自定义 sysroot；产物为静态链接 musl 二进制 + `.bpf.o`
- **打包**：
    - `deb` / `rpm` / `apk` 包
    - Yocto 层 `meta-symlite`（`deploy/yocto/`）
    - 容器镜像（仅用于构建与测试，不推荐目标设备运行）
- **部署形态**：systemd unit（`deploy/systemd/`）、Ansible role、Yocto image 集成
- **配置**：TOML 主配置 + 环境变量覆盖；`symlite config validate` 子命令

## 10. 测试策略

| 层级 | 内容 | 工具 |
|---|---|---|
| 单元 | 符号索引编解码、聚合键哈希稳定性、控制器状态机 | `cargo test` |
| 集成 | libbpf 加载、map 生命周期、drain 路径 | `tests/integration` + QEMU |
| e2e | 有/无 BTF 内核、三架构、attach 全流程 | `tests/e2e` + 实体板卡矩阵 |
| 基准 | 性能预算全项 | `tests/benchmark` + criterion |
| 模糊 | 符号索引解析器、配置文件解析器 | `cargo-fuzz` |
| 稳定性 | 72h 长稳 + 内存泄漏检测 | nightly job |

## 11. 发布与版本

- 语义化版本；`0.x` 阶段 API 可破坏但需 CHANGELOG 明示
- 每季度一个 minor，安全修复走 patch
- 支持窗口：最近 3 个 minor + 最近 2 个 LTS 内核矩阵
- 灰度：配置兼容性在 minor 间保证；索引格式带版本号，跨版本不兼容时明确拒绝并提示重建

## 12. 路线图

| 阶段 | 周期 | 交付 | 成功指标 |
|---|---|---|---|
| M1 | 0–3 月 | 符号预解析缓存 + 内核单符号快速路径验证 | attach ≤ 50 ms |
| M2 | 3–8 月 | BPF 采集 + 用户态聚合流水线 | CPU ≤ 1.5%，RSS ≤ 20 MB |
| M3 | 8–12 月 | 回退机制 + 自适应控制器 + 导出接口 | 3 内核版本跨 BTF 部署成功 |

## 13. 贡献

见 `CONTRIBUTING.md`。所有代码变更需：通过 CI 矩阵、附基准数据（性能相关）、
更新 CHANGELOG、ADR（架构相关）。提交信息遵循 Conventional Commits。

## 14. 许可证

用户态：Apache-2.0；BPF 程序：GPL-2.0。详见 `LICENSE` 与 `NOTICE`。