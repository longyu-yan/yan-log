# yan-log

yan-log是一个用Rust语言开发的轻量级日志库，采用异步输出日志，支持日志级别、按日期时间拆分、按文件大小拆分、自动删除旧文件，建议搭配 log 日志门面使用，
默认情况在 release 模式不会打印日志到控制台，可通过开启 stdout 启动 release 模式的控制台日志打印

## Features（特性）

stdout: 开启 stdout 特性时，release 模式，会和 dev 模式相同打印日志到控制台

## 用法

### 搭配 log 日志门面库使用示例

```rust
fn main() {
    yan_log::Logger::init("logs", yan_log::LogLevel::Debug)
        .set_file_pattern(r#"app_%Y-%m-%d %H：%M：%S-%i.log"#, yan_log::LoggerFormatTimeDivisionRule::Day)
        .start()
        .unwrap();

    // 搭配 log 日志门店使用输出日志
    log::info!("应用已启动");

    // shutdown函数用于程序停止时优雅关闭异步日志线程，将日志完全写入文件，避免日志丢失
    yan_log::Logger::shutdown();
}
```
### 最小运行示例

```rust
const LOG:yan_log::Logger = yan_log::Logger::new(module_path!(), yan_log::LogLevel::Debug);
fn main() {
    yan_log::Logger::init("logs", yan_log::LogLevel::Debug)
        .set_file_pattern(r#"app_%Y-%m-%d %H：%M：%S-%i.log"#, yan_log::LoggerFormatTimeDivisionRule::Day)
        .start()
        .unwrap();

    // 直接输出日志，不使用 log 日志门面
    // 输出的日志级别会优先采用 LOG 变量指定的级别，而不会采用 init 函数指定的日志级别
    LOG.debug("应用已启动");

    // shutdown函数用于程序停止时优雅关闭异步日志线程，将日志完全写入文件，避免日志丢失
    yan_log::Logger::shutdown();
}

```
### 完整使用示例

```rust
fn main() {
    // 初始化全局日志系统
    yan_log::Logger::init("logs", yan_log::LogLevel::Debug)
        // 设置日志文件命名模式和时间分割规则
        .set_file_pattern("app_%Y-%m-%d_%H：%M：%S-%i.log", yan_log::LoggerFormatTimeDivisionRule::Day)
        // 设置日志文件大小触发拆分文件策略（100MB = 104857600B）
        .set_max_file_triggering_policy(104857600)
        // 设置最大保留日志文件数量
        .set_max_retained_files(100)
        // 设置是时间偏移量，北京时间为 utc+8（8小时 = 2880_0000毫秒）
        .set_timezone_offset(2880_0000)
        // 设置日志消息通道的缓冲区大小
        .set_bound(200)
        // 启动日志系统
        .start()
        .unwrap();

    // 记录跟踪日志
    log::trace!("应用已启动");
    // 记录调试日志
    log::debug!("应用已启动");
    // 记录信息日志
    log::info!("应用已启动");
    // 记录警告日志
    log::warn!("应用已启动");
    // 记录错误日志
    log::error!("应用已启动");

    // shutdown函数用于程序停止时优雅关闭异步日志线程，将日志完全写入文件，避免日志丢失
    yan_log::Logger::shutdown();
}

```