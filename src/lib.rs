pub mod unit;

use crate::unit::{
    find_log_files, format_u16_as_padded_3_digits, format_u8_as_padded_2_digits,
    timestamp_ms_to_datetime,
};
use proc_tools::concat_vars;
use proc_tools_core::{concat_str, replace_multiple_patterns};
use proc_tools_helper::lang_tr;
use std::cmp::{Ordering, PartialOrd};
use std::sync::mpsc::SyncSender;
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::mpsc::{self},
    thread::JoinHandle,
};

/// 日志级别
#[derive(Clone)]
pub enum LogLevel {
    /// 错误
    Error,
    /// 警告
    Warn,
    /// 信息
    Info,
    /// 调试
    Debug,
    /// 跟踪
    Trace,
}

impl LogLevel {
    /// 将自定义日志级别转换为 log crate 的 [`log::LevelFilter`]
    /// - 提供自定义日志级别枚举与标准 log crate 级别过滤器之间的转换。
    /// - 这用于在设置全局日志级别时与 Rust 生态系统的标准日志库兼容。
    ///
    /// # 返回值
    /// - `log::LevelFilter`: 对应的标准日志级别过滤器
    ///
    /// # 转换映射
    /// - `LogLevel::Error` → `log::LevelFilter::Error`
    /// - `LogLevel::Warn` → `log::LevelFilter::Warn`
    /// - `LogLevel::Info` → `log::LevelFilter::Info`
    /// - `LogLevel::Debug` → `log::LevelFilter::Debug`
    /// - `LogLevel::Trace` → `log::LevelFilter::Trace`
    ///
    /// # 示例
    /// ```rust,ignore
    /// let level = yan_log::LogLevel::Info;
    /// let filter = level.to_level_filter();
    /// assert_eq!(filter, log::LevelFilter::Info);
    /// ```
    ///
    /// # 命名建议
    /// 原函数名 `s` 过于简略，建议改为 `to_level_filter`，
    /// 清晰表达了转换的目标类型和用途。
    #[inline]
    pub(crate) fn to_level_filter(&self) -> log::LevelFilter {
        match self {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}

/// 日志消息结构
pub(crate) struct LogMessage {
    /// 格式化后的日志消息内容
    formatted: String,
    /// 日志记录的日期时间
    now: (u32, u8, u8, u8, u8, u8, u16),
}

impl LogMessage {
    /// 创建新的日志消息实例
    /// - 使用当前时间戳和提供的参数初始化日志消息。
    ///
    /// # 参数
    /// - `level`: 日志级别
    /// - `module_path`: 模块路径标识
    /// - `message`: 日志消息内容
    ///
    /// # 返回值
    /// - `LogMessage`: 初始化完成的日志消息实例
    ///
    /// # 示例
    /// ```rust,ignore
    /// let message = yan_log::LogMessage::new(
    ///     LogLevel::Info,
    ///     std::sync::Arc::from("my_module"),
    ///     "这是一条测试消息".to_string()
    /// );
    /// ```
    #[inline]
    fn from<T: Into<String>>(level: LogLevel, module_path: &str, message: T) -> Self {
        let mut timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        match get_timezone_offset() {
            TimezoneOffset::PositiveNumber(v) => timestamp += v,
            TimezoneOffset::NegativeNumber(v) => timestamp -= v,
        };
        let (year, month, day, hour, minute, second, millis) = timestamp_ms_to_datetime(timestamp);

        const HYPHEN: char = '-';
        const COLON: char = ':';
        let mut bytes = [0u8; 3];
        let month_buf = format_u8_as_padded_2_digits(month, &mut bytes);
        let mut bytes = [0u8; 3];
        let day_buf = format_u8_as_padded_2_digits(day, &mut bytes);
        let mut bytes = [0u8; 3];
        let hour_buf = format_u8_as_padded_2_digits(hour, &mut bytes);
        let mut bytes = [0u8; 3];
        let minute_buf = format_u8_as_padded_2_digits(minute, &mut bytes);
        let mut bytes = [0u8; 3];
        let second_buf = format_u8_as_padded_2_digits(second, &mut bytes);
        let mut bytes = [b'0'; 5];
        let millis_buf = format_u16_as_padded_3_digits(millis, &mut bytes);
        let level_str = match level {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => " WARN",
            LogLevel::Info => " INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
        };
        let message = message.into();
        let formatted = concat_vars!(
            "[":String,
            year :u32,
            HYPHEN : char,
            month_buf : String,
            HYPHEN : char,
            day_buf : String,
            " " : String,
            hour_buf : String,
            COLON : char,
            minute_buf : String,
            COLON : char,
            second_buf : String,
            "." : String,
            millis_buf : String,
            "]_[" : String,
            level_str : String,
            "]_[" : String,
            module_path : String,
            "] - ": String,
            message: String,
            "\n" : String
        );
        LogMessage {
            formatted,
            now: (year, month, day, hour, minute, second, millis),
        }
    }
}

/// 全局日志消息发送器及其处理线程的实例。
static LOG_BACKEND: RwLock<Option<(SyncSender<LogMessage>, JoinHandle<()>)>> = RwLock::new(None);
/// 全局时区偏移
static TIMEZONE_OFFSET: OnceLock<TimezoneOffset> = OnceLock::new();

/// 设置全局时区偏移
#[inline]
pub(crate) fn set_timezone_offset(value: TimezoneOffset) {
    TIMEZONE_OFFSET.get_or_init(|| value);
}
/// 获取全局时区偏移
#[inline]
pub(crate) fn get_timezone_offset() -> &'static TimezoneOffset {
    &*TIMEZONE_OFFSET.get_or_init(|| TimezoneOffset::PositiveNumber(0))
}
/// 初始化日志发送器和日志处理线程
/// - 设置日志文件目录，创建日志文件，并启动后台线程处理日志消息。
/// - 此函数是日志系统的核心初始化方法。
///
/// # 参数
/// - `logger_format`: 日志格式配置，包含目录路径、文件名、时间分割规则等
///
/// # 处理流程
/// 1. 确保日志目录存在，不存在则创建
/// 2. 打开或创建日志文件
/// 3. 创建同步通道用于日志消息传递
/// 4. 启动后台线程处理日志消息
/// 5. 将发送器和线程句柄存储到全局静态变量
///
/// # 日志分割规则
/// - 根据配置的时间分割规则（年、月、日等）自动创建新的日志文件
/// - 根据配置的日志大小分割规则，自动创建新的日志文件
///
/// # 错误处理
/// - 日志写入失败会触发eprintln，打印错误信息
///
/// # 注意事项
/// - 此函数只需在应用程序启动时调用一次
/// - 重复调用会导致资源泄漏或panic
/// - 默认情况，在 dev 模式会打印日志到控制台，release模式，不会打印日志到控制台
/// - 开启 stdout 特性时，release模式，会和 dev 模式相同打印日志到控制台
#[inline(always)]
fn init_log_backend(mut logger_format: LoggerFormat) -> Result<(), std::io::Error> {
    // 确保日志目录存在
    let log_dir = Path::new(&*logger_format.dir_path);
    let msg_str = lang_tr!(
        cn = "创建日志目录失败，错误信息：",
        en = "Failed to create log directory, error message:",
    );
    if !log_dir.exists() {
        fs::create_dir_all(log_dir).map_err(|err| {
            std::io::Error::new(err.kind(), concat_str!(msg_str, &err.to_string()))
        })?;
    }
    let file_path: String = concat_str!(&*logger_format.dir_path, "/", &*logger_format.file_name);

    let result = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_path);
    let msg_str = lang_tr!(
        cn = "打开日志文件失败，错误信息：",
        en = "Failed to open log file, Exception message:"
    );
    let mut log_file =
        result.map_err(|e| std::io::Error::new(e.kind(), concat_str!(msg_str, &e.to_string())))?;
    logger_format.file_size = if let Ok(v) = log_file.metadata() {
        v.len()
    } else {
        0
    };
    let mut is_create_file = false;
    let (sender, receiver) = mpsc::sync_channel::<LogMessage>(logger_format.bound as usize);
    let handle = std::thread::spawn(move || {
        while let Ok(msg) = receiver.recv() {
            // 按时间分割日志文件
            if logger_format.should_split_by_time(&msg.now) {
                // 创建新的日志文件
                logger_format = logger_format.update_filename_for_time(msg.now);
                let file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&*logger_format.file_path);
                let msg_str = lang_tr!(
                    cn = "打开日志文件失败，错误信息：",
                    en = "Failed to open log file, error message:"
                );
                match file {
                    Ok(v) => log_file = v,
                    Err(e) => eprintln!("{}{}", msg_str, e),
                }
                // 更新日期
                logger_format.datetime = msg.now;
                logger_format.file_size = if let Ok(v) = log_file.metadata() {
                    v.len()
                } else {
                    0
                };
                logger_format.index = 0;
                is_create_file = true;
            }
            // 按文件大小分割日志文件
            if logger_format.max_file_triggering_policy != 0
                && logger_format.file_size > logger_format.max_file_triggering_policy
            {
                // 创建新的日志文件
                logger_format = logger_format.update_filename_for_filesize(msg.now);
                let file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&*logger_format.file_path);
                let msg_str = lang_tr!(
                    cn = "打开日志文件失败，错误信息：",
                    en = "Failed to open log file, error message:"
                );
                match file {
                    Ok(v) => log_file = v,
                    Err(e) => eprintln!("{}{}", msg_str, e),
                }
                logger_format.file_size = if let Ok(v) = log_file.metadata() {
                    v.len()
                } else {
                    0
                };
                is_create_file = true;
            };
            // 当创建新日志文件时，删除旧文件
            if is_create_file && logger_format.max_retained_files != 0 {
                let result = prune_old_logs(&mut logger_format);
                if let Err((msg_str, Some(e))) = result {
                    eprintln!("{}{}", msg_str, e);
                } else if let Err((msg_str, None)) = result {
                    eprintln!("{}", msg_str);
                }
                is_create_file = false;
            }
            // 打印日志到控制台
            // 检查 stdout 特性
            #[cfg(feature = "stdout")]
            print!("{}", msg.formatted);
            // 未开启 stdout 时，仅在 debug 模式下打印
            #[cfg(all(not(feature = "stdout"), debug_assertions))]
            print!("{}", msg.formatted);

            // 写入日志文件
            match write!(log_file, "{}", msg.formatted) {
                Ok(_) => logger_format.file_size += msg.formatted.len() as u64,
                Err(e) => {
                    let msg_str = lang_tr!(
                        cn = "写入日志文件失败：",
                        en = "Writing to log file failed:"
                    );
                    eprintln!("{}{}", msg_str, e)
                }
            };
            // 刷新文件确保写入
            match log_file.flush() {
                Ok(_) => {}
                Err(e) => {
                    let msg_str = lang_tr!(
                        cn = "刷新输出流失败：",
                        en = "Refresh output stream failed:"
                    );
                    eprintln!("{}{}", msg_str, e)
                }
            };
        }
    });
    let new_backend = (sender, handle);
    LOG_BACKEND.write().unwrap().replace(new_backend);
    Ok(())
}

#[inline(always)]
fn prune_old_logs(logger_format: &mut LoggerFormat) -> Result<(), (&str, Option<std::io::Error>)> {
    let path_vec_result = find_log_files(
        logger_format.dir_path.as_ref(),
        logger_format.file_pattern.as_ref(),
    );
    let mut path_vec = match path_vec_result {
        Ok(v) => v,
        Err(e) => {
            let msg = lang_tr!(cn = "删除日志文件失败：", en = "Failed to delete log file:");
            return Err((msg, Some(e)));
        }
    };
    // 没有超过指定最大日志文件数量时直接返回
    if path_vec.len() as u64 <= logger_format.max_retained_files {
        return Ok(());
    }
    // 将超出数量的日志文件从旧到新开始删除
    let n = path_vec.len() as u64 - logger_format.max_retained_files;
    let mut i = 0;
    while i < n {
        match path_vec.pop() {
            None => {
                let msg = lang_tr!(
                    cn = "日志异常，path_vec删除最后一项元素失败",
                    en = "Log exception, path_cec failed to delete the last element"
                );
                return Err((msg, None));
            }
            Some(v) => match fs::remove_file(v) {
                Ok(_) => {}
                Err(e) => {
                    let msg =
                        lang_tr!(cn = "删除日志文件失败：", en = "Failed to delete log file:");
                    return Err((msg, Some(e)));
                }
            },
        }
        i += 1;
    }
    Ok(())
}

/// 日志记录器结构体
pub struct Logger {
    /// 模块路径标识，用于标识日志来源
    module_path: &'static str,
    /// 当前日志记录器的过滤级别
    log_level: LogLevel,
}

/// 定义日志相等性比较
impl PartialEq for LogLevel {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (LogLevel::Error, LogLevel::Error)
            | (LogLevel::Warn, LogLevel::Warn)
            | (LogLevel::Info, LogLevel::Info)
            | (LogLevel::Debug, LogLevel::Debug)
            | (LogLevel::Trace, LogLevel::Trace) => true,
            _ => false,
        }
    }
}

/// 定义日志顺序关系
impl PartialOrd for LogLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // 定义级别优先级（数字越大表示级别越高）
        let priority = |level: &LogLevel| match level {
            LogLevel::Error => 4,
            LogLevel::Warn => 3,
            LogLevel::Info => 2,
            LogLevel::Debug => 1,
            LogLevel::Trace => 0,
        };
        priority(self).partial_cmp(&priority(other))
    }
}

impl Logger {
    /// 初始化日志记录器实例
    /// - 创建一个新的日志记录器实例，指定模块路径和日志级别。
    /// - 此方法仅创建实例，要启用全局日志系统需要调用 [`Logger::init`] 方法。
    /// - 可用于设置单独某个模块的日志级别
    ///
    /// # 参数
    /// - `module_path`: 当前模块的路径标识，用于日志记录中的来源标识
    /// - `log_level`: 日志记录器的过滤级别
    ///
    /// # 返回值
    /// - `Logger`: 初始化完成的日志记录器实例
    ///
    /// # 示例
    /// ```
    /// let log = yan_log::Logger::new(module_path!(), yan_log::LogLevel::Debug);
    /// log.debug("Debug information");
    /// yan_log::Logger::shutdown();
    /// ```
    #[inline]
    pub const fn new(module_path: &'static str, log_level: LogLevel) -> Self {
        Logger {
            module_path,
            log_level,
        }
    }

    /// 初始化全局日志系统
    /// - 搭配 log 日志门面框架使用
    /// - 设置日志发送器和全局日志级别，使日志系统开始工作
    /// - 此方法只需在应用程序启动时调用一次
    ///
    /// # 参数
    /// - `dir_path`: 日志文件存储目录路径
    /// - `level`: 全局日志级别过滤设置
    ///
    /// # 注意事项
    /// - 必须在创建任何日志记录器实例之前调用
    /// - 如果未调用此方法，日志将无法正常记录
    /// - 设置全局日志级别会影响所有日志记录器
    ///
    /// # 示例
    /// ```
    /// yan_log::Logger::init("logs", yan_log::LogLevel::Debug)
    ///     .start()
    ///     .unwrap();
    /// log::info!("Application started");
    /// yan_log::Logger::shutdown();
    /// ```
    #[inline(always)]
    pub fn init(dir_path: &str, level: LogLevel) -> LoggerFormat {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let (year, month, day, hour, minute, second, millis) = timestamp_ms_to_datetime(timestamp);
        LoggerFormat {
            dir_path: Box::from(dir_path),
            file_name: Box::from("application.log"),
            file_path: Box::from(concat_str!(dir_path, "/", "application.log")),
            file_pattern: Box::from(""),
            level,
            max_file_triggering_policy: 0,
            bound: 100,
            file_size: 0,
            index: 0,
            time_division_rule: LoggerFormatTimeDivisionRule::None,
            datetime: (year, month, day, hour, minute, second, millis),
            max_retained_files: 0,
        }
    }

    /// 关闭日志系统并等待日志线程结束
    /// - 优雅地关闭日志系统，发送关闭信号给日志线程并等待其完成。
    /// - 建议在应用程序主线程结束前调用此方法以确保所有日志都被处理。
    ///
    /// # 注意事项
    /// - 调用此方法后，日志系统将无法继续使用
    /// - 会阻塞当前线程直到日志线程完全退出
    /// - 如果不调用此方法，日志线程可能无法正常退出
    ///
    /// # 示例
    /// ```
    /// fn main(){
    ///    // 应用程序运行期间...
    ///
    ///    // 在应用程序退出前执行shutdown，确保日志正常记录
    ///    yan_log::Logger::shutdown();
    /// }
    /// ```
    #[inline(always)]
    pub fn shutdown() {
        let log_backend = LOG_BACKEND.write().unwrap().take();
        match log_backend {
            None => return,
            Some((sender, handle)) => {
                drop(sender); // 关闭通道，触发线程退出
                handle.join().unwrap(); // 等待线程结束
            }
        };
    }

    /// 记录信息级别日志
    ///
    /// # 参数
    /// - `message`: 日志消息内容，可以是任何能转换为字符串的类型
    ///
    /// # 示例
    /// ```
    /// let log = yan_log::Logger::new(module_path!(), yan_log::LogLevel::Debug);
    /// log.info("应用程序启动完成");
    /// ```
    pub fn info<T: Into<String>>(&self, message: T) {
        self.log(LogLevel::Info, message);
    }

    /// 记录调试级别日志
    ///
    /// # 参数
    /// - `message`: 调试日志消息内容
    ///
    /// # 示例
    /// ```
    /// let log = yan_log::Logger::new(module_path!(), yan_log::LogLevel::Debug);
    /// log.debug("进入数据处理函数");
    /// ```
    pub fn debug<T: Into<String>>(&self, message: T) {
        self.log(LogLevel::Debug, message);
    }

    /// 记录警告级别日志
    ///
    /// # 参数
    /// - `message`: 调试日志消息内容
    ///
    /// # 示例
    /// ```
    /// let log = yan_log::Logger::new(module_path!(), yan_log::LogLevel::Debug);
    /// log.warn("磁盘空间不足");
    /// ```
    pub fn warn<T: Into<String>>(&self, message: T) {
        self.log(LogLevel::Warn, message);
    }

    /// 记录错误级别日志
    ///
    /// # 参数
    /// - `message`: 错误日志消息内容
    ///
    /// # 示例
    /// ```
    ///
    /// let log = yan_log::Logger::new(module_path!(), yan_log::LogLevel::Debug);
    /// log.error("数据库连接失败");
    /// ```
    pub fn error<T: Into<String>>(&self, message: T) {
        self.log(LogLevel::Error, message);
    }

    /// 记录跟踪级别日志
    ///
    /// # 参数
    /// - `message`: 跟踪日志消息内容
    ///
    /// # 示例
    /// ```
    /// let log = yan_log::Logger::new(module_path!(), yan_log::LogLevel::Debug);
    /// log.trace("函数内部变量值: x = 42");
    /// ```
    pub fn trace<T: Into<String>>(&self, message: T) {
        self.log(LogLevel::Trace, message);
    }

    /// 内部日志记录方法
    /// - 实际的日志记录实现，将日志消息发送到日志线程处理。
    ///
    /// # 参数
    /// - `level`: 日志级别
    /// - `message`: 日志消息内容
    ///
    /// # 错误处理
    /// - 如果日志发送失败，会将错误信息打印到标准错误记录
    /// - 如果日志系统未初始化，会提示初始化异常
    #[inline]
    fn log<T: Into<String>>(&self, level: LogLevel, message: T) {
        if level < self.log_level {
            return;
        }
        let log_backend = LOG_BACKEND.read().unwrap();
        let option = log_backend.as_ref();

        if let Some((sender, _)) = option {
            if let Err(e) = sender.send(LogMessage::from(level, self.module_path, message)) {
                let msg_str = lang_tr!(
                    cn = "日志记录失败，错误信息:",
                    en = "Logging failed with error message:"
                );
                eprintln!("{}{}", msg_str, e);
            };
        } else {
            let msg_str = lang_tr!(
                cn = "日志记录失败，日志未初始化或已关闭",
                en = "Log output failed, Log not initialized or closed"
            );
            eprintln!("{}", msg_str);
        };
    }
}
impl log::Log for Logger {
    /// 检查是否启用指定级别的日志记录
    /// - 根据当前日志记录器配置的日志级别，判断是否应该记录给定元数据对应的日志。
    ///
    /// # 参数
    /// - `metadata`: 日志元数据，包含日志级别和目标信息
    ///
    /// # 返回值
    /// - `bool`: 是否启用该级别日志的记录
    ///   - `true`: 日志级别在当前配置级别范围内，允许记录
    ///   - `false`: 日志级别低于当前配置级别，不记录
    #[inline]
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= self.log_level.to_level_filter()
    }

    /// 记录日志消息
    /// - 实现 [`log::Log`] trait的核心方法，将标准log记录转换为内部日志格式并发送到日志线程。
    /// - 此方法由log门面自动调用，通常不应直接调用。
    ///
    /// # 参数
    /// - `record`: 日志记录，包含级别、消息、模块路径等信息
    ///
    /// # 处理流程
    /// 1. 将log::Level转换为内部[`LogLevel`]
    /// 2. 提取模块路径或使用默认值
    /// 3. 获取发送器锁并发送日志消息
    ///
    /// # 错误处理
    /// - 如果日志发送失败，会将错误信息打印到标准错误记录
    /// - 如果日志系统未初始化，消息会被静默丢弃
    ///
    /// # 注意事项
    /// - 此方法会在日志记录时获取全局锁，可能影响性能
    /// - 在性能敏感的场景中应谨慎使用高频率日志
    fn log(&self, record: &log::Record<'_>) {
        let level = match record.level() {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Trace => LogLevel::Trace,
        };
        let module_path: &str = record.module_path().unwrap_or_else(|| "None");
        let log_backend = LOG_BACKEND.read().unwrap();
        let option = log_backend.as_ref();
        if let Some((sender, _)) = option {
            if let Err(e) = sender.send(LogMessage::from(
                level,
                module_path,
                record.args().to_string(),
            )) {
                let msg = lang_tr!(
                    cn = "日志记录失败，错误信息：",
                    en = "Logging failed, error message:"
                );
                eprintln!("{}{}", msg, e);
            };
        }
    }

    /// 刷新日志缓冲区
    /// - 实现 [`log::Log`] trait的要求方法，确保所有缓冲的日志消息被写入目标。
    /// - 在当前实现中，由于使用通道异步处理，此方法为空实现。
    ///
    /// # 说明
    /// - 当前日志系统使用通道进行异步日志处理，不需要手动刷新
    /// - 如果需要确保日志立即写入，请考虑使用同步日志实现
    /// - 此方法为满足trait要求而存在，实际不执行任何操作
    fn flush(&self) {}
}

/// 日志文件时间分割规则枚举
pub struct LoggerFormat {
    /// 日志文件目录
    dir_path: Box<str>,
    /// 日志文件名
    file_name: Box<str>,
    /// 日志文件路径
    file_path: Box<str>,
    /// 日志文件格式
    file_pattern: Box<str>,
    /// 日志级别
    level: LogLevel,
    /// 日志日期
    datetime: (u32, u8, u8, u8, u8, u8, u16),
    /// 日志文件时间分割规则
    time_division_rule: LoggerFormatTimeDivisionRule,
    /// 日志文件大小触发策略，为0时默认不触发
    max_file_triggering_policy: u64,
    /// 日志通道容量
    bound: u32,
    /// 日志文件大小
    file_size: u64,
    /// 当前日志文件索引
    index: u64,
    /// 最大保留日志文件数，为0时默认不触发删除文件
    max_retained_files: u64,
}

/// UTC时间偏移
pub(crate) enum TimezoneOffset {
    /// 东时区偏移 UTC + N（毫秒）
    PositiveNumber(u128),
    /// 西时区偏移 UTC - N（毫秒）
    NegativeNumber(u128),
}

/// 日志文件时间分割规则枚举
/// - 定义日志文件按时间维度进行分割的不同策略，用于自动管理日志文件的创建和轮转。
/// - 根据不同的时间粒度，可以按年、月、日来组织日志文件。
pub enum LoggerFormatTimeDivisionRule {
    /// 不按时间分割
    None,
    /// 按年份分割日志文件，每年创建一个新文件
    Year,
    /// 按月份分割日志文件，每月创建一个新文件
    Month,
    /// 按日期分割日志文件，每天创建一个新文件
    Day,
    /// 按日期分割日志文件，每小时创建一个新文件
    Hours,
}

impl LoggerFormat {
    /// 根据当前时间设置日志文件名
    /// - 根据提供的时间信息和文件模式，生成具体的日志文件名
    ///
    /// # 参数
    /// - `self`: [`LoggerFormat`] 实例
    /// - `today`: 当前时间，用于生成基于时间的文件名
    ///
    /// # 返回值
    /// - `Self`: 更新文件名后的 [`LoggerFormat`] 实例
    ///
    /// # 示例
    /// ```rust,ignore
    /// let mut log_fmt = yan_log::Logger::init("logs", yan_log::LogLevel::Debug)
    ///     .set_file_pattern("app_%Y-%m-%d.log", yan_log::LoggerFormatTimeDivisionRule::Day);
    /// let mut timestamp = std::time::SystemTime::now()
    ///     .duration_since(std::time::UNIX_EPOCH)
    ///     .unwrap()
    ///     .as_millis();
    /// timestamp += 28_800_000;
    /// let now = yan_log::unit::timestamp_ms_to_datetime(timestamp);
    /// let log_fmt = log_fmt.update_filename_for_time(now);
    /// ```
    /// # 示例
    /// 如果文件模式为 "app_%Y-%m-%d %H：%M：%S-%i.log"，当前时间为 2023-10-25 10:19:12，索引为 1，
    /// 则生成的文件名为 "app_2023-10-25 10：19：12-1"
    #[inline]
    pub(crate) fn update_filename_for_time(
        mut self,
        today: (u32, u8, u8, u8, u8, u8, u16),
    ) -> Self {
        let new_file_name = self.get_new_file_name(today);
        self.file_name = Box::from(new_file_name);
        self.file_path = Box::from(concat_str!(&*self.file_pattern, "/", &*self.file_name));
        self
    }

    /// 根据文件大小更新日志文件名
    /// - 当日志文件达到大小限制时，创建新的日志文件并更新索引。
    /// - 如果日期发生变化，则重置文件索引为0。
    ///
    /// # 参数
    /// - `self`: [`LoggerFormat`] 实例
    /// - `today`: 当前时间组件元组
    ///
    /// # 返回值
    /// - `Self`: 更新文件名、文件路径和索引后的 [`LoggerFormat`] 实例
    ///
    /// # 处理逻辑
    /// - 如果日期时间变化，重置索引为0
    /// - 如果日期不变，索引递增
    /// - 根据新的时间和索引生成文件名
    #[inline]
    pub(crate) fn update_filename_for_filesize(
        mut self,
        today: (u32, u8, u8, u8, u8, u8, u16),
    ) -> Self {
        self.index = self.index.checked_add(1).unwrap_or(0);
        let new_file_name = self.get_new_file_name(today);
        self.file_name = Box::from(new_file_name);
        self.file_path = Box::from(concat_str!(&*self.dir_path, "/", &*self.file_name));
        self
    }

    /// 根据规则获取新日志文件名
    fn get_new_file_name(&self, today: (u32, u8, u8, u8, u8, u8, u16)) -> String {
        let mut buf = [0u8; 3];
        let month = format_u8_as_padded_2_digits(today.1, &mut buf);
        let mut buf = [0u8; 3];
        let day = format_u8_as_padded_2_digits(today.2, &mut buf);
        let mut buf = [0u8; 3];
        let hour = format_u8_as_padded_2_digits(today.3, &mut buf);
        let mut buf = [0u8; 3];
        let minutes = format_u8_as_padded_2_digits(today.4, &mut buf);
        let mut buf = [0u8; 3];
        let seconds = format_u8_as_padded_2_digits(today.5, &mut buf);
        replace_multiple_patterns(
            &*self.file_pattern,
            &[
                ("%Y", &concat_vars!(today.0 : u32)),
                ("%m", &concat_vars!(month : String)),
                ("%d", &concat_vars!(day : String)),
                ("%H", &concat_vars!(hour : String)),
                ("%M", &concat_vars!(minutes : String)),
                ("%S", &concat_vars!(seconds : String)),
                ("%i", &concat_vars!(self.index : u64)),
            ],
        )
    }

    /// 检查是否应该根据时间规则分割日志文件
    ///
    /// # 参数
    /// - `now`: 待记录的日志时间
    ///
    /// # 返回值
    /// - `bool`: 是否需要创建新的日志文件
    ///   - `true`: 需要按时间分割，创建新文件
    ///   - `false`: 不需要分割，继续使用当前文件
    ///
    /// # 分割规则说明
    ///
    /// - `None`: 不按时间分割，始终返回 `false`
    /// - `Year`: 当年份不同时分割
    /// - `Month`: 当年份或月份不同时分割
    /// - `Day`: 当年份、月份或日期不同时分割
    /// - `Hours`: 当年份、月份、日期或小时不同时分割
    #[inline]
    pub(crate) fn should_split_by_time(&self, now: &(u32, u8, u8, u8, u8, u8, u16)) -> bool {
        match self.time_division_rule {
            LoggerFormatTimeDivisionRule::None => false,
            LoggerFormatTimeDivisionRule::Year => now.0 != self.datetime.0,
            LoggerFormatTimeDivisionRule::Month => {
                now.0 != self.datetime.0 || now.1 != self.datetime.1
            }
            LoggerFormatTimeDivisionRule::Day => {
                now.0 != self.datetime.0 || now.1 != self.datetime.1 || now.2 != self.datetime.2
            }
            LoggerFormatTimeDivisionRule::Hours => {
                now.0 != self.datetime.0
                    || now.1 != self.datetime.1
                    || now.2 != self.datetime.2
                    || now.3 != self.datetime.3
            }
        }
    }

    /// 设置固定的日志文件名
    /// - 直接指定日志文件名，不使用文件分割规则。
    /// - 设置后将覆盖之前通过 [`LoggerFormat::set_file_pattern`] 设置文件模式生成的文件名。
    /// - 如果使用了 [`LoggerFormat::set_max_file_triggering_policy`] 设置日志文件大小触发策略，在文件达到指定大小时，会覆盖原日志。
    ///
    /// # 参数
    /// - `self`: [`LoggerFormat`] 实例
    /// - `file_name`: 要设置的固定文件名
    ///
    /// # 返回值
    /// - `Self`: 更新文件名后的 [`LoggerFormat`] 实例
    #[inline]
    pub fn set_file_name(mut self, file_name: &str) -> Self {
        self.time_division_rule = LoggerFormatTimeDivisionRule::None;
        self.file_name = Box::from(file_name);
        self.file_path = Box::from(concat_str!(&*self.file_pattern, "/", &*self.file_name));
        self
    }

    /// 设置日志消息通道的缓冲区大小
    /// - 当通道中的日志消息数量达到边界值时，新的日志发送操作将会阻塞，直到有空间可用。
    ///
    /// # 参数
    /// - `bound`: 通道缓冲区容量，表示可以排队等待处理的日志消息数量
    ///
    /// # 返回值
    /// - `Self`: 返回修改后的配置对象，支持链式调用
    ///
    /// # 性能影响
    /// - 较小的值：减少内存使用，但在高日志量时可能导致发送阻塞
    /// - 较大的值：提高吞吐量，但会增加内存占用和潜在的消息延迟
    ///
    /// # 示例
    /// ```
    /// let format = yan_log::Logger::init("logs", yan_log::LogLevel::Debug)
    ///     .set_bound(200)  // 设置通道容量为200
    /// ```
    ///
    /// # 注意事项
    /// - 边界值为0时，通道变为同步通道（每次发送都会阻塞直到接收）
    /// - 在高并发场景中建议适当增大边界值
    /// - 边界值过大会增加内存占用和消息处理延迟
    #[inline]
    pub fn set_bound(mut self, bound: u32) -> Self {
        self.bound = bound;
        self
    }

    /// 设置日志文件大小触发拆分文件策略
    /// - 配置当日志文件达到指定大小时自动创建新文件的策略。
    /// - 设置后会立即根据当前时间更新文件名并重置索引。
    ///
    /// # 参数
    /// - `self`: [`LoggerFormat`] 实例
    /// - `max_file_triggering_policy`: 最大文件大小（字节），超过此大小会触发文件分割
    ///
    /// # 返回值
    /// - `Self`: 更新大小策略和文件名后的 [`LoggerFormat`] 实例
    ///
    /// # 说明
    /// - 值为0表示禁用文件大小分割
    /// - 非零值表示单个日志文件的最大字节数
    /// - 达到大小时会创建新文件，文件名中的索引会递增
    ///
    /// # 示例
    /// ```
    /// let mut log_fmt = yan_log::Logger::init("logs", yan_log::LogLevel::Debug);
    /// // 1024B * 1024 = 1048576B = 1024KB = 1MB
    /// // 1048576B * 100 = 104857600B = 100MB
    /// let format = log_fmt.set_max_file_triggering_policy(104857600); // 设置100MB的触发策略
    /// ```
    #[inline]
    pub fn set_max_file_triggering_policy(mut self, max_file_triggering_policy: u64) -> Self {
        self.max_file_triggering_policy = max_file_triggering_policy;
        let datetime = self.datetime.clone();
        let mut log_fmt = self.update_filename_for_filesize(datetime);
        log_fmt.index = 0;
        log_fmt
    }

    /// 设置日志文件命名模式和时间分割规则
    ///
    /// # 参数
    /// - `self`: [`LoggerFormat`] 实例
    /// - `file_pattern`: 文件命名模式，支持的模式占位符：
    ///   - `%Y`: 四位年份
    ///   - `%m`: 两位月份（01-12）
    ///   - `%d`: 两位日期（01-31）
    ///   - `%H`: 两位小时（00-23）
    ///   - `%M`: 两位分钟（00-59）
    ///   - `%S`: 两位秒数（00-59）
    ///   - `%i`: 文件索引号
    /// - `time_division_rule`: 明确的时间分割规则
    ///
    /// # 返回值
    /// - `Self`: 更新文件模式和时间分割规则后的 [`LoggerFormat`] 实例
    ///
    /// # 示例
    /// ```
    /// let mut log_fmt = yan_log::Logger::init("logs", yan_log::LogLevel::Debug);
    /// let log_fmt = log_fmt.set_file_pattern("app_%Y-%m-%d.log", yan_log::LoggerFormatTimeDivisionRule::Day);
    /// ```
    #[inline]
    pub fn set_file_pattern(
        mut self,
        file_pattern: &str,
        time_division_rule: LoggerFormatTimeDivisionRule,
    ) -> Self {
        self.time_division_rule = time_division_rule;
        self.file_pattern = Box::from(file_pattern);
        self
    }

    /// 设置时间偏移量（单位：毫秒）
    /// - 根据偏移量的正负值自动设置时区偏移方向
    /// - 正数表示东时区，负数表示西时区
    ///
    /// # 参数
    /// - `offset`: 时间偏移量，单位为毫秒
    ///   - 正数：东时区（UTC+）
    ///   - 负数：西时区（UTC-）
    ///
    /// # 返回值
    /// - `Self`: 返回自身的所有权，支持链式调用
    ///
    /// # 注意
    /// - 内部会自动处理偏移量的正负转换，将负值转换为对应的正值并标记为负方向
    /// - 该操作只能设置一次，后续重复设置无效
    ///
    /// # 示例
    /// ```
    /// let config = TimeConfig::new()
    ///     .set_timezone_offset(28800000); // 设置为 UTC+8（8小时 = 28800000毫秒）
    ///
    /// let config = TimeConfig::new()
    ///     .set_timezone_offset(-18000000); // 设置为 UTC-5（-5小时 = -18000000毫秒）
    /// ```
    #[inline]
    pub fn set_timezone_offset(self, offset: i128) -> Self {
        if offset < 0 {
            set_timezone_offset(TimezoneOffset::NegativeNumber(offset.abs() as u128));
        } else {
            set_timezone_offset(TimezoneOffset::PositiveNumber(offset as u128));
        };
        self
    }

    /// 设置最大保留日志文件数量
    ///
    /// # 参数
    /// - `self`: [`LoggerFormat`] 实例
    /// - `max_retained_files`: 最大保留日志文件数
    ///
    /// # 返回值
    /// - `Self`: 更新最大保留日志文件数后的 [`LoggerFormat`] 实例
    ///
    /// # 示例
    /// ```
    /// let mut log_fmt = yan_log::Logger::init("logs", yan_log::LogLevel::Debug);
    /// let log_fmt = log_fmt.set_max_retained_files(3);
    /// ```
    #[inline]
    pub fn set_max_retained_files(mut self, max_retained_files: u64) -> Self {
        self.max_retained_files = max_retained_files;
        self
    }

    /// 启动日志系统
    /// - 完成日志系统的最终配置并启动所有相关组件。
    /// - 此方法会设置全局日志级别、注册日志实现并启动日志处理线程。
    ///
    /// # 处理流程
    /// 1. 设置全局日志级别过滤
    /// 2. 注册 log crate 的日志实现
    /// 3. 启动日志发送器和处理线程
    ///
    /// # 注意事项
    /// - 此方法会消费 [`LoggerFormat`] 实例
    /// - 调用后日志系统开始工作，可以记录日志
    /// - 通常在应用程序启动时调用一次
    ///
    /// # 示例
    /// ```
    /// yan_log::Logger::init("logs", yan_log::LogLevel::Debug)
    ///     .set_file_pattern("app_%Y-%m-%d.log", yan_log::LoggerFormatTimeDivisionRule::Day)
    ///     .start()
    ///     .unwrap();
    /// ```
    ///
    /// # 安全性
    /// - 使用 `Box::leak` 将日志记录器泄漏到静态生命周期，这是启动全局日志系统的常见模式
    ///
    /// # 注意事项
    /// - 默认情况，在 dev 模式会打印日志到控制台，release模式，不会打印日志到控制台
    /// - 开启 stdout 特性时，release模式，会和 dev 模式相同打印日志到控制台
    #[inline]
    pub fn start(self) -> Result<(), std::io::Error> {
        // 设置log日志门面的实现
        let box_logger = Box::from(Logger::new("None", self.level.clone()));
        log::set_logger(Box::leak(box_logger)).unwrap();
        // 设置全局日志级别
        log::set_max_level(self.level.to_level_filter());

        // 获取当前时间戳，根据已设置的时间偏移量重新设置 日期时间 和 日志文件名
        let mut timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        match get_timezone_offset() {
            TimezoneOffset::PositiveNumber(v) => timestamp += v,
            TimezoneOffset::NegativeNumber(v) => timestamp -= v,
        };
        let now = timestamp_ms_to_datetime(timestamp);
        let mut s = self.update_filename_for_time(now);
        s.datetime = now;
        init_log_backend(s)
    }
}
