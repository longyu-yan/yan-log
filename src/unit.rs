use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

/// 将 u32 数字格式化为2位数字的字节切片
/// - 将输入的数字格式化为固定2位宽度的字符串表示，不足两位时前面补零。
/// - 对于0-9的数字使用预定义的字节字面量以获得最佳性能。
///
/// # 参数
/// - `i`: 要格式化的无符号32位整数
/// - `buf`: 用于存储格式化结果的缓冲区，必须至少10字节长度
///
/// # 返回值
/// - `&[u8]`: 指向格式化结果的字节切片引用，长度为2
///
/// # 性能优化
/// - 对于0-9的数字直接返回预定义的字节字面量，避免函数调用
/// - 对于10及以上的数字使用高效的算法
/// - 使用内联优化减少函数调用开销
/// # 示例
/// ```rust,ignore
/// let mut buf = [0u8; 3];
/// let result = format_u8_as_padded_2_digits(5, &mut buf);
/// assert_eq!(result, b"05");
///
/// let result2 = format_u8_as_padded_2_digits(15, &mut buf);
/// assert_eq!(result2, b"15");
/// ```
#[inline]
pub(crate) fn format_u8_as_padded_2_digits(i: u8, buf: &mut [u8; 3]) -> &[u8] {
    match i {
        0 => b"00",
        1 => b"01",
        2 => b"02",
        3 => b"03",
        4 => b"04",
        5 => b"05",
        6 => b"06",
        7 => b"07",
        8 => b"08",
        9 => b"09",
        _ => proc_tools_core::utils_core::impl_to_ascii::itoa_buf_u8(buf, i),
    }
}

/// 将 u32 数字格式化为3位数字的字节切片
/// - 将输入的数字格式化为固定3位宽度的字符串表示，不足三位时前面补零。
/// - 针对不同范围的数字使用不同的优化策略。
///
/// # 参数
/// - `i`: 要格式化的无符号32位整数
/// - `buf`: 用于存储格式化结果的缓冲区，必须至少10字节长度
///
/// # 返回值
/// - `&[u8]`: 指向格式化结果的字节切片引用，长度为3
///
/// # 算法说明
/// - 0-9: 手动填充两个前导零
/// - 10-99: 手动填充一个前导零
/// - 100+: 使用高效的算法
///
/// # 性能优化
/// - 使用内联(always)确保关键路径的性能
/// - 对小数字进行手动处理避免函数调用
/// - 缓冲区预初始化为'0'字符减少赋值操作
///
/// # 示例
/// ```rust,ignore
/// let mut buf = [b'0'; 5];
/// let result = format_u16_as_padded_3_digits(5, &mut buf);
/// assert_eq!(result, b"005");
///
/// let result2 = format_u16_as_padded_3_digits(42, &mut buf);
/// assert_eq!(result2, b"042");
///
/// let result3 = format_u16_as_padded_3_digits(123, &mut buf);
/// assert_eq!(result3, b"123");
/// ```
#[inline(always)]
pub(crate) fn format_u16_as_padded_3_digits(i: u16, buf: &mut [u8; 5]) -> &[u8] {
    if i < 10 {
        buf[0] = b'0';
        buf[1] = b'0';
        buf[2] = b'0' + i as u8;
        &buf[0..3]
    } else if i < 100 {
        buf[0] = b'0';
        buf[1] = b'0' + (i / 10) as u8; // 十位
        buf[2] = b'0' + (i % 10) as u8; // 个位
        &buf[0..3]
    } else {
        proc_tools_core::utils_core::impl_to_ascii::itoa_buf_u16(buf, i)
    }
}

/// 将毫秒级时间戳转换为日期时间组件
/// - 将自 Unix 纪元（1970-01-01 00:00:00 UTC）以来的毫秒数转换为对应的
/// - 使用 UTC/GMT (世界协调时间)，如果要用北京时间的时区，需手动为时间戳加 28_800_000（8小时）
/// - 年、月、日、时、分、秒和毫秒组件。使用简单的计算避免昂贵的日期时间库调用。
///
/// # 参数
/// - `timestamp`: 毫秒级 Unix 时间戳
///
/// # 返回值
/// - `(u32, u8, u8, u8, u8, u8, u16)`: 日期时间组件的元组，包含：
///   - `u32`: 年份（如 2023）
///   - `u8`: 月份（1-12）
///   - `u8`: 日期（1-31）
///   - `u8`: 小时（0-23）
///   - `u8`: 分钟（0-59）
///   - `u8`: 秒数（0-59）
///   - `u16`: 毫秒数（0-999）
///
/// # 算法特点
/// - 使用 400 年、100 年、4 年周期进行高效年份计算
/// - 时间复杂度为 O(1)，最多进行 3 次年份调整和 12 次月份调整
/// - 正确处理闰年规则：能被4整除但不能被100整除，或能被400整除
///
/// # 注意事项
/// - 输入时间戳应为毫秒级（Unix 时间戳 × 1000）
/// - 返回的月份和日期从1开始（1月=1，1日=1）
/// - 算法假设格里高利历法，适用于 1970 年之后的日期
///
/// # 示例
/// ```rust,ignore
/// let timestamp = 1698242456123; // 世界协调时间：2023-10-25 14:00:56.123
/// let (year, month, day, hour, minute, second, millis) = timestamp_to_datetime(timestamp);
/// assert_eq!(year, 2023);
/// assert_eq!(month, 10);
/// assert_eq!(day, 25);
/// assert_eq!(hour, 14);
/// assert_eq!(minute, 0);
/// assert_eq!(second, 56);
/// assert_eq!(millis, 123);
///
/// //北京时间需要在原时间戳上加28_800_000
/// let mut timestamp = 1698242456123; // 世界协调时间：2023-10-25 14:00:56.123
/// timestamp += 28_800_000; // 北京时间：2023-10-25 22:00:56.123
/// let (year, month, day, hour, minute, second, millis) = timestamp_to_datetime(timestamp);
/// assert_eq!(hour, 22);
/// ```
///
/// # 性能
/// - 使用整数运算，避免浮点数计算
/// - 循环次数有上限（年份最多3次，月份最多12次）
/// - 适合高性能场景，如日志处理、时间序列数据分析
#[inline]
pub fn timestamp_ms_to_datetime(timestamp: u128) -> (u32, u8, u8, u8, u8, u8, u16) {
    // 毫秒时间戳 -> 秒 + 毫秒
    let total_seconds = timestamp / 1000;
    let milliseconds = timestamp % 1000;

    // 计算天数和当天的秒数
    let days = total_seconds / 86400;
    let seconds_in_day = total_seconds % 86400;

    // 计算时分秒
    let hours = (seconds_in_day / 3600) as u8;
    let minutes = ((seconds_in_day % 3600) / 60) as u8;
    let seconds = (seconds_in_day % 60) as u8;

    // 精确年份计算（400年/100年/4年周期）
    let n400 = days / 146097; // 400年周期天数: 146097
    let mut year = 1970 + n400 * 400;
    let mut remaining_days = days % 146097;

    let n100 = remaining_days / 36524; // 100年周期天数: 36524
    year += n100 * 100;
    remaining_days %= 36524;

    let n4 = remaining_days / 1461; // 4年周期天数: 1461
    year += n4 * 4;
    remaining_days %= 1461;

    // 剩余天数最多处理3次（O(1)时间）
    for _ in 0..3 {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        if remaining_days >= 366 && is_leap {
            remaining_days -= 366;
            year += 1;
        } else if remaining_days >= 365 {
            remaining_days -= 365;
            year += 1;
        } else {
            break;
        }
    }

    // 计算月份和日期（最多12次循环，常数时间）
    let mut month = 1;
    let mut days_in_month = 31;
    while remaining_days >= days_in_month {
        remaining_days -= days_in_month;
        month += 1;
        days_in_month = match month {
            2 => {
                if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
                    29
                } else {
                    28
                }
            }
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
    }

    let day = (remaining_days + 1) as u8;

    (
        year as u32,
        month,
        day,
        hours,
        minutes,
        seconds,
        milliseconds as u16,
    )
}

/// 根据日志文件命名规则，查询目录下所有匹配的文件路径，并按修改时间从新到旧排序
///
/// # 参数
/// - `dir_path`: 日志目录路径
/// - `pattern`: 文件命名模式（如 "app_%Y-%m-%d.log"）
///
/// # 返回
/// - `Ok(Vec<PathBuf>)`: 匹配文件的路径列表（按修改时间新到旧排序）
/// - `Err(std::io::Error)`: 目录读取或文件操作错误
pub(crate) fn find_log_files(dir_path: &str, pattern: &str) -> io::Result<Vec<PathBuf>> {
    let fragments = parse_pattern(pattern);
    let mut files: Vec<(PathBuf, SystemTime)> = Vec::new();

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || path.file_name().is_none() {
            continue;
        }

        let file_name_lossy = path.file_name().unwrap().to_string_lossy();

        if !matches_pattern_bytes(&file_name_lossy, &fragments) {
            continue;
        }

        let mod_time = fs::metadata(&path)?.modified()?;
        files.push((path, mod_time));
    }

    files.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(files.into_iter().map(|(path, _)| path).collect())
}

/// 解析日志文件名模式字符串
/// - 将模式字符串解析为片段序列，用于后续的文件名匹配和生成。
/// - 支持占位符语法：`%Y`(四位数年份), `%m`(月份), `%d`(日期), `%H`(小时), `%M`(分钟), `%S`(秒), `%i`(任意数字)
///
/// # 参数
/// - `pattern`: 模式字符串，可以包含固定文本和占位符
///
/// # 返回值
/// - `Vec<Fragment>`: 解析后的片段序列，用于文件名模式匹配
///
/// # 处理流程
/// 1. 逐字节扫描模式字符串
/// 2. 遇到 `%` 字符时检查后续字符是否为有效占位符
/// 3. 将固定文本和占位符分别存储为不同的片段类型
/// 4. 支持UTF-8字符的安全处理
///
/// # 示例
/// ```
/// use log_processor::parse_pattern;
///
/// let fragments = parse_pattern("%Y-%m-%d %H：%M：%S-%i.log");
/// // 解析结果包含固定文本和日期时间占位符
/// ```
///
/// # 注意事项
/// - 不支持嵌套或复杂的占位符语法
/// - 未识别的占位符会被忽略
/// - 模式字符串必须是有效的UTF-8编码
fn parse_pattern(pattern: &str) -> Vec<Fragment> {
    let mut fragments: Vec<Fragment> = Vec::new();
    let mut i: usize = 0;
    let mut poi: usize = 0;
    let bytes = pattern.as_bytes();
    while i < pattern.len() {
        if bytes[i] == b'%' {
            if i + 1 == pattern.len() {
                break;
            }
            let next_byte = bytes[i + 1];
            let char_len = utf8_char_len(next_byte);
            if char_len == 1 {
                fragments.push(Fragment::Fixed(Box::from(&pattern[poi..i])));
                if next_byte == b'Y' {
                    fragments.push(Fragment::PlaceholderFourDigits);
                } else if next_byte == b'm'
                    || next_byte == b'd'
                    || next_byte == b'H'
                    || next_byte == b'M'
                    || next_byte == b'S'
                {
                    fragments.push(Fragment::PlaceholderTwoDigits);
                } else if next_byte == b'i' {
                    fragments.push(Fragment::PlaceholderAnyDigits);
                } else {
                    i += 1;
                    fragments.pop();
                    continue;
                }
                i += 2;
                poi = i;
            } else {
                // UTF-8字符处理，确保不会越界
                let actual_len = char_len.min(bytes.len() - i);
                i += actual_len;
            }
        } else {
            i += 1;
        }
    }
    if poi < pattern.len() {
        fragments.push(Fragment::Fixed(Box::from(&pattern[poi..pattern.len()])));
    }
    fragments
}

/// 文件名模式片段枚举
enum Fragment {
    // 四位数数字占位符
    PlaceholderFourDigits,
    // 两位数数字占位符
    PlaceholderTwoDigits,
    // 任意位数数字占位符
    PlaceholderAnyDigits,
    // 固定字符串
    Fixed(Box<str>),
}

/// 计算 UTF-8 字符的字节长度
///
/// # 参数
/// - `next_byte`: UTF-8字符的首字节
///
/// # 返回值
/// - `usize`: UTF-8字符的字节长度 (1-4)
///
/// # UTF-8编码规则
/// - 单字节: 0xxxxxxx
/// - 双字节: 110xxxxx
/// - 三字节: 1110xxxx
/// - 四字节: 11110xxx
///
/// # 示例
/// ```rust`ignore
/// assert_eq!(utf8_char_len(b'a'), 1);    // ASCII字符
/// assert_eq!(utf8_char_len(0xC3), 2);    // 双字节UTF-8
/// assert_eq!(utf8_char_len(0xE2), 3);    // 三字节UTF-8
/// ```
fn utf8_char_len(next_byte: u8) -> usize {
    if next_byte & 0b1110_0000 == 0b1100_0000 {
        2
    } else if next_byte & 0b1111_0000 == 0b1110_0000 {
        3
    } else if next_byte & 0b1111_1000 == 0b1111_0000 {
        4
    } else {
        1 // 单字节ASCII字符或无效UTF-8
    }
}

/// 检查文件名是否匹配片段模式
/// - 验证给定的文件名是否符合预解析的片段模式结构。
/// - 逐个匹配片段，确保文件名在结构和内容上符合预期格式。
///
/// # 参数
/// - `file_name`: 要检查的文件名字符串
/// - `fragments`: 预解析的模式片段序列
///
/// # 返回值
/// - `bool`: 文件名是否匹配模式
///   - `true`: 文件名完全匹配所有片段
///   - `false`: 文件名不符合模式要求
///
/// # 匹配规则
/// - `Fixed`: 精确匹配固定字符串
/// - `PlaceholderTwoDigits`: 匹配连续两个 `ASCII` 数字
/// - `PlaceholderFourDigits`: 匹配连续四个 `ASCII` 数字
/// - `PlaceholderAnyDigits`: 匹配连续 1-39 个 `ASCII` 数字
fn matches_pattern_bytes(file_name: &str, fragments: &[Fragment]) -> bool {
    let mut pos = 0;
    let file_name_bytes = file_name.as_bytes();
    for fragment in fragments {
        match fragment {
            Fragment::Fixed(s) => {
                if !file_name_bytes[pos..pos + s.len()].starts_with(s.as_bytes()) {
                    return false;
                }
                pos += s.len();
            }
            Fragment::PlaceholderTwoDigits => {
                if file_name_bytes[pos].is_ascii_digit() {
                    return false;
                }
                pos += 1;
                if file_name_bytes[pos].is_ascii_digit() {
                    return false;
                }
                pos += 1;
            }
            Fragment::PlaceholderFourDigits => {
                for ch in &file_name_bytes[pos..pos + 4] {
                    if !ch.is_ascii_digit() {
                        return false;
                    }
                }
                pos += 4;
            }
            Fragment::PlaceholderAnyDigits => {
                let remain_str = &file_name_bytes[pos..];
                let remain_len = remain_str.len().min(39);
                let mut any_digits = 0;
                for i in &file_name_bytes[pos..pos + remain_len] {
                    if !i.is_ascii_digit() {
                        break;
                    }
                    any_digits += 1;
                }
                if any_digits == 0 {
                    return false;
                }
                pos += any_digits;
            }
        }
    }
    pos == file_name_bytes.len()
}
