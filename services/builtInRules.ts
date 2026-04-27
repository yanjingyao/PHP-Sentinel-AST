import { VulnerabilityType, RiskLevel, Rule } from '../types';

export const BUILT_IN_RULES: Rule[] = [
  // --- 通用漏洞规则 (注入类) ---
  // 规则b1a: 检测SQL函数中字符串内的变量插值（如 "...$var..."）
  { id: 'b1a', name: 'SQL 注入 - 字符串变量插值', pattern: '(mysql_query|mysqli_query|db_query|pg_query|execute|query|prepare|PDO::query|PDO::prepare)\\s*\\(\\s*["\x27][^"\x27]*\\$\\w+[^"\x27]*["\x27]', type: VulnerabilityType.SQL_INJECTION, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },
  // 规则b1b: 检测SQL函数中直接使用变量（如 mysql_query($sql)）
  { id: 'b1b', name: 'SQL 注入 - 变量参数', pattern: '(mysql_query|mysqli_query|db_query|pg_query|execute|query|prepare|PDO::query|PDO::prepare)\\(.*?([$].*?)\\)', type: VulnerabilityType.SQL_INJECTION, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },
  { id: 'b2', name: '跨站脚本 (XSS)', pattern: '(echo|print|printf|vprintf|die|exit|vfprintf|print_r)\\s*?\\(?.*?([$].*?)\\)?', type: VulnerabilityType.XSS, level: RiskLevel.HIGH, enabled: true, isBuiltIn: true },

  // --- 通用漏洞规则 (执行类) ---
  { id: 'b3', name: '代码执行 (RCE)', pattern: '(eval|system|exec|passthru|shell_exec|popen|proc_open|create_function|assert|preg_replace\\s*?\\(\\s*?[\x27"].*?\\/e[\x27"])\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.CODE_EXECUTION, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },
  { id: 'b4', name: '文件包含 (LFI/RFI)', pattern: '(include|require|include_once|require_once|file_get_contents|readfile|fopen|parse_ini_file)\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.FILE_INCLUSION, level: RiskLevel.HIGH, enabled: true, isBuiltIn: true },

  // --- 通用漏洞规则 (文件/系统类) ---
  { id: 'b5', name: '不安全的文件上传', pattern: '(move_uploaded_file|copy|file_put_contents|fwrite)\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.FILE_UPLOAD, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },
  { id: 'b6', name: '任意文件操作/遍历', pattern: '(unlink|rmdir|mkdir|rename|chown|chmod|touch|opendir|scandir)\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.PATH_TRAVERSAL, level: RiskLevel.HIGH, enabled: true, isBuiltIn: true },

  // --- 通用漏洞规则 (网络/反序列化) ---
  { id: 'b7', name: 'SSRF (Curl/Stream)', pattern: '(curl_init|curl_exec|fsockopen|pfsockopen|stream_context_create|get_headers|file_get_contents)\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.SSRF, level: RiskLevel.HIGH, enabled: true, isBuiltIn: true },
  { id: 'b8', name: '反序列化', pattern: '(unserialize|yaml_parse|json_decode)\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.DESERIALIZATION, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },

  // --- 信息泄露 ---
  { id: 'b9', name: '敏感信息泄露', pattern: '(phpinfo|var_dump|debug_backtrace|print_r)\\s*?\\(\\s*?\\)', type: VulnerabilityType.SENSITIVE_CALL, level: RiskLevel.INFO, enabled: true, isBuiltIn: true },

  // --- 中危规则 ---
  { id: 'm1', name: '不安全的随机数生成', pattern: '(rand|mt_rand|uniqid)\\s*?\\(', type: VulnerabilityType.WEAK_CRYPTO, level: RiskLevel.MEDIUM, enabled: true, isBuiltIn: true },
  { id: 'm2', name: 'HTTP 头部注入', pattern: '(header|setcookie)\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.HEADER_INJECTION, level: RiskLevel.MEDIUM, enabled: true, isBuiltIn: true },
  { id: 'm3', name: '不安全的文件操作', pattern: '(file|file_get_contents|fopen|readfile)\\s*?\\(.*?([$].*?)\\)', type: VulnerabilityType.PATH_TRAVERSAL, level: RiskLevel.MEDIUM, enabled: true, isBuiltIn: true },
  { id: 'm4', name: 'LDAP 注入风险', pattern: '(ldap_search|ldap_list|ldap_read)\\s*?\\(', type: VulnerabilityType.LDAP_INJECTION, level: RiskLevel.MEDIUM, enabled: true, isBuiltIn: true },

  // --- 低危规则 ---
  { id: 'l1', name: '弱哈希算法 (MD5/SHA1)', pattern: '(md5|sha1)\\s*?\\(', type: VulnerabilityType.WEAK_CRYPTO, level: RiskLevel.LOW, enabled: true, isBuiltIn: true },
  { id: 'l2', name: '硬编码密码/密钥', pattern: '(password|passwd|secret|key)\\s*=\\s*[\\\x27"][^\\\x27"]+[\\\x27"]', type: VulnerabilityType.SENSITIVE_CALL, level: RiskLevel.LOW, enabled: true, isBuiltIn: true },
  { id: 'l3', name: '不安全的反序列化 (普通)', pattern: 'unserialize\\s*?\\(', type: VulnerabilityType.DESERIALIZATION, level: RiskLevel.LOW, enabled: true, isBuiltIn: true },
  { id: 'l4', name: '动态代码执行风险', pattern: '(create_function|assert)\\s*?\\(', type: VulnerabilityType.CODE_EXECUTION, level: RiskLevel.LOW, enabled: true, isBuiltIn: true },

  // --- Webshell 专项规则 ---
  { id: 'w1', name: '一句话木马特征 (Eval/Assert)', pattern: '(eval|assert|preg_replace\\s*?\\(\\s*?[\x27"].*?\\/e[\x27"])\\s*?\\(\\s*?([$]_(POST|GET|REQUEST|COOKIE|SERVER|FILES)|base64_decode|gzinflate|str_rot13)', type: VulnerabilityType.WEBSHELL, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },
  { id: 'w2', name: '动态函数调用 (变量执行)', pattern: '\\$([$]\\w+)\\s*?\\(\\s*?\\$_(POST|GET|REQUEST|COOKIE)', type: VulnerabilityType.WEBSHELL, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },
  { id: 'w3', name: '代码隐写/混淆加载', pattern: '(base64_decode|gzinflate|str_rot13|hex2bin|pack|unpack)\\s*?\\(.*?([$]_(POST|GET|REQUEST|COOKIE|SERVER)|file_get_contents|curl_exec)', type: VulnerabilityType.WEBSHELL, level: RiskLevel.HIGH, enabled: true, isBuiltIn: true },
  { id: 'w4', name: '可疑系统指令反弹', pattern: '(system|shell_exec|exec|passthru|popen|proc_open)\\s*?\\(.*?([$]_(POST|GET|REQUEST|COOKIE)|base64_decode)', type: VulnerabilityType.WEBSHELL, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true },
  { id: 'w5', name: '冰蝎/蚁剑强特征', pattern: '(@error_reporting|@set_time_limit|@ini_set).*?eval\\s*?\\(.*?base64_decode', type: VulnerabilityType.WEBSHELL, level: RiskLevel.CRITICAL, enabled: true, isBuiltIn: true }
];
