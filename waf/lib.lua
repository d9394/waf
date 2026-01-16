--waf core lib
require 'config'

-- 在函数外部定义一个全局 Table 用于存放规则缓存
-- 注意：这个变量要在 lib.lua 的顶层定义，这样它就会驻留在内存中
local _RULES_CACHE = {}

--Get the client IP
function get_client_ip()
    local CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
end

--Get the client user agent
function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

--Get WAF rule
--function get_rule(rulefilename)
--    local io = require 'io'
--    local RULE_PATH = config_rule_dir
--    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
--    if RULE_FILE == nil then
--        return
--    end
--    local RULE_TABLE = {}
--    for line in RULE_FILE:lines() do
--        table.insert(RULE_TABLE,line)
--    end
--    RULE_FILE:close()
--    return(RULE_TABLE)
--end

function get_rule(rulefilename)
    -- 1. 检查缓存中是否已经存在该规则
    if _RULES_CACHE[rulefilename] then
        return _RULES_CACHE[rulefilename]
    end

    -- 2. 如果缓存没有，则读取文件
    local io = require 'io'
    local RULE_PATH = config_rule_dir
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename, "r")

    if RULE_FILE == nil then
        -- 如果文件不存在，可以返回一个空表防止后续 pairs 报错，或者直接返回 nil
        return nil
    end

    local RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        -- 过滤掉空行和无效行
        if line ~= "" then
            table.insert(RULE_TABLE, line)
        end
    end
    RULE_FILE:close()

    -- 3. 将结果存入缓存并返回
    _RULES_CACHE[rulefilename] = RULE_TABLE
    -- ngx.log(ngx.INFO, "WAF_LOG: Loaded rule file into memory: ", rulefilename) -- 调试用

    return RULE_TABLE
end

--WAF log record for json,(use logstash codec => json)
function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }
    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME = LOG_PATH..'/waf_'..ngx.today()..".log"
    local file = io.open(LOG_NAME,"a")
    if file == nil then
        return
    end
    file:write(LOG_LINE.."\n")
    file:flush()
    file:close()
end

--WAF return
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)
        ngx.exit(ngx.status)
    end
end

--add ip to be ban by WAF
function add_ban_ip(reason, ban_time)
    -- 1. 设置默认值：如果 reason 为空，默认为 "Unknown"
    reason = reason or "Unknown"

    -- 2. 设置默认值：如果 ban_time 为空或不是数字，默认为 86400
    ban_time = tonumber(ban_time) or 86400

    local ip = ngx.var.remote_addr
    local blacklist = ngx.shared.cc_blacklist

    -- 3. 执行封禁,blacklist:set(key, value, exptime)， 第三个参数就是过期时间（秒），0 表示永不过期
    local ok, err = blacklist:set(ip, 1, ban_time)

    if not ok then
        ngx.log(ngx.ERR, "Failed to write IP to blacklist: ", ip, " error: ", err)
    else
        -- 记录日志，注意这里打印的是实际生效的 ban_time
        ngx.log(ngx.ERR, "[WAF_BAN] IP: ", ip, " Reason: ", reason, " Duration: ", ban_time, "s")
    end
end
