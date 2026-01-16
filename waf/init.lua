--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

--allow white ip
function white_ip_check()
     if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jo") then
                    log_record('White_IP',ngx.var_request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

--deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"jo") then
                    log_record('BlackList_IP',ngx.var_request_uri,"_","_")
                    if config_waf_enable == "on" then
                        ngx.exit(444)
                        return true
                    end
                end
            end
        end
    end
end

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTACK_URI=ngx.var.uri
        local CC_TOKEN = get_client_ip()..ATTACK_URI
        local limit = ngx.shared.limit
        local CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        local CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req > CCcount then
                log_record('CC_Attack',ngx.var.request_uri,"-","-")
                if config_waf_enable == "on" then
                    ngx.exit(403)
                end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

--deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
         end
    end
    return false
end

--deny url
function url_attack_check()

    --local REQ_URI = ngx.var.request_uri
    --local REFERER = ngx.var.http_referer

    -- 新增拦截逻辑：针对 /forum/ 或 /aprs1/ 且 Referer 为空的情况
    --if REQ_URI then
        -- 使用正则匹配路径前缀
        --if ngx.re.find(REQ_URI, [[^/(forum|aprs1)/]], "jo") then
            -- 【防误杀逻辑】：如果请求的是静态 .html 页面，通常允许空 Referer
            --local is_html = ngx.re.find(REQ_URI, [[\.html(\?.*)?$]], "jo")
            -- 如果 Referer 为空（nil 或 空字符串）
            --if (REFERER == nil or REFERER == "") and not is_html then
                --log_record('Deny_Empty_Referer', REQ_URI, "-", "Non-HTML Empty Referer")
                --if config_waf_enable == "on" then
                    --add_ban_ip("Matched_Rule: " .. rule)
                    --waf_output()
                    --return true
                --end
            --end
        --end
    --end

    if config_url_check == "on" then
        -- 获取最原始的请求串（包含 rewrite 之前的路径）
        local RAW_URI = ngx.var.request_uri

        -- 1. 拦截路径递归特征 (针对原始请求)
        if ngx.re.find(RAW_URI, "(/m/|/simple/){2,}", "jo") then
            log_record('Deny_Recursive_Path', RAW_URI, "-", "Path Recursion")
            ngx.exit(444)
            return true
        end

        -- 2. 拦截路径层级过深 (针对原始请求)
        local _, count = string.gsub(RAW_URI, "/", "")
        if count > 10 then
            log_record('Deny_Deep_Path', RAW_URI, "-", "Path Depth")
            ngx.exit(444)
            return true
        end

        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule)
                if config_waf_enable == "on" then
                    add_ban_ip("Matched_Rule: " .. rule)
                    --waf_output()
                    ngx.exit(444)
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
--function url_args_attack_check()
--    if config_url_args_check == "on" then
--        local ARGS_RULES = get_rule('args.rule')
--        for _,rule in pairs(ARGS_RULES) do
--            local REQ_ARGS = ngx.req.get_uri_args()
--            for key, val in pairs(REQ_ARGS) do
--                if type(val) == 'table' then
--                    local ARGS_DATA = table.concat(val, " ")
--                else
--                    local ARGS_DATA = val
--                end
--                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
--                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule)
--                    if config_waf_enable == "on" then
--                      add_ban_ip("Matched_Rule: " .. rule)
--                        waf_output()
--                        return true
--                    end
--                end
--            end
--        end
--    end
--    return false
--end
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule')
        -- 1. 将参数获取移出规则循环，只执行一次
        local REQ_ARGS = ngx.req.get_uri_args()

        -- 2. 先遍历参数，再遍历规则（这样逻辑更清晰，性能更好）
        for key, val in pairs(REQ_ARGS) do
            local ARGS_DATA
            if type(val) == 'table' then
                ARGS_DATA = table.concat(val, " ")
            else
                ARGS_DATA = val
            end

            if ARGS_DATA and type(ARGS_DATA) ~= "boolean" then
                -- 3. 【核心修改】双重解码 + 转小写
                -- 处理 %25%27 -> %27 -> '
                local decoded_data = unescape(unescape(ARGS_DATA)):lower()

                for _, rule in pairs(ARGS_RULES) do
                    -- 4. 匹配时将规则也转为小写（实现不区分大小写匹配）
                    if rule ~= "" and rulematch(decoded_data, rule:lower(), "jo") then
                        log_record('Deny_URL_Args', ngx.var.request_uri, "-", rule)

                        if config_waf_enable == "on" then
                            add_ban_ip("Matched_Rule: " .. rule)
                            -- 如果你的 waf_output 是返回 HTML 提示，就用它
                            -- 如果想直接断开连接，用 ngx.exit(444)
                            --waf_output()
                            ngx.exit(444)
                            return true
                        end
                    end
                end
            end
        end
    end
    return false
end

--deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
--                        add_ban_ip("Matched_Rule: " .. rule)
--                        waf_output()
--                        return true
--                      ngx.log(ngx.WARN, "Dropped UA: ", USER_AGENT, " rule: ", rule)
                        ngx.exit(444)
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post
function post_attack_check()
    if config_post_check == "on" then
        local POST_RULES = get_rule('post.rule')
        for _,rule in pairs(ARGS_RULES) do
            local POST_ARGS = ngx.req.get_post_args()
        end
        return true
    end
    return false
end

-- deny referer
function referer_attack_check()
    if config_referer_check == "on" then
        local REFERER_RULES = get_rule('referer.rule')
        -- 获取 referer，并处理可能的空值
        local USER_REFERER = ngx.var.http_referer
        local URI = ngx.var.uri -- 匹配路径部分

        -- 判断条件：Referer 不存在 (nil) 或者 明确为 "-"
        if USER_REFERER == nil or USER_REFERER == "-" or USER_REFERER == "" then
            -- ngx.log(ngx.ERR, "WAF_TRACE: URI is [", URI, "], Referer is [", USER_REFERER, "]")
            for _, rule in pairs(REFERER_RULES) do
                if rule ~= "" and rulematch(URI, rule, "jo") then
                    -- 命中后记录并退出
                    log_record('Deny_Referer', ngx.var.request_uri, "-", rule)
                    if config_waf_enable == "on" then
                        ngx.exit(444)
                        return true
                    end
                end
            end
        end
    end
    return false
end
