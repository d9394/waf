require 'init'

function check_and_block()
    local blacklist = ngx.shared.cc_blacklist
    local ip = ngx.var.remote_addr
    if ip == "127.0.0.1" or ip == "::1" then
        return
    end
    local is_banned, err = blacklist:get(ip)
    if is_banned then
        ngx.log(ngx.WARN, "Blocked globally by cc_blacklist: ", ip)
        return ngx.exit(ngx.HTTP_CLOSE)
    end
end

function waf_main()
    check_and_block()
    if white_ip_check() then
    elseif black_ip_check() then
    elseif user_agent_attack_check() then
    elseif cc_attack_check() then
    elseif cookie_attack_check() then
    elseif white_url_check() then
    elseif url_attack_check() then
    elseif url_args_attack_check() then
    elseif referer_attack_check() then
    --elseif post_attack_check() then
    else
        return
    end
end

waf_main()
