-- Private request state is set only by the pinned Bouncer's ban branch.
local cjson = require "cjson.safe"
local M = {}

function M.mark(ip, cause, expected_status)
    ngx.ctx.crowdsec_1key_execution = {
        ip = ip, cause = cause, expected_status = expected_status,
        request_id = ngx.var.request_id
    }
end

function M.emit()
    local item = ngx.ctx.crowdsec_1key_execution
    if not item or ngx.is_subrequest then return end
    local status = tonumber(ngx.status)
    local upstream = ngx.var.upstream_addr or ""
    if upstream ~= "" or status ~= tonumber(item.expected_status)
        or status < 400 or status > 599 then return end
    local record = cjson.encode({v = 1, time = ngx.now(), ip = item.ip,
        cause = item.cause, status = status, upstream = upstream,
        request_id = item.request_id})
    if record then ngx.log(ngx.ERR, "CB_EXEC_V1 ", record) end
end

return M
