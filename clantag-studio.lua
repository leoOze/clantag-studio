-- Clantag Studio 2.1 - dedicated tab and Undercover-setter.
-- Native layout verified against the installed tier0.dll (timestamp 1788980629).
-- Unknown builds fail closed. All foreign memory is copied through Win32.
-- Do not run multiple name changers concurrently.

local ffi = ffi
local config = {
    enabled = true,
    undercover_enabled = false, undercover_name = '',
    interval = 0.8,
    confirmation_timeout = 5.0,
    text = 'fatality ', mode = 2, casing = 1, reverse = false
}
local ui = { keep = {}, syncing = false }
local runtime = { busy=false, halted=false, closed=false, loading=true, stage='start' }
local function stage(name)
    runtime.stage=name
    if runtime.loading then print('[Clantag Studio] init: '..name) end
end
-- Not an exception catcher: if a native callback unwinds before returning,
-- the NEXT invocation stops instead of repeating the failed operation.
local function guarded(name,fn)
    return function(...)
        if runtime.closed or runtime.halted then return end
        if runtime.busy then
            if ui.syncing and name=='menu: ativar' then return end
            runtime.halted=true
            print('[Clantag Studio] Callback stopped at: '..runtime.stage..'. Reload and send this line.')
            return
        end
        runtime.busy=true;stage(name)
        fn(...)
        runtime.busy=false
    end
end

local state = {
    original = nil, confirmed = nil, pending = nil,
    frame = 1, next_update = 0, deadline = 0, last_time = 0,
    fallback_sent = false,
    blocked = false, connected = false, message = nil, saw_confirmation = false
}

local function report(message)
    if state.message ~= message then
        state.message = message
        print('[Clantag Studio] ' .. message)
    end
end

local native = { ready = false }

local function initialize_native()
    if not ffi or not utils or not utils.FindExport then
        return false, 'FFI/FindExport unavailable; enable unsafe Lua access in Fatality.'
    end
    if ffi.sizeof('void*') ~= 8 then return false, 'Requires a Windows x64 process.' end
    local rpm_address = utils.FindExport('kernel32.dll', 'ReadProcessMemory')
    local wpm_address = utils.FindExport('kernel32.dll', 'WriteProcessMemory')
    local factory = tonumber(utils.FindExport('tier0.dll', 'CreateInterface'))
    if not rpm_address or rpm_address == 0 or not wpm_address or wpm_address == 0
        or not factory or factory == 0 then
        return false, 'Required exports unavailable; no pointer was accessed.'
    end
    local rpm = ffi.cast('int (__stdcall *)(void*, const void*, void*, size_t, size_t*)', rpm_address)
    local wpm = ffi.cast('int (__stdcall *)(void*, void*, const void*, size_t, size_t*)', wpm_address)
    local process = ffi.cast('void*', -1)
    local function read(address, length)
        if not address or address < 0x10000 or address + length > 0x7FFFFFFFFFFF then return nil end
        local buffer, count = ffi.new('uint8_t[?]', length), ffi.new('size_t[1]')
        if rpm(process, ffi.cast('const void*', address), buffer, length, count) == 0
            or tonumber(count[0]) ~= length then return nil end
        return buffer
    end
    local function number(buffer, offset, ctype)
        return tonumber(ffi.cast('const ' .. ctype .. '*', buffer + offset)[0])
    end
    local function matches(address, value)
        local buffer = read(address, #value)
        return buffer ~= nil and ffi.string(buffer, #value) == value
    end

    -- Build and instruction checks BEFORE applying any layout offsets.
    local base = factory - 0x20AE70
    local dos = read(base, 64)
    if not dos or ffi.string(dos, 2) ~= 'MZ' then return false, 'Unrecognized tier0 base.' end
    local pe_offset = number(dos, 0x3C, 'uint32_t')
    if pe_offset < 64 or pe_offset > 4096 then return false, 'Invalid PE header.' end
    local pe = read(base + pe_offset, 0x60)
    if not pe or ffi.string(pe, 4) ~= 'PE\0\0'
        or number(pe, 4, 'uint16_t') ~= 0x8664
        or number(pe, 8, 'uint32_t') ~= 1788980629
        or number(pe, 0x50, 'uint32_t') ~= 0x3FA000 then
        return false, 'Build de tier0 diferente da validada; atualize os offsets antes de usar.'
    end
    if not matches(factory, '\x4C\x8B\x0D\x29\x80\x19\x00')
        or not matches(base + 0x685A0, '\x48\x8D\x05\x49\xCF\x33\x00\xC3') then
        return false, 'Interface code changed; initialization cancelled.'
    end

    -- Read registration nodes; never call an unknown fnCreate or vtable slot.
    local head = read(base + 0x3A2EA0, 8)
    if not head then return false, 'Interface list unreadable.' end
    local node, seen, found = number(head, 0, 'uint64_t'), {}, false
    for _ = 1, 256 do
        if node == 0 then break end
        if seen[node] then return false, 'Cycle in interface list.' end
        seen[node] = true
        local entry = read(node, 24)
        if not entry then return false, 'Interface entry unreadable.' end
        if matches(number(entry, 8, 'uint64_t'), 'VEngineCvar007\0') then
            if number(entry, 0, 'uint64_t') ~= base + 0x685A0 then
                return false, 'Factory VEngineCvar007 inesperada.'
            end
            found = true
            break
        end
        node = number(entry, 16, 'uint64_t')
    end
    if not found then return false, 'VEngineCvar007 not found.' end
    local object = base + 0x3A54F0 -- decoded from the verified LEA above
    local header = read(object, 0x68)
    if not header or number(header, 0, 'uint64_t') ~= base + 0x30DF48 then
        return false, 'Unrecognized CCvar instance.'
    end
    -- Current build: list at +0x48, storage at +0x50, head at +0x58.
    local data, index = number(header, 0x50, 'uint64_t'), number(header, 0x58, 'uint16_t')
    local previous, visited, target = 65535, {}, nil
    for _ = 1, 65535 do
        if index == 65535 then break end
        if visited[index] then return false, 'Cycle in convar list.' end
        visited[index] = true
        local entry = read(data + index * 16, 16)
        if not entry or number(entry, 8, 'uint16_t') ~= previous then
            return false, 'Convar list invalid or changed during reading.'
        end
        local address = number(entry, 0, 'uint64_t')
        local cv = read(address, 0x38)
        if not cv then return false, 'Convar ilegivel.' end
        if matches(number(cv, 0, 'uint64_t'), 'name\0') then
            if number(cv, 0x28, 'int16_t') ~= 9 then return false, 'name convar is not a string.' end
            target = address
            break
        end
        previous, index = index, number(entry, 10, 'uint16_t')
    end
    if not target then return false, 'name convar not found.' end
    local function current_flags()
        local cv = read(target, 0x38)
        if not cv or number(cv, 0x28, 'int16_t') ~= 9
            or not matches(number(cv, 0, 'uint64_t'), 'name\0') then return nil end
        return ffi.string(cv + 0x30, 8)
    end
    local original = current_flags()
    if not original then return false, 'Could not validate name.' end
    local api = game.cvar:Find('name')
    local low = ffi.new('uint32_t[2]')
    ffi.copy(low, original, 8)
    if not api or api.name ~= 'name' or type(api.value) ~= 'string'
        or not tonumber(api.flags) or tonumber(api.flags) % 4294967296 ~= tonumber(low[0]) then
        return false, 'Native flags differ from Fatality API; nothing was written.'
    end
    -- FCVAR_USERINFO (1<<9) only. Preserve all other 63 bits.
    local added = math.floor(tonumber(low[0]) / 512) % 2 == 0
    if added then low[0] = low[0] + 512 end
    local patched = ffi.string(low, 8)
    local function write_flags(expected, replacement)
        if current_flags() ~= expected then return false end
        local count = ffi.new('size_t[1]')
        local ok = wpm(process, ffi.cast('void*', target + 0x30), replacement, 8, count)
        return ok ~= 0 and tonumber(count[0]) == 8 and current_flags() == replacement
    end
    if added and not write_flags(original, patched) then
        write_flags(patched, original)
        return false, 'Could not apply USERINFO to name.'
    end
    native.ready = true
    native.valid = function() return current_flags() == patched end
    native.release = function()
        -- Remove only our bit, preserving subsequent changes to other flags.
        if not added then return true end
        local current = current_flags()
        if not current then return false end
        local words = ffi.new('uint32_t[2]')
        ffi.copy(words, current, 8)
        if math.floor(tonumber(words[0]) / 512) % 2 == 0 then return true end
        words[0] = words[0] - 512
        return write_flags(current, ffi.string(words, 8))
    end
    return true, 'name validated; USERINFO active. Waiting for controller confirmation.'
end

local function clean(value, limit)
    local text = tostring(value or ''):gsub('[";\\]', ''):gsub('%c', '')
    local result = ''
    -- Limit bytes without splitting UTF-8 codepoints.
    for char in text:gmatch('[%z\1-\127\194-\244][\128-\191]*') do
        if #result + #char > limit then break end
        result = result .. char
    end
    return result
end

local function compose_name(tag, original)
    -- Preserve the captured nickname; shorten only the animated prefix.
    local budget = 32 - #original - 1
    if budget < 1 then return original end
    local prefix = clean(tag, budget):gsub('^%s+', ''):gsub('%s+$', '')
    if prefix == '' or prefix == '.' then return original end
    return prefix .. ' ' .. original
end

local modes = {'Type / erase', 'Marquee', 'Back and forth', 'Scanner', 'Glitch', 'Center outward', 'Static', 'HVHRAT Portal'}
local cases = {'Original', 'lowercase', 'UPPERCASE', 'Upper/lower pulse', 'Uppercase wave'}
local frames = {}
local function chars(text)
    local out = {}
    for c in text:gmatch('[%z\1-\127\194-\244][\128-\191]*') do out[#out+1] = c end
    return out
end
local lower, upper = {}, {}
local accents_low = chars('áàâãäéèêëíìîïóòôõöúùûüçñ')
local accents_up = chars('ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇÑ')
for i, c in ipairs(accents_low) do lower[accents_up[i]], upper[c] = c, accents_up[i] end
local function casechar(c, up)
    if up then return upper[c] or c:upper() end
    return lower[c] or c:lower()
end
local function gcd(a,b) while b ~= 0 do a,b = b,a%b end return a end
local function compile(c)
    local letters, result = chars(c.text), {}
    local n = #letters
    local lengths = {math.max(1,2*n), n, math.max(1,2*n-2), n, 2*n, 2*n, 1, 8}
    local period = lengths[c.mode]
    local caseperiod = c.casing == 4 and 2 or (c.casing == 5 and n or 1)
    local total = period * caseperiod / gcd(period, caseperiod)
    for step=0,total-1 do
        local list = {}
        for i,ch in ipairs(letters) do
            if c.casing == 2 then ch=casechar(ch,false)
            elseif c.casing == 3 then ch=casechar(ch,true)
            elseif c.casing == 4 then ch=casechar(ch,step%2==0)
            elseif c.casing == 5 then ch=casechar(ch,(i-1)==step%n) end
            list[i]=ch
        end
        local p, text = step%period, ''
        if c.mode == 1 or c.mode == 6 then
            local count = p <= n and p or 2*n-p
            local first = c.mode == 6 and math.floor((n-count)/2)+1 or 1
            for i=first,first+count-1 do text=text..list[i] end
        elseif c.mode == 2 or c.mode == 3 then
            local offset = c.mode == 3 and (p<n and p or 2*n-2-p) or p
            for i=1,n do text=text..list[(i-1+offset)%n+1] end
        elseif c.mode == 4 then
            for i,ch in ipairs(list) do text=text..(i==p+1 and '['..ch..']' or ch) end
        elseif c.mode == 5 then
            local symbols='_-+*'
            local target=math.floor(p/2)+1
            for i,ch in ipairs(list) do
                text=text..(p%2==0 and i==target and symbols:sub(target%4+1,target%4+1) or ch)
            end
        elseif c.mode == 8 then
            -- Pulse-style frames use plain letters, dash and underscore.
            -- Keep the special look without brackets/angle bars that may be
            -- rejected or normalized by some name paths.
            local core=table.concat(list):gsub('^%s+',''):gsub('%s+$','')
            local lower_core,upper_core=core:lower(),core:upper()
            local patterns={
                lower_core, lower_core..'_', '_'..lower_core..'_',
                '-'..upper_core..'-', '_'..upper_core..'_',
                upper_core..'_', upper_core, core
            }
            text=patterns[p+1]
        else text=table.concat(list) end
        -- CS2 may trim edge spaces. Canonicalize before confirmation.
        text=clean(text,32):gsub('^%s+',''):gsub('%s+$','')
        result[#result+1]=text~='' and text or '.'
    end
    if c.reverse then
        local reversed={}
        for i=#result,1,-1 do reversed[#reversed+1]=result[i] end
        return reversed
    end
    return result
end

-- A reversible config code, NOT encryption, authentication or executable Lua.
local function checksum(s)
    local a,b=1,0
    for i=1,#s do a=(a+s:byte(i))%65521;b=(b+a)%65521 end
    return string.format('%08X',b*65536+a)
end
local function encode(c)
    local hex=c.text:gsub('.',function(ch) return string.format('%02X',ch:byte()) end)
    local body=table.concat({'CT2',c.mode,c.casing,c.reverse and 1 or 0,math.floor(c.interval*1000+0.5),hex},':')
    return body..':'..checksum(body)
end
local function decode(code)
    if type(code)~='string' or #code>180 then return nil,'Code too long or invalid.' end
    code=code:gsub('^%s+',''):gsub('%s+$','')
    local m,c,r,ms,hex,sum=code:match('^CT2:(%d):(%d):([01]):(%d+):([%x]+):(%x%x%x%x%x%x%x%x)$')
    if not m then return nil,'Invalid format; expected CT2.' end
    if checksum(code:sub(1,-10))~=sum:upper() then return nil,'Incorrect checksum; code is incomplete or changed.' end
    m,c,ms=tonumber(m),tonumber(c),tonumber(ms)
    if not modes[m] or not cases[c] or ms<500 or ms>3000 or ms%100~=0 or #hex%2~=0 or #hex>48 then
        return nil,'Configuration out of range.'
    end
    local text=hex:gsub('%x%x',function(pair) return string.char(tonumber(pair,16)) end)
    if clean(text,24)~=text or not text:find('%S') then return nil,'Empty or unsafe text.' end
    -- Reject malformed/overlong UTF-8 and surrogate codepoints in imported data.
    for _,ch in ipairs(chars(text)) do
        local first,second=ch:byte(1,2)
        local width=first<128 and 1 or (first<224 and 2 or (first<240 and 3 or 4))
        if #ch~=width or (first==224 and second<160) or (first==237 and second>159)
            or (first==240 and second<144) or (first==244 and second>143) then
            return nil,'Text is not valid UTF-8.'
        end
    end
    return {text=text,mode=m,casing=c,reverse=r=='1',interval=ms/1000}
end

local clock = {}
local function clock_utc(now)
    -- Official API only. Interpolate after observing a UTC second boundary.
    -- Phase accuracy is limited by the frame that observes that boundary.
    if not utils.GetUnixTime then return now end
    stage('clock: utils.GetUnixTime')
    local second=utils.GetUnixTime()
    if type(second)~='number' then return now end
    if clock.second~=second or (clock.last and now<clock.last) then
        clock.second,clock.anchor=second,now
    end
    clock.last=now
    return second+math.max(0,math.min(0.999,now-clock.anchor))
end
local function preview_at(now)
    return frames[math.floor(now/config.interval)%#frames+1]
end

local function set_undercover(value, enabled)
    local name=clean(value,24):gsub('^%s+',''):gsub('%s+$','')
    if enabled and not name:find('%S') then return false,'Enter a valid name.' end
    if name~='' then
        local valid=decode(encode({text=name,mode=7,casing=1,reverse=false,interval=0.8}))
        if not valid then return false,'Name is not valid UTF-8.' end
    end
    config.undercover_name=name
    config.undercover_enabled=enabled==true
    state.next_update=0;state.disable_restore_sent=false
    return true
end
local function base_name(original)
    return config.undercover_enabled and config.undercover_name or original
end

local function save()
    if utils.DbSave then
        stage('config: DbSave')
        if not utils.DbSave({code=encode(config),enabled=config.enabled,
            undercover_enabled=config.undercover_enabled,undercover_name=config.undercover_name},'clantag_studio_v2') then
            report('Configuration applied, but could not be saved locally.')
        end
    end
end
local function apply(c, persist)
    -- All sources (including our menu and saved data) pass the same validator.
    local validated,reason=decode(encode(c))
    if not validated then report(reason);return false end
    for k,v in pairs(validated) do config[k]=v end
    frames=compile(config)
    state.next_update=0
    if persist then save() end
    return true
end

local function build_menu()
    if not gui then return end
    local function keep(item)
        if item then ui.keep[#ui.keep+1]=item end
        return item
    end
    local edit,share,undercover
    local icon=draw and draw.textures and draw.textures['gui_icon_down']
    if icon and gui.GetMainWindow and gui.TabLayoutMode and gui.GroupWidthMode
        and gui.GroupWidthMode.FULL~=nil then
        stage('menu: window')
        local window=keep(gui.GetMainWindow())
        if window then
        stage('menu: Clantag Studio tab')
            local tab=keep(window:AddTab('clantag_studio_tab_v21',icon,'Clantag Studio',gui.TabLayoutMode.DEFAULT))
            if tab then
                stage('menu: tab groups')
                edit=keep(gui.Group('clantag_studio_animation_v21','Animated clantag',440,gui.GroupWidthMode.FULL))
                share=keep(gui.Group('clantag_studio_share_v21','Presets and sharing',360,gui.GroupWidthMode.FULL))
                undercover=keep(gui.Group('clantag_studio_undercover_v21','Undercover-setter',220,gui.GroupWidthMode.FULL))
                tab:Add(edit);tab:Add(share);tab:Add(undercover)
                ui.menu_path='Clantag Studio'
            end
        end
    end
    if not edit then
        edit=keep(gui.ctx:Find('lua>elements a'))
        share=keep(gui.ctx:Find('lua>elements b'))
        undercover=share
        ui.menu_path='Lua > Elements A/B (tab unavailable)'
    end
    if not edit or not share or not undercover then
        report('Menu areas unavailable.')
        return
    end
    local function control(group,id,label,kind,...)
        stage('menu: create '..id)
        local item,row=gui.MakeControlEasy('clantag_studio_v201_'..id,label,kind,...)
        keep(item);keep(row)
        group:Add(row);return item
    end
    local function button(group,id,label,callback)
        stage('menu: button '..id)
        local item=keep(gui.Button('clantag_studio_v201_'..id,label))
        group:Add(item);item:AddCallback(guarded('botao: '..id,callback));return item
    end
    local function combo(id,label,items)
        stage('menu: combo '..id)
        local item=keep(gui.ComboBox('clantag_studio_v201_'..id))
        item.allowMultiple=false
        for i,name in ipairs(items) do
            item:Add(keep(gui.Selectable('clantag_studio_v201_'..id..i,name)))
        end
        edit:Add(keep(gui.MakeControl(label,item)))
        return item
    end
    local function select(item,index)
        item:GetValue():Get():SetRaw(2^(index-1))
    end
    local function selected(item,n)
        local raw=item:GetValue():Get():GetRaw()
        for i=1,n do if raw==2^(i-1) then return i end end
        return 1
    end
    -- Static labels: create once, never call the native SetText path.
    if gui.Label then
        edit:Add(keep(gui.Label('clantag_studio_build_v21','build: 2.1')))
        edit:Add(keep(gui.Label('clantag_studio_author_v21','coded by $ky')))
    end
    ui.enabled=control(edit,'enabled','Enable animated clantag','checkbox')
    ui.text=control(edit,'text','Custom text (24 bytes)','text_input')
    ui.text.tooltip='Edit the text and choose a preset effect. Lua code is not accepted. Trailing spaces are part of the marquee.'
    ui.mode=combo('mode','Animation',modes)
    ui.casing=combo('case','Letter case',cases)
    ui.speed=control(edit,'speed','Frame interval (ms)','slider',500,3000,{'%.0f'},100)
    ui.direction=control(edit,'direction','Reverse direction','checkbox')
    -- No dynamic native labels or tab:Reset; retain all native menu objects.
    local function populate()
        ui.syncing=true
        stage('menu: text and enabled values')
        ui.enabled:SetValue(config.enabled);ui.text:SetValue(config.text)
        stage('menu: combo values')
        select(ui.mode,config.mode);select(ui.casing,config.casing)
        stage('menu: slider value')
        ui.speed:GetValue():Set(config.interval*1000);ui.speed:Reset()
        ui.direction:SetValue(config.reverse)
        ui.syncing=false
    end
    ui.populate=populate
    local function from_menu()
        local text=clean(ui.text.value,24)
        local c={text=text,mode=selected(ui.mode,#modes),casing=selected(ui.casing,#cases),reverse=ui.direction:GetValue():Get(),
            interval=math.floor(ui.speed:GetValue():Get()/100+0.5)/10}
        if not apply(c,true) then return false end
        ui.text:SetValue(config.text)
        report('Configuration applied and saved.');return true
    end
    button(edit,'apply','Apply text and effects',from_menu)
    button(edit,'reverse','Reverse direction',function()
        if not from_menu() then return end
        config.reverse=not config.reverse;frames=compile(config);save();populate()
        report(config.reverse and 'Direction reversed.' or 'Normal direction.')
    end)
    local function preset(text,mode,casing)
        apply({text=text,mode=mode,casing=casing,reverse=false,interval=0.8},true)
        populate();report('Preset applied: '..text)
    end
    button(share,'fatality','fatality ',function() preset('fatality ',2,1) end)
    button(share,'hvhrat','hvhrat',function() preset('hvhrat',8,1) end)
    button(share,'specter','specter //',function() preset('specter ',4,4) end)
    ui.code=control(share,'code','Clantag code (CT2)','text_input')
    button(share,'copy','Copy clantag',function()
        if not from_menu() then return end
        local code=encode(config);ui.code:SetValue(code)
        if utils.ClipboardSet then utils.ClipboardSet(code);report('CT2 code copied. Share it with someone using this Lua.')
        else report('Clipboard unavailable; copy the code from the CT2 field.') end
    end)
    button(share,'paste','Paste code',function()
        if utils.ClipboardGet then ui.code:SetValue(utils.ClipboardGet() or '') end
    end)
    button(share,'import','Import clantag',function()
        local c,reason=decode(ui.code.value)
        if not c then report(reason);return end
        apply(c,true);populate();report('Clantag imported. Same configuration and UTC reference; no connection between players.')
    end)
    button(share,'status','Show status in console',function()
        print('[Clantag Studio] '..(state.message or 'Waiting for game.'))
        print('[Clantag Studio] Direction: '..(config.reverse and 'reversed' or 'normal'))
        print('[Clantag Studio] Preview: '..table.concat(frames,' | ',1,math.min(#frames,12)))
    end)
    ui.undercover=control(undercover,'undercover_name','Custom static name (24 bytes)','text_input')
    ui.undercover:SetValue(config.undercover_name)
    button(undercover,'undercover_apply','Apply Undercover name',function()
        local ok,reason=set_undercover(ui.undercover.value,true)
        if not ok then report(reason);return end
        ui.undercover:SetValue(config.undercover_name)
        save();report('Static name applied. Clantag animation remains independent.')
    end)
    button(undercover,'undercover_reset','Restore original name',function()
        set_undercover(config.undercover_name,false)
        save();report('Original name selected; clantag settings remain unchanged.')
    end)
    -- Set initial values before enabling callbacks.
    populate()
    ui.enabled:AddCallback(guarded('menu: ativar',function()
        config.enabled=ui.enabled:GetValue():Get();state.next_update=0;state.disable_restore_sent=false;save()
        report(config.enabled and 'Animation enabled.' or 'Animation disabled; selected static name remains.')
    end))
    stage('menu: group layout')
    edit:Reset();share:Reset()
    if undercover~=share then undercover:Reset() end
end

local function reset_session()
    state.resume_original, state.resume_confirmed, state.resume_pending = state.original, state.confirmed, state.pending
    state.original, state.confirmed, state.pending = nil, nil, nil
    state.frame, state.next_update, state.deadline = 1, 0, 0
    state.fallback_sent = false
    state.blocked = false
    state.saw_confirmation = false
    state.disable_restore_sent = false
end

local function advance(now)
    -- Do not delay another full frame AFTER the acknowledgement.
    state.next_update = math.max(state.next_update, now)
end

local function send_name(name, alternate)
    -- Values here have already been validated or sanitized.
    stage('name: validate flags')
    if not native.ready or not native.valid() then
        state.blocked = true
        report('name flags changed or became unreadable; command cancelled.')
        return false
    end
    stage('name: ClientCmd')
    local command=alternate and 'name' or 'setinfo name'
    -- The alternate command uses the documented unrestricted ClientCmd mode.
    -- Some CS2 builds reject the name convar through the restricted path.
    game.engine:ClientCmd(command..' "' .. name .. '"',alternate==true)
    return true
end

local function restore()
    if not state.original or not game.engine:IsConnected() or not game.engine:InGame() then return end
    local controller = entities.GetLocalController()
    if not controller then return end
    local observed = controller:GetName()
    local ours = observed == state.confirmed or observed == state.pending
    if not ours or observed == state.original then return end
    if send_name(state.original) then
        report('Name restoration requested; cannot verify after unloading.')
    end
end

local function update()
    if not native.ready then return end
    stage('game: connection')
    local connected = game.engine:IsConnected() and game.engine:InGame()
    if not connected then
        if state.connected then reset_session() end
        state.connected = false
        return
    end
    state.connected = true
    if state.blocked then
        if not config.enabled and not config.undercover_enabled and not state.disable_restore_sent then
            restore();state.disable_restore_sent=true
        end
        return
    end
    stage('game: controller')
    local controller = entities.GetLocalController()
    if not controller then return end
    stage('game: GetName')
    local observed = controller:GetName()
    if type(observed) ~= 'string' or observed == '' then return end
    if not state.original then
        if not config.enabled and not config.undercover_enabled then return end
        if clean(observed, 128) ~= observed then
            state.blocked = true
            report('Original name cannot be restored by command; animation stopped.')
            return
        end
        if state.resume_original and (observed == state.resume_confirmed or observed == state.resume_pending) then
            state.original = state.resume_original
            state.confirmed = observed
        else
            state.original = observed
        end
        state.resume_original, state.resume_confirmed, state.resume_pending = nil, nil, nil
    end

    stage('game: GetTime')
    local now = draw.GetTime()
    local epoch = clock_utc(now)
    if now < state.last_time then
        state.next_update = now
        state.deadline = now + config.confirmation_timeout
    end
    state.last_time = now

    if state.pending then
        if observed == state.pending then
            if not state.saw_confirmation then
                state.saw_confirmation = true
                report('First name change confirmed by controller; animation active.')
            end
            state.confirmed = observed
            state.pending = nil
            state.fallback_sent = false
            advance(now)
        elseif now >= state.deadline then
            stage('name: read convar after timeout')
            local cv = game.cvar:Find('name')
            local applied = cv and cv.value == state.pending
            if not applied and not state.fallback_sent then
                state.fallback_sent=true
                state.deadline=now+config.confirmation_timeout
                report('setinfo name did not apply; trying the name command once.')
                send_name(state.pending,true)
                return
            end
            state.blocked = true
            -- Keep pending text so unload can restore a late acknowledgement.
            report(applied and 'name changed locally, but controller did not confirm it. Server may be ignoring changes; animation stopped.'
                or 'Both name commands failed, including unrestricted mode. Game rejected the convar change; animation stopped. Unload other name changers and check the game console.')
        end
        return
    end

    -- A different script/user changed the name. Do not fight it.
    if observed ~= (state.confirmed or state.original) then
        state.blocked = true
        report('Name changed externally; animation stopped to avoid conflict.')
        return
    end
    if now < state.next_update then return end
    -- Always compose from the captured base, never from the animated name.
    local base = base_name(state.original)
    local desired = config.enabled and compose_name(preview_at(epoch), base) or base
    if desired == observed then
        advance(now)
        return
    end
    state.pending = desired
    state.fallback_sent = false
    state.deadline = now + config.confirmation_timeout
    state.next_update = now + 0.5 -- bounded command rate even with fast acknowledgements
    send_name(desired)
end

local function initialize()
stage('config: DbLoad')
if utils and utils.DbLoad then
    local saved=utils.DbLoad('clantag_studio_v2')
    if type(saved)=='table' then
        local c=decode(saved.code)
        if c then
            apply(c,false)
            config.enabled=saved.enabled~=false
            if type(saved.undercover_name)=='string' then
                set_undercover(saved.undercover_name,saved.undercover_enabled==true)
            end
        end
    end
end
frames=compile(config)
build_menu()
stage('backend: validate name convar')
local ok,reason=initialize_native()
report(reason)
runtime.loading=false
if ok then report('Loaded. Menu: '..(ui.menu_path or 'unavailable')..'. Status in console.') end
end
function __shutdown()
    runtime.closed=true
    restore()
    if native.release and not native.release() then
        report('Could not restore USERINFO flag; restart the game before testing again.')
    end
    native.ready = false
end
events.presentQueue:Add(guarded('frame',update))
guarded('initialization',initialize)()
return {encode=encode,decode=decode,compile=compile,apply=apply,preview=preview_at,clock=clock_utc,compose=compose_name,undercover=set_undercover,base=base_name}
