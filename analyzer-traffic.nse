local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local io = require "io"

description = [[
Analisador simples de tráfego HTTP: envia requisição para a porta 80,
registra Host, User-Agent usado, IP e conta quantas requisições já foram feitas para aquele IP.
]]

author = "Finger"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(80, "http")

local log_file = "/home/finger/Documentos/http_requests_log.txt"
local ip_counter = {}  -- Tabela para contar as requisições por IP

local function load_counter()
  local file = io.open(log_file, "r")
  if file then
    for line in file:lines() do
      local ip, count = line:match("IP: (%S+) | Requisicoes: (%d+)")
      if ip and count then
        ip_counter[ip] = tonumber(count)
      end
    end
    file:close()
  end
end

local function save_log(entry, ip)
  local file = io.open(log_file, "a")
  if file then
    file:write(string.format("IP: %s | Requisicoes: %d\n", ip, ip_counter[ip]))
    file:close()
  end
end

local function update_counter(ip)
  if ip_counter[ip] then
    ip_counter[ip] = ip_counter[ip] + 1
  else
    ip_counter[ip] = 1
  end
end

action = function(host, port)
  local ip = host.ip or "unknown"
  local user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36"

  load_counter()

  local response = http.get(host, port, "/", {header={["User-Agent"]=user_agent}})
  if not response then
    return "Sem resposta do servidor."
  end

  update_counter(ip)

  local host_header = host.targetname or host.name or host.ip

  local log_entry = string.format(
    "Host: %s | User-Agent: %s | Requisicoes: %d",
    host_header, user_agent, ip_counter[ip]
  )

  save_log(log_entry, ip)

  return log_entry
end
