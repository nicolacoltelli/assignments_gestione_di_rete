--Per tutti i protocolli
--- numero di hosts diversi contattattati (client)
--- numero di hosts diversi da cui sono stati contattati (server)
--per tutti i protocolli intendevo “a prescindere dal protocollo” ovvero senza differenziare DNS o TLS ad esempio.
--Per fare qeusto esercizio usate pure una hash o simile, anche se poi tra un pochino vi faccio vedere delle strutture dati ad hoc a lezione
--(es vd https://github.com/avz/hll). 
--Il client si intente colui che inizia la comunicazione 
--(quelloc he manda il SYN in TCP per intenderci,
--mentre su UDP chi della 5-tupla IP src/dst,ports src/dst e protocollo invia il pacchetto per primo). Per semplicita’ potreste considerare
--le coppie IP src-IP dst lasciando il discorso client/server a quando vi spiego meglio come analizzare questi dati. 
-- Non metterei di certo un parametro nel codice.

local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local f_udp_src_port = Field.new("udp.srcport")
local f_udp_dst_port = Field.new("udp.dstport")
local f_tcp_flags  = Field.new("tcp.flags")
local f_tcp_flags_syn  = Field.new("tcp.flags.syn")
local f_tcp_flags_ack  = Field.new("tcp.flags.ack")

local function getstring(finfo)
	 local ok, val = pcall(tostring, finfo)
	 if not ok then val = "(unknown)" end
	 return val
end

local function isMulticast(v_ip_dst)
			if (v_ip_dst ~= nil) then 
				local ip = tostring(v_ip_dst.value)
    			local o1,o2,o3,o4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)" )
    			if (tonumber(o1) >= 224 and tonumber(o1) <= 239) then
    			--print(o1,o2,o3,o4)
    			return true
    			end
			end
			return false
end
local function clientIpFinder(list, new_ip_src, new_ip_dst)

	--dst is multicast
	--src can be either us (if we send it) or someone else on the network
	if (isMulticast(new_ip_dst)) then
		return nil
	end
	-- Base case for fist packet
	if (next(list) == nil) then
		table.insert(list, new_ip_src.value)
		table.insert(list, new_ip_dst.value)
		print(getstring(list[1]) .. " func")
		print(getstring(list[2]) .. " func")
		return nil
	end

	if (   (list[1] == new_ip_src.value and list[2] == new_ip_dst.value)
		or (list[2] == new_ip_src.value and list[1] == new_ip_dst.value) ) then
		--print("same ips")
		return nil
	end

	if (list[1] == new_ip_src.value or list[2] == new_ip_src.value) then
		return new_ip_src.value
	end

	if (list[1] == new_ip_dst.value or list[2] == new_ip_dst.value) then
		return new_ip_dst.value
	end

	return nil

end

local function gr_tap()
	 -- Declare the window we will use
	 local tw = TextWindow.new("Client Server")
	 
	 -- Dictionary key:hostname value:boolean representing its presence ad client
	 local clients_tcp = {}
	 local servers_tcp = {}
	 local hosts_udp = {}
	 local clients_udp = {}
	 local servers_udp = {}

	 --ip_src:src_port -> ip_dst:dst_port

	 local candidate_client_ips_list = {}
	 local client_ip = nil

	 local test = false
	 local test_count = 0

	 -- this is our tap
	 local tap = Listener.new();

	 local function remove()
			-- this way we remove the listener that otherwise will remain running indefinitely
			tap:remove();
	 end

	 -- we tell the window to call the remove() function when closed
	 tw:set_atclose(remove)

	 -- this function will be called once for each packet
	 function tap.packet(pinfo,tvb)
		-- Call all the function that extracts the fields
			local ip_src = f_ip_src()
			local ip_dst = f_ip_dst()
			local src_port = f_udp_src_port()
			local dst_port = f_udp_dst_port()
			local tcp_flags = f_tcp_flags()
			local tcp_flags_syn = f_tcp_flags_syn() 
			local tcp_flags_ack = f_tcp_flags_ack()

			if (ip_src == nil or ip_dst == nil) then 
				return 
			end

			-- @@@debug count
			if (client_ip == nil) then
				client_ip = clientIpFinder(candidate_client_ips_list, ip_src, ip_dst)
			end

			-- @@@debug
			if (not(test) and client_ip ~= nil) then
				print (getstring(client_ip) .. "\n")
				--test = true
			end

			--Check if it's a tcp packet and contains an IP source (maybe we can't get src information a non-IP datagram)
			if(tcp_flags ~= nil) then
				--Check if the SYN flag is 1 (if it isn't it's just a TCP segment of an already enstablished connection)
				if(tcp_flags_syn.value) then
					--If ACK is set to 1 then the src is the Server that sends the second segment of the 3 way handshake 
					if(tcp_flags_ack.value) then
						if(servers_tcp[getstring(ip_src.value)] == nil) then
							servers_tcp[getstring(ip_src.value)] = true
						end
					--Else is the client that starts the communication with just a SYN
					else
						if (clients_tcp[getstring(ip_src.value)] == nil) then
							clients_tcp[getstring(ip_src.value)]= true
						end
					end

				end 
			end
			if(src_port ~= nil and dst_port ~= nil) then
				if(hosts_udp[getstring(ip_src.value)] == nil) then
					hosts_udp[getstring(ip_src.value)] = {}
				end
				if(hosts_udp[getstring(ip_dst.value)] == nil) then
					hosts_udp[getstring(ip_dst.value)] = {}
				end
				
				hosts_udp[getstring(ip_src.value)][getstring(src_port.value)] = true
				hosts_udp[getstring(ip_dst.value)][getstring(dst_port.value)] = true

			end

			if (not(test) and client_ip ~= nil) then
				print (getstring(client_ip) .. "\n")
				--test = true
			end
	 end

	 -- this function will be called once every few seconds to update our window
	 function tap.draw(t)
				tw:clear()
				local tot_clients_tcp = 0
				local tot_servers_tcp = 0
				local tot_hosts_udp = 0
				local tot_clients_udp=0
				local tot_servers_udp=0

				tw:append("TCP \n")
				tw:append("Clients: " .. "\n")
				for host,flag in pairs(clients_tcp) do
						tw:append(getstring(host) .. "\n")
						if(flag) then
							tot_clients_tcp = tot_clients_tcp + 1
						end
				end

				tw:append("Servers: " .. "\n")
				for host,flag in pairs(servers_tcp) do
					tw:append(getstring(host) .. "\n")
					if(flag) then
						tot_servers_tcp = tot_servers_tcp + 1
					end
				end

			  tw:append("Total clients: " .. tot_clients_tcp .. "\n")
			  tw:append("Total servers: " .. tot_servers_tcp .. "\n")

			  tw:append("UDP: \n")

			 	for host in pairs(hosts_udp) do
			 		print(getstring(client_ip))
			 		if (client_ip ~= nil and host == getstring(client_ip)) then
						for port, check in pairs (hosts_udp[host]) do
								tw:append("Client " .. getstring(host) .. ":" .. getstring(port) .. "\n")
								tot_hosts_udp = tot_hosts_udp + 1
								tot_clients_udp = tot_clients_udp + 1
						end
					else
						for port, check in pairs (hosts_udp[host]) do
								tw:append("Server " .. getstring(host) .. ":" .. getstring(port) .. "\n")
								tot_hosts_udp = tot_hosts_udp + 1
								tot_servers_udp = tot_servers_udp + 1
						end
					end
				end

			 tw:append("Total UDP hosts: " .. tot_hosts_udp .. "\n")
			 tw:append("Total Server hosts: " .. tot_servers_udp .. "\n")
			 tw:append("Total Client hosts: " .. tot_clients_udp .. "\n")
	 end

	 -- this function will be called whenever a reset is needed
	 -- e.g. when reloading the capture file
	 function tap.reset()
		--tw:clear()
		clients_tcp = {}
		servers_tcp = {}
		hosts_udp = {}
		clients_udp = {}
		servers_udp = {}
		candidate_client_ips_list = {}
 		client_ip = nil

 		---@@@debug
 		test_count = 0
	 end

	 -- Ensure that all existing packets are processed.
	 retap_packets()
end

-- Menu GR -> Packets
register_menu("Gruppo9/Client Server", gr_tap, MENU_TOOLS_UNSORTED)

--if gui_enabled() then
--   local splash = TextWindow.new("Hello!");
--   splash:set("Wireshark has been enhanced with a usefull feature.\n")
--   splash:append("Go to 'Tools->Gruppo9' and check it out!")
--end