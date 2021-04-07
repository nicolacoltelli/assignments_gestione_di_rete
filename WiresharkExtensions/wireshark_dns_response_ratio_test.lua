-- TODO
-- 1) try running script during capture
-- 2) ask for retap_packets()
-- 3) empty query (defaulted to root) one time gave us 6 in the
--	questions field in wireshark (dns.count.queries)
-- 4) Field Extractors when working with bits (we are able to treat
--	a bit as boolean, but what about 3 bits like dns error codes)
-- 5) Ask if a DNS packet can have a name but not flags and viceversa
--	(dns.qry.name != nil <=> dns.flags.response != nil)
-- 6) Even if we included 2 hostnames in dig command 2 separate queries are sent.
--	We think it's caused by the dns client implementation because we read on
--	the Internet that dns request with multiple queries are not really used. 

--Per ciascun host riportare 

--DNS
-- il rapporto queries fatte/risposte ricevute (in teoria dovrebbe essere intorno a 1)
-- il rapporto risposte positive/risposte con errori
-- numero di queries diverse (nomi al dominio) inviate

--HTTP
-- Rapporto risposte HTTP positive (es codice 200) e negative (es errori 50)0)

--Per tutti i protocolli
-- numero di hosts diversi contattattati (client)
-- numero di hosts diversi da cui sono stati contattati (server)

local f_dns_query_name     = Field.new("dns.qry.name")
local f_dns_flags_response = Field.new("dns.flags.response")
--Field cotaining error code
local f_dns_flags_rcode = Field.new("dns.flags.rcode")

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

local function gr_tap()

	-- Declare the window we will use
	local tw = TextWindow.new("DNS Queries/Answers ratio")

	-- This will contain a hash of counters of appearances of a certain address
	--Queries dictionary
	local dns_queries = {}
	--Answers dictionary
	local dns_answers = {}
	--Dictionaries key:hostname value:counter of error/no error for the answers
	local dns_answers_error = {}
	local dns_answers_no_error = {}

	local total_dns_packets = 0
	--The cap is arbitrary, maybe should sort the dictionaries by occurrences then trim the lowest
	local max_dns_packets = 500

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
	
		local dns_query_name = f_dns_query_name() -- Call the function that extracts the field
		local dns_flags_response = f_dns_flags_response()
		local dns_flags_rcode = f_dns_flags_rcode()

		if(dns_query_name ~= nil and total_dns_packets<max_dns_packets) then
			
			local old_value
			dns_query_name = getstring(dns_query_name) -- get the string returned by the query name

			if( dns_flags_response ~= nil) then
				if(dns_flags_response.value) then 

						old_value = dns_answers[dns_query_name] or 0 
						dns_answers[dns_query_name] = old_value + 1
						
						if (dns_flags_rcode.value>0) then
							old_value = dns_answers_error[dns_query_name] or 0
							dns_answers_error[dns_query_name] = old_value + 1
						else
							old_value = dns_answers_no_error[dns_query_name] or 0
							dns_answers_no_error[dns_query_name] = old_value + 1
						end
					else
						old_value = dns_queries[dns_query_name] or 0 -- read the old value      
						dns_queries[dns_query_name] = old_value + 1  -- increase the number of queries observed for this DNS name
				end
				total_dns_packets = total_dns_packets + 1 
			end
		
		end
	
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		
		tw:clear()
		local total_dns_names = 0
		for dns_query,num in pairs(dns_queries) do
			--incremento il contatore dei nomi richiesti nelle queries dns
			total_dns_names = total_dns_names + 1
			--ottengo il numero di risposte per l'host attuale
			local answers = dns_answers[dns_query] or 0
			if(answers>0) then
				--ottengo il numero di errori per l'host attuale
				local errors=(dns_answers_error[dns_query] or 0)
				local no_errors=(dns_answers_no_error[dns_query] or 0)
				if (errors>0 and no_errors>0) then
					tw:append(dns_query .. ":\t" .. (num/answers) .. "\t" .. (dns_answers_no_error[dns_query]/errors) .. "\n");
				end
				if (errors==0 and no_errors>0) then
					tw:append(dns_query .. ":\t" .. (num/answers) .. "\t" .. "No errors" .. "\n");
				end
				if (errors>0 and no_errors==0) then
					tw:append(dns_query .. ":\t" .. (num/answers) .. "\t" .. errors .. " errors" .. "\n");
				end
			else
				tw:append(dns_query .. "\t" .. "No answer received" .. "\n");
			end
		end

		tw:append("\n");
		tw:append("Total hostnames queried: " .. total_dns_names);
	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		dns_queries = {}
		dns_answers = {}
		total_dns_packets = 0
	end

	-- Ensure that all existing packets are processed.
	retap_packets()

end

-- Menu GR -> Packets
register_menu("GR/Gruppo9_test", gr_tap, MENU_TOOLS_UNSORTED)

