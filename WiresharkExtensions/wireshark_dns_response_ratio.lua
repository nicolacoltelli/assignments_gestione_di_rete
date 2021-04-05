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

local f_dns_query_name     = Field.new("dns.qry.name")
local f_dns_flags_response = Field.new("dns.flags.response")

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

local function gr_tap()

	-- Declare the window we will use
	local tw = TextWindow.new("DNS Queries/Answers ratio")

	-- This will contain a hash of counters of appearances of a certain address
	local dns_queries = {}
	local queries_done = 0
	local answer_received = 0

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

		if(dns_query_name ~= nil) then
		
			local old_value
		
			dns_query_name = getstring(dns_query_name) -- get the string returned by the query name

			old_value = dns_queries[dns_query_name] or 0 -- read the old value      
			dns_queries[dns_query_name] = old_value + 1  -- increase the number of queries observed for this DNS name

		-- We count as queries done by us the packets with the response
			-- bit inside the flags set to 0.
			if( dns_flags_response ~= nil) then
			
				if(dns_flags_response.value) then 
						answer_received = answer_received + 1
					else
						queries_done = queries_done + 1 
				end
			end
		
		end
	
	end

	-- this function will be called once every few seconds to update our window
	function tap.draw(t)
		
		tw:clear()
		
		for dns_query,num in pairs(dns_queries) do
				tw:append(dns_query .. "\t" .. num .. "\n");
		end

		tw:append("\n");
		tw:append("Total queries: " .. queries_done .. "\n");
		tw:append("Total answers: " .. answer_received .. "\n");
		
		if (queries_done > 0 and answer_received > 0) then
    		tw:append("Ratio between queries sent and answers received is: " .. queries_done/answer_received .. "\n");
		end

	end

	-- this function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		dns_queries = {}
		queries_done = 0
		answer_received = 0
	end

	-- Ensure that all existing packets are processed.
	retap_packets()

end

-- Menu GR -> Packets
register_menu("GR/Gruppo9", gr_tap, MENU_TOOLS_UNSORTED)

