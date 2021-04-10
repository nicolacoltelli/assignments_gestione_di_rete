

--HTTP
-- Rapporto risposte HTTP positive (es codice 200) e negative (es errori 500)
-- Actually the responses of HTTP are different than only positive and negative : 
-- {broken,server error(es 500), client error, redirection , sucess response (es 200), informational}

local f_http_code = Field.new("http.response.code")

local function getstring(finfo)
   local ok, val = pcall(tostring, finfo)
   if not ok then val = "(unknown)" end
   return val
end

local function gr_tap()
   -- Declare the window we will use
   local tw = TextWindow.new("HTTP Rapporto")
   
   -- This will contain a hash of counters of appearances of a certain address
   --local dns_queries = {}
   local http_response = 0
   local http_response_positive = 0
   local http_response_negative = 0
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
      local http_response_c = f_http_code() -- Call the function that extracts the field

      if(http_response ~= nil) then
		 
		 if (http_response_c.value > 199 and http_response_c.value < 300) then
			http_response_positive = http_response_positive + 1
		 else if (http_response_c.value > 499 and http_response_c.value < 600) then
			  http_response_negative = http_response_negative + 1
			  end
		 end    	 
      end
   end

   -- this function will be called once every few seconds to update our window
   function tap.draw(t)
      tw:clear()
	  tw:append(http_response_positive .. "\n")
	  tw:append(http_response_negative .. "\n")
   end

   -- this function will be called whenever a reset is needed
   -- e.g. when reloading the capture file
   function tap.reset()
    	tw:clear()
    	http_response = 0
    	http_response_positive = 0
    	http_response_negative = 0
   end

   -- Ensure that all existing packets are processed.
   retap_packets()
end

-- Menu GR -> Packets
register_menu("Gruppo9/HTTP", gr_tap, MENU_TOOLS_UNSORTED)

